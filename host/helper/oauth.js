// OAuth sources (site type `oauth`): the owner authorizes once (device flow or
// redirect flow with PKCE), the refresh token is sealed in store/oauth/<id>.enc
// and never leaves the helper; agents only ever get short-lived access tokens
// minted by a refresh grant (`token.mint`) and revoked at lease end.
//
// Ops (all but the last two are admin ops: they are outside VAULTD_OPS in helper.js):
//   oauth.start  { siteId, flow, port? }  device:   { handle, userCode, verificationUri, interval, expiresAt }
//                                         redirect: { handle, authUrl, listen: { host, port }, redirectUri, expiresAt }
//   oauth.finish { handle }               waits for the owner, stores the grant: { authorized: true, scopes }
//   token.mint   { leaseId, siteId, minutes, scopes } -> { accessToken, tokenType, expiresAt, scopes }
//   token.revoke { leaseId }              -> { revoked: true | false | 'unsupported' }
//
// Nothing secret (codes, tokens, the PKCE verifier) is logged or put into an error.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { HelperError, bad } from './errors.js';
import { ID_RE, LEASE_ID_RE, HANDLE_RE, needInt, needString } from './params.js';
import { KeyedMutex } from './queue.js';

const HTTP_TIMEOUT_MS = 20_000;
const MAX_BODY_BYTES = 64 * 1024;
const DEVICE_MAX_MS = 30 * 60_000;
const DEVICE_DEFAULT_MS = 15 * 60_000;
const DEFAULT_INTERVAL_S = 5;
const SLOW_DOWN_S = 5;
const POLL_FAILURES = 3; // consecutive network errors while polling before giving up
export const REDIRECT_TTL_MS = 10 * 60_000;
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export function abortableSleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

const b64url = (buf) => buf.toString('base64url');

function safeEqual(a, b) {
  const x = createHash('sha256').update(String(a)).digest();
  const y = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(x, y);
}

/** Provider error names are shown to the owner; keep only a harmless token. */
function errorName(body) {
  const e = typeof body?.error === 'string' ? body.error : '';
  return /^[A-Za-z0-9_.-]{1,60}$/.test(e) ? e : '';
}

function scopeList(value, fallback) {
  return typeof value === 'string' && value.trim() ? value.trim().split(/\s+/) : fallback;
}

/**
 * @param store   SealedStore (kind `oauth`)
 * @param creds   Credentials (optional `oauth-client-secret`)
 * @param options.fetch  the HTTP client (tests may replace it)
 * @param options.sleep  async (ms, signal) used between device polls
 * @param options.now    clock
 * @param options.redirectTtlMs  how long a redirect-flow listener waits for the callback (10 minutes)
 */
export function createOAuth({ store, creds, log, fetch: fetchImpl = globalThis.fetch, sleep = abortableSleep, now = Date.now, redirectTtlMs = REDIRECT_TTL_MS }) {
  /** @type {Map<string, object>} owner authorizations in progress */
  const pending = new Map();
  const grantLocks = new KeyedMutex();

  // ---- HTTP -----------------------------------------------------------------------
  async function clientForm(site, extra) {
    const form = { client_id: site.oauth.clientId, ...extra };
    const secret = await creds.optional(site.id, 'oauth-client-secret');
    if (secret) form.client_secret = secret;
    return form;
  }

  /** POST a form; resolves { status, body } (body is {} when the answer is not a JSON object). */
  async function postForm(url, form, signal) {
    let res;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams(form),
        redirect: 'error',
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(HTTP_TIMEOUT_MS)]) : AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
    } catch (err) {
      if (signal?.aborted) throw signal.reason instanceof HelperError ? signal.reason : new HelperError('timeout', 'operation timed out');
      throw new HelperError('site_unreachable', `the OAuth endpoint did not answer (${err?.name ?? 'error'})`);
    }
    const reader = res.body?.getReader();
    const chunks = [];
    let size = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MAX_BODY_BYTES) {
          await reader.cancel();
          throw new HelperError('oauth_error', 'the OAuth endpoint answered with more than 64 KiB');
        }
        chunks.push(value);
      }
    }
    let body = {};
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) body = parsed;
    } catch {
      // not JSON: the status decides
    }
    return { status: res.status, body };
  }

  /** The error a failed token / device-code answer becomes. */
  function failure({ status, body }, { refresh = false } = {}) {
    const name = errorName(body);
    if (status >= 500) return new HelperError('site_unreachable', `the OAuth endpoint answered ${status}`);
    if (name === 'access_denied') return new HelperError('oauth_denied', 'the authorization was denied');
    if (name === 'expired_token') return new HelperError('timeout', 'the authorization code expired');
    if (refresh && (name === 'invalid_grant' || name === 'unauthorized_client' || name === 'invalid_client')) {
      return new HelperError('needs_authorize', 'the provider rejected the stored authorization; run vault-site authorize again');
    }
    return new HelperError('oauth_error', name ? `the provider answered ${name}` : `the provider answered ${status}`);
  }

  // ---- grants -----------------------------------------------------------------------
  /** Seal the refresh token of a first authorization. */
  async function saveGrant(site, body) {
    if (typeof body.refresh_token !== 'string' || !body.refresh_token) {
      throw new HelperError('oauth_error', 'the provider returned no refresh token (is offline access among the scopes?)');
    }
    const scopes = scopeList(body.scope, site.oauth.scopes);
    await store.put('oauth', site.id, { v: 1, refreshToken: body.refresh_token, scopes, authorizedAt: new Date(now()).toISOString() });
    log('info', 'oauth authorized', { siteId: site.id });
    return { authorized: true, scopes };
  }

  /** Refresh grant. A rotated refresh token is sealed before the access token is handed on. */
  async function refresh(site, scopes, signal) {
    const release = await grantLocks.acquire(site.id, signal);
    try {
      const record = await store.get('oauth', site.id);
      if (!record?.refreshToken) throw new HelperError('needs_authorize', 'this site is not authorized yet; run vault-site authorize');
      const form = await clientForm(site, { grant_type: 'refresh_token', refresh_token: record.refreshToken, scope: scopes.join(' ') });
      const res = await postForm(site.oauth.tokenUrl, form, signal);
      if (res.status !== 200 || typeof res.body.access_token !== 'string' || !res.body.access_token) {
        throw failure(res, { refresh: true });
      }
      const next = res.body.refresh_token;
      if (typeof next === 'string' && next && next !== record.refreshToken) {
        await store.put('oauth', site.id, { ...record, refreshToken: next, rotatedAt: new Date(now()).toISOString() });
        log('info', 'oauth refresh token rotated', { siteId: site.id });
      }
      return res.body;
    } finally {
      release();
    }
  }

  // ---- pending authorizations ---------------------------------------------------------
  function drop(handle) {
    const p = pending.get(handle);
    if (!p) return null;
    pending.delete(handle);
    clearTimeout(p.timer);
    p.close?.();
    return p;
  }

  function track(handle, p, ttlMs) {
    // One authorization per site: starting again replaces the earlier one.
    for (const [h, other] of pending) if (other.site.id === p.site.id) drop(h);
    p.timer = setTimeout(() => drop(handle), ttlMs);
    p.timer.unref?.();
    pending.set(handle, p);
  }

  function claim(handle) {
    const p = pending.get(handle);
    if (!p) throw new HelperError('not_found', 'no such authorization (expired or finished)');
    if (p.busy) throw new HelperError('conflict', 'this authorization is already being finished');
    p.busy = true;
    return p;
  }

  /** What an aborted wait becomes: the shutdown error, or a timeout. */
  function abortedAs(err, signal) {
    if (err instanceof HelperError || !signal.aborted) return err;
    return signal.reason instanceof HelperError ? signal.reason : new HelperError('timeout', 'the authorization was not completed in time');
  }

  // ---- device flow ----------------------------------------------------------------------
  async function startDevice(site, signal) {
    const o = site.oauth;
    const form = await clientForm(site, { scope: o.scopes.join(' ') });
    const res = await postForm(o.deviceUrl, form, signal);
    const b = res.body;
    const uri = b.verification_uri ?? b.verification_url;
    if (res.status !== 200 || typeof b.device_code !== 'string' || typeof b.user_code !== 'string' || typeof uri !== 'string') {
      throw failure(res);
    }
    const ttl = Number.isFinite(b.expires_in) && b.expires_in > 0 ? Math.min(b.expires_in * 1000, DEVICE_MAX_MS) : DEVICE_DEFAULT_MS;
    const interval = Number.isInteger(b.interval) && b.interval >= 1 ? Math.min(b.interval, 60) : DEFAULT_INTERVAL_S;
    const handle = `oau_${randomBytes(8).toString('hex')}`;
    const expiresAtMs = now() + ttl;
    track(handle, { kind: 'device', site, deviceCode: b.device_code, interval, expiresAtMs }, ttl);
    return {
      handle,
      userCode: b.user_code,
      verificationUri: uri,
      ...(typeof b.verification_uri_complete === 'string' ? { verificationUriComplete: b.verification_uri_complete } : {}),
      interval,
      expiresAt: new Date(expiresAtMs).toISOString(),
    };
  }

  async function finishDevice(p, signal) {
    const { site } = p;
    let interval = p.interval;
    let failures = 0;
    for (;;) {
      await sleep(interval * 1000, signal);
      if (now() >= p.expiresAtMs) throw new HelperError('timeout', 'the device code expired before it was approved');
      let res;
      try {
        res = await postForm(site.oauth.tokenUrl, await clientForm(site, { grant_type: DEVICE_GRANT, device_code: p.deviceCode }), signal);
      } catch (err) {
        if (err.code === 'site_unreachable' && (failures += 1) < POLL_FAILURES) continue;
        throw err;
      }
      failures = 0;
      if (res.status === 200 && typeof res.body.access_token === 'string') return saveGrant(site, res.body);
      const name = errorName(res.body);
      if (name === 'authorization_pending') continue;
      if (name === 'slow_down') {
        interval += SLOW_DOWN_S;
        continue;
      }
      throw failure(res);
    }
  }

  // ---- redirect flow (127.0.0.1 listener, PKCE S256, one callback) ----------------------
  async function startRedirect(site, port) {
    const o = site.oauth;
    const state = b64url(randomBytes(32));
    const verifier = b64url(randomBytes(48));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const p = { kind: 'redirect', site, verifier, consumed: false };
    p.result = new Promise((resolve, reject) => {
      p.resolve = resolve;
      p.reject = reject;
    });
    p.result.catch(() => {}); // surfaced by finish; nobody may be waiting yet

    const server = http.createServer((req, res) => {
      const reply = (code, text) => {
        res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', connection: 'close' });
        res.end(text);
      };
      let url;
      try {
        url = new URL(req.url, 'http://127.0.0.1');
      } catch {
        return reply(400, 'bad request');
      }
      // The Host header must name the loopback listener (a DNS-rebinding page would not).
      const hostOk = [`127.0.0.1:${p.port}`, `localhost:${p.port}`].includes(req.headers.host);
      if (req.method !== 'GET' || !hostOk || url.pathname !== '/callback') return reply(404, 'not found');
      if (!safeEqual(url.searchParams.get('state') ?? '', state)) return reply(400, 'state mismatch');
      if (p.consumed) return reply(409, 'this authorization was already used');
      p.consumed = true;
      const code = url.searchParams.get('code');
      if (url.searchParams.get('error') || !code) p.reject(new HelperError('oauth_denied', 'the authorization was denied'));
      else p.resolve(code);
      reply(200, 'Authorization received. You can close this window and go back to the terminal.');
      server.close();
      server.closeIdleConnections();
    });
    await new Promise((resolve, reject) => {
      server.once('error', (err) => reject(err.code === 'EADDRINUSE'
        ? new HelperError('conflict', `port ${port} is already in use`)
        : new HelperError('internal', 'could not start the callback listener')));
      server.listen(port ?? 0, '127.0.0.1', resolve);
    });
    p.port = server.address().port;
    p.redirectUri = `http://127.0.0.1:${p.port}/callback`;
    p.close = () => {
      p.reject(new HelperError('timeout', 'the authorization was not completed in time'));
      server.close();
      server.closeAllConnections();
    };
    const handle = `oau_${randomBytes(8).toString('hex')}`;
    track(handle, p, redirectTtlMs);
    const url = new URL(o.authUrl);
    for (const [k, v] of Object.entries({
      response_type: 'code',
      client_id: o.clientId,
      redirect_uri: p.redirectUri,
      scope: o.scopes.join(' '),
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })) url.searchParams.set(k, v);
    return {
      handle,
      authUrl: url.toString(),
      listen: { host: '127.0.0.1', port: p.port },
      redirectUri: p.redirectUri,
      expiresAt: new Date(now() + redirectTtlMs).toISOString(),
    };
  }

  async function finishRedirect(p, signal) {
    const code = await Promise.race([
      p.result,
      new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true })),
    ]);
    const form = await clientForm(p.site, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: p.redirectUri,
      code_verifier: p.verifier,
    });
    const res = await postForm(p.site.oauth.tokenUrl, form, signal);
    if (res.status !== 200 || typeof res.body.access_token !== 'string') throw failure(res);
    return saveGrant(p.site, res.body);
  }

  // ---- ops ------------------------------------------------------------------------------
  function oauthSite(deps, params) {
    const siteId = needString(params, 'siteId', ID_RE);
    const site = deps.sites().get(siteId);
    if (!site) throw new HelperError('not_found', `unknown site ${siteId}`);
    if (site.type !== 'oauth') throw bad(`site ${siteId} is not an oauth site`);
    return site;
  }

  const ops = {
    async 'oauth.start'(params, deps) {
      const site = oauthSite(deps, params);
      if (params.flow !== site.oauth.flow) throw bad(`flow must be ${site.oauth.flow} for this site`);
      const signal = deps.opSignal(deps.config.timeouts.openMs);
      if (site.oauth.flow === 'device') {
        if (params.port !== undefined) throw bad('port is only for the redirect flow');
        return startDevice(site, signal);
      }
      const port = params.port === undefined ? undefined : needInt(params, 'port', 1024, 65535);
      return startRedirect(site, port);
    },

    async 'oauth.finish'(params, deps) {
      const handle = needString(params, 'handle', HANDLE_RE);
      const p = claim(handle);
      const limit = p.kind === 'device' ? Math.max(1000, p.expiresAtMs - now() + 10_000) : redirectTtlMs + 10_000;
      const signal = deps.opSignal(limit);
      try {
        return await (p.kind === 'device' ? finishDevice(p, signal) : finishRedirect(p, signal));
      } catch (err) {
        throw abortedAs(err, signal);
      } finally {
        drop(handle);
      }
    },

    async 'token.mint'(params, deps) {
      const leaseId = needString(params, 'leaseId', LEASE_ID_RE);
      const site = oauthSite(deps, params);
      const minutes = needInt(params, 'minutes', 1, 480);
      const wanted = params.scopes === undefined ? site.oauth.scopes : params.scopes;
      if (!Array.isArray(wanted) || wanted.length === 0 || wanted.length > 50 || !wanted.every((s) => typeof s === 'string')) {
        throw bad('scopes must be a non-empty array of scope names');
      }
      if (!wanted.every((s) => site.oauth.scopes.includes(s))) throw bad('scopes must be a subset of the site scopes');
      const unreserve = deps.leases.reserve(leaseId);
      try {
        const startedMs = now();
        const body = await refresh(site, wanted, deps.opSignal(deps.config.timeouts.openMs));
        // The lease is never longer than the request, the site, or the source allows.
        const endsAtMs = startedMs + Math.min(minutes, site.maxMinutes, site.oauth.accessTtlMaxMinutes) * 60_000;
        const providerMs = Number.isFinite(body.expires_in) && body.expires_in > 0 ? now() + body.expires_in * 1000 : Infinity;
        const expiresAtMs = Math.min(providerMs, endsAtMs);
        const tokenType = typeof body.token_type === 'string' && body.token_type ? body.token_type : 'Bearer';
        const token = { accessToken: body.access_token, tokenType };
        try {
          await deps.leases.register({ leaseId, site, endsAtMs, token });
        } catch (err) {
          // Not sealed means not revocable later: revoke now, hand nothing out.
          await revokeToken({ site, token }, deps.opSignal(15_000)).catch(() => {});
          throw err;
        }
        log('info', 'token minted', { siteId: site.id, leaseId });
        return {
          accessToken: body.access_token,
          tokenType,
          expiresAt: new Date(expiresAtMs).toISOString(),
          scopes: scopeList(body.scope, wanted),
        };
      } finally {
        unreserve();
      }
    },

    async 'token.revoke'(params, deps) {
      const leaseId = needString(params, 'leaseId', LEASE_ID_RE);
      const { loggedOut } = await deps.leases.close(leaseId, 'revoked');
      return { revoked: loggedOut };
    },
  };

  /**
   * End a token lease at the provider (RFC 7009 on `revokeUrl`). true: revoked,
   * false: the provider refused, 'unsupported': the site has no revokeUrl.
   * Throws on network trouble (the caller retries).
   */
  async function revokeToken({ site, token }, signal) {
    if (!site.oauth.revokeUrl) return 'unsupported';
    const form = await clientForm(site, { token: token.accessToken, token_type_hint: 'access_token' });
    const res = await postForm(site.oauth.revokeUrl, form, signal);
    if (res.status >= 500) throw new HelperError('site_unreachable', `the revocation endpoint answered ${res.status}`);
    return res.status >= 200 && res.status < 300;
  }

  return {
    ops,
    revokeToken: (sealed, signal) => revokeToken(sealed, signal),
    pendingCount: () => pending.size,
    shutdown() {
      for (const handle of [...pending.keys()]) drop(handle);
    },
  };
}
