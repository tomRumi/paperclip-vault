// Wiring and the operation table. Every op is `async (params, deps) => data`
// in `ops`; the oauth and interactive modules contribute their ops and their
// login strategy, and the `extensions` argument can add or replace more:
//
//   createHelper({ config, token, adminToken, storeKey }, {
//     ops:        { 'token.mint': async (params, deps) => ... },
//     strategies: { interactive: { login(site, { signal, attended }) { ... } } },
//   })
//
// Two bearer tokens: `token` (vaultd) for ping, session.open/close and
// token.mint/revoke (VAULTD_OPS); `adminToken` (root CLI) for everything else.
//
// A strategy's `login(site, { signal, attended, leaseId, endsAtMs })` resolves
// { kind: 'done', session: { liveState, deliverState, landingUrl, trustUsed } }
// (see password.js); the lease machinery (clamping, sealing, timer, logout) is
// shared. A strategy may also offer `test(site, opts)` to replace the generic
// site.test, and `submitChallenge(handle, code, opts)` for attended challenges.
import { randomBytes } from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { BrowserPool } from './browser.js';
import { Credentials } from './creds.js';
import { HelperError, bad } from './errors.js';
import { clampState, LeaseManager } from './leases.js';
import { HANDLE_RE, ID_RE, LEASE_ID_RE, needInt, needIsoFuture, needString, optBool, plainObject } from './params.js';
import { createPasswordStrategy } from './password.js';
import { KeyedMutex } from './queue.js';
import { Sealer, SealedStore } from './seal.js';
import { cookieAllowed, loadSites, needsOwnerAck, urlAllowed } from './sites.js';
import { createInteractive } from './interactive.js';
import { createOAuth } from './oauth.js';
import { createSocketServer } from './sock.js';

const VERSION = createRequire(import.meta.url)('./package.json').version;
const MAX_SESSION_BYTES = 2 * 1024 * 1024;
const TEST_LEASE_MS = 2 * 60_000;
/**
 * The operations vaultd's token may call (allow-list). Every other operation,
 * unknown names included, needs the admin token (/etc/vault/helper-admin.token).
 */
export const VAULTD_OPS = Object.freeze(new Set(['ping', 'session.open', 'session.close', 'token.mint', 'token.revoke']));

export function createLogger(write = (line) => process.stderr.write(line)) {
  return (level, msg, fields = {}) => write(`${JSON.stringify({ t: new Date().toISOString(), level, msg, ...fields })}\n`);
}

function siteOf(deps, params) {
  const siteId = needString(params, 'siteId', ID_RE);
  const site = deps.sites().get(siteId);
  if (!site) throw new HelperError('not_found', `unknown site ${siteId}`);
  return site;
}

function strategyOf(deps, site) {
  const strategy = deps.strategies[site.type];
  if (!strategy) throw new HelperError('unsupported', `site type ${site.type} is not supported by this helper build`);
  return strategy;
}

/** Checks shared by session.open and site.test before any browser starts. */
function prepare(deps, site) {
  if (site.type === 'oauth') throw bad(`site ${site.id} is an oauth site: it is used through token.mint`);
  if (needsOwnerAck(site)) {
    throw new HelperError('needs_owner_ack', `site ${site.id} has no logout recipe and the owner has not accepted that (acceptNoLogout)`);
  }
  const strategy = strategyOf(deps, site);
  if (strategy.busy?.(site)) throw new HelperError('conflict', `an interactive login for ${site.id} is running`);
  return strategy;
}

/** Credential parts a recipe cannot do without: those of non-optional fill steps. */
function requiredParts(site) {
  return new Set((site.recipe?.steps ?? []).filter((s) => s.fill !== undefined && s.optional !== true).map((s) => s.from));
}

/** What the site needs next, from the credential files and the sealed store (no network, no browser). */
async function siteState(deps, site) {
  if (site.type === 'oauth') return (await deps.store.has('oauth', site.id)) ? 'ready' : 'needs_authorize';
  if (site.type === 'interactive') {
    if (!(await deps.store.has('session', site.id))) return 'needs_interactive';
    return needsOwnerAck(site) ? 'needs_owner_ack' : 'ready';
  }
  for (const part of requiredParts(site)) {
    if (!(await deps.creds.has(site.id, part))) return 'missing_credential';
  }
  return 'ready';
}

async function login(deps, site, strategy, opts) {
  const release = await deps.siteLocks.acquire(site.id, opts.signal);
  try {
    return await strategy.login(site, opts);
  } finally {
    release();
  }
}

/** Seal a finished login as a lease; returns what the caller may keep. */
async function startLease(deps, { leaseId, site, endsAtMs, session }) {
  try {
    await deps.leases.register({
      leaseId,
      site,
      endsAtMs,
      liveState: session.liveState,
      landingUrl: session.landingUrl,
    });
  } catch (err) {
    // The session exists at the site but could not be sealed, so nothing
    // would end it later: log out now, then report the failure.
    await deps.leases.abandon({ site, state: session.liveState, landingUrl: session.landingUrl });
    throw err;
  }
  return clampState(session.deliverState, endsAtMs);
}

const ops = {
  async ping(_params, deps) {
    return {
      version: VERSION,
      browsers: await deps.pool.works(),
      sandbox: deps.pool.sandbox,
      leases: deps.leases.list(),
      sites: await Promise.all([...deps.sites().values()].map(async (site) => ({ siteId: site.id, state: await siteState(deps, site) }))),
    };
  },

  async 'session.open'(params, deps) {
    const leaseId = needString(params, 'leaseId', LEASE_ID_RE);
    const site = siteOf(deps, params);
    const minutes = needInt(params, 'minutes', 1, 480);
    const now = deps.now();
    const endsAtParam = needIsoFuture(params, 'endsAt', now);
    const strategy = prepare(deps, site);
    const unreserve = deps.leases.reserve(leaseId);
    // Never later than the lease asks for, never longer than the site allows.
    const endsAtMs = Math.min(endsAtParam, now + Math.min(minutes, site.maxMinutes) * 60_000);
    const signal = deps.opSignal(deps.config.timeouts.openMs);

    let storageState;
    let result;
    try {
      result = await login(deps, site, strategy, { signal, attended: false, leaseId, endsAtMs });
      storageState = await startLease(deps, { leaseId, site, endsAtMs, session: result.session });
    } finally {
      unreserve();
    }
    const body = { storageState, expiresAt: new Date(endsAtMs).toISOString(), trustUsed: result.session.trustUsed };
    if (deps.now() >= endsAtMs) {
      await deps.leases.close(leaseId, 'ended_during_login');
      throw new HelperError('timeout', 'the lease ended while the login was running');
    }
    if (Buffer.byteLength(JSON.stringify(body.storageState)) > MAX_SESSION_BYTES) {
      await deps.leases.close(leaseId, 'session_too_large');
      throw new HelperError('recipe_error', 'the session state exceeds 2 MiB');
    }
    return body;
  },

  async 'session.close'(params, deps) {
    const leaseId = needString(params, 'leaseId', LEASE_ID_RE);
    const { loggedOut } = await deps.leases.close(leaseId, 'closed');
    return { loggedOut };
  },

  async 'site.test'(params, deps) {
    const site = siteOf(deps, params);
    const attended = optBool(params, 'attended');
    const strategy = prepare(deps, site);
    if (strategy.test) return strategy.test(site, { attended, signal: deps.opSignal(deps.config.timeouts.openMs) });
    const signal = deps.opSignal(deps.config.timeouts.openMs);
    const result = await login(deps, site, strategy, { signal, attended, leaseId: null });
    if (result.kind === 'challenge') {
      return { state: 'challenge', handle: result.handle, expiresAt: result.expiresAt };
    }
    return finishTest(deps, site, result.session);
  },

  async 'challenge.submit'(params, deps) {
    const handle = needString(params, 'handle', HANDLE_RE);
    const code = needString(params, 'code');
    if (code.length > 64) throw bad('code too long');
    const owner = Object.values(deps.strategies).find((s) => s.submitChallenge);
    if (!owner) throw new HelperError('not_found', 'no such challenge');
    const { site, session } = await owner.submitChallenge(handle, code, { signal: deps.opSignal(deps.config.timeouts.openMs) });
    return finishTest(deps, site, session);
  },

  async 'session.import'(params, deps) {
    const site = siteOf(deps, params);
    if (site.type !== 'interactive') throw bad('session.import is only for interactive sites');
    const state = plainObject(params.storageState, 'storageState');
    validateImportedState(state, site);
    await deps.store.put('session', site.id, { cookies: state.cookies, origins: state.origins ?? [] });
    // An older interactive profile would shadow the imported session at the next session.open.
    await fsp.rm(path.join(deps.config.stateDir, 'profiles', site.id), { recursive: true, force: true });
    return { imported: true, cookies: state.cookies.length };
  },

  async 'site.forget'(params, deps) {
    const siteId = needString(params, 'siteId', ID_RE);
    await deps.leases.closeSite(siteId, 'site_forgotten');
    for (const kind of ['trust', 'oauth', 'session']) await deps.store.shred(kind, siteId);
    await fsp.rm(path.join(deps.config.stateDir, 'profiles', siteId), { recursive: true, force: true });
    return { forgotten: true };
  },

  async 'site.reload'(_params, deps) {
    const { sites, errors } = loadSites(deps.config.sitesDir);
    deps.setSites(sites);
    for (const e of errors) deps.log('warn', 'invalid site file', { file: e.file });
    return { sites: sites.size, errors };
  },
};

/** A test login is a real login that is logged out at once. */
async function finishTest(deps, site, session) {
  const leaseId = `tst_${randomBytes(8).toString('hex')}`;
  const endsAtMs = deps.now() + TEST_LEASE_MS;
  await startLease(deps, { leaseId, site, endsAtMs, session });
  const { loggedOut } = await deps.leases.close(leaseId, 'site_test');
  return { state: 'ok', trustUsed: session.trustUsed, loggedOut };
}

/** Cookie shape and host check for an imported storageState. */
function validateImportedState(state, site) {
  if (!Array.isArray(state.cookies) || state.cookies.length === 0 || state.cookies.length > 500) {
    throw bad('storageState.cookies must be an array of 1..500 cookies');
  }
  if (state.origins !== undefined && !Array.isArray(state.origins)) throw bad('storageState.origins must be an array');
  for (const o of state.origins ?? []) {
    if (o === null || typeof o !== 'object' || typeof o.origin !== 'string' || !urlAllowed(o.origin, site.allowedHosts)) {
      throw bad('every origin must be an allowed host:port origin');
    }
  }
  for (const c of state.cookies) {
    if (c === null || typeof c !== 'object' || typeof c.name !== 'string' || typeof c.value !== 'string' || typeof c.domain !== 'string') {
      throw bad('every cookie needs name, value and domain');
    }
    const covered = cookieAllowed(c, site);
    if (!covered) throw bad(`cookie ${c.name} belongs to a host outside allowedHosts`);
  }
}

export function createHelper({ config, token, adminToken, storeKey }, extensions = {}) {
  if (typeof adminToken !== 'string' || adminToken.length === 0 || adminToken === token) {
    throw new TypeError('createHelper needs an admin token that differs from the helper token');
  }
  const log = extensions.log ?? createLogger();
  let sites = new Map();
  const sealer = new Sealer(storeKey);
  const store = new SealedStore({ root: config.stateDir, sealer });
  const creds = new Credentials(config.credentialsDir);
  const stop = new AbortController();
  const pool = new BrowserPool({ maxBrowsers: config.maxBrowsers, allowNoSandbox: config.allowNoSandbox, log, signal: stop.signal });
  const oauth = createOAuth({ store, creds, log, ...extensions.oauth });
  const leases = new LeaseManager({
    store, pool, creds, log, revoke: oauth.revokeToken, timeouts: config.timeouts, logoutRetryMs: config.logoutRetryMs, signal: stop.signal,
  });
  const siteLocks = new KeyedMutex();
  const password = createPasswordStrategy({ pool, store, creds, log, abandon: (a) => leases.abandon(a), timeouts: config.timeouts });
  const interactive = createInteractive({
    pool,
    store,
    log,
    siteLocks,
    abandon: (a) => leases.abandon(a),
    stateDir: config.stateDir,
    runDir: path.dirname(config.socketPath),
    timeouts: config.timeouts,
    env: extensions.env ?? process.env,
    ...extensions.interactive,
  });
  const strategies = { 'password-totp': password, interactive: interactive.strategy, ...extensions.strategies };
  const table = Object.freeze({ ...ops, ...oauth.ops, ...interactive.ops, ...extensions.ops });

  const deps = {
    config,
    log,
    store,
    creds,
    pool,
    leases,
    oauth,
    interactive,
    strategies,
    siteLocks,
    now: () => Date.now(),
    sites: () => sites,
    setSites: (next) => {
      sites = next;
    },
    /** Signal that aborts after `ms` or when the helper stops. */
    opSignal: (ms) => AbortSignal.any([stop.signal, AbortSignal.timeout(ms)]),
  };

  const server = createSocketServer({
    socketPath: config.socketPath,
    mode: config.socketMode,
    group: config.socketGroup,
    token,
    adminToken,
    vaultdOps: VAULTD_OPS,
    log,
    handle: async (op, params) => {
      if (!Object.hasOwn(table, op)) throw new HelperError('unknown_op', `unknown op ${op}`);
      return table[op](params, deps);
    },
  });

  return {
    deps,
    /** Load sites, re-arm sealed leases, then accept requests. */
    async start() {
      const loaded = loadSites(config.sitesDir);
      sites = loaded.sites;
      for (const e of loaded.errors) log('warn', 'invalid site file', { file: e.file });
      await leases.recover();
      await server.listen();
      log('info', 'helper listening', { version: VERSION, sites: sites.size });
    },
    /** Resolves when lease ends started by recovery have finished. */
    idle: () => leases.idle(),
    /** Stop serving and end whatever runs: logouts, probes and browsers. Sealed leases stay on disk and resume at the next start. */
    async stop() {
      stop.abort(new HelperError('helper_down', 'helper is shutting down'));
      leases.stop();
      await server.close();
      oauth.shutdown();
      await interactive.shutdown();
      await password.shutdown();
      await leases.idle(); // aborted lease ends have returned (their sealed leases stay)
      await pool.closeAll(); // no browser outlives stop()
    },
  };
}
