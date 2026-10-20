// OAuth: device flow, redirect flow (PKCE, state, one callback), rotation, mint
// expiry clamp, revoke. Against tests/fakes/fake_oauth.py; no browser.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { after, afterEach, before, describe, test } from 'node:test';
import { REDIRECT_TTL_MS } from '../oauth.js';
import { Sealer } from '../seal.js';
import { oauthSite, scratch, sleep, startFakeOauth, startHelper, teardown } from './support.js';

const MIN = 60_000;

/** Everything a test needs: a fake provider, a helper with an injected poll sleep, one oauth site. */
async function setup({ provider = [], site = {}, oauth = {}, siteOver = {}, helper = {} } = {}) {
  const env = scratch();
  let fake, h;
  const sleeps = [];
  const down = () => teardown(() => h?.stop(), () => fake?.stop(), () => env.cleanup());
  try {
    fake = await startFakeOauth(provider);
    h = await startHelper(env, {
      extensions: { oauth: { sleep: async (ms) => void sleeps.push(ms), ...oauth } },
      ...helper,
    });
    env.writeSite(oauthSite(fake, { ...siteOver, oauth: site }));
    await h.ok('site.reload');
  } catch (err) {
    await down().catch(() => {});
    throw err;
  }
  const sealedRefreshToken = () => new Sealer(env.storeKey).open('oauth', 'drive', fs.readFileSync(`${env.state}/store/oauth/drive.enc`)).refreshToken;
  return { env, fake, h, sleeps, sealedRefreshToken, teardown: down };
}

async function authorizeByDevice(t) {
  const started = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'device' });
  const done = await t.h.ok('oauth.finish', { handle: started.handle });
  return { started, done };
}

let leaseCounter = 0;
const mint = (t, over = {}) => {
  leaseCounter += 1;
  return t.h.call('token.mint', { leaseId: `lse_oa${leaseCounter}`, siteId: 'drive', minutes: 30, scopes: ['drive.read'], ...over });
};

describe('device flow', () => {
  let t;
  before(async () => {
    t = await setup();
  });
  after(() => t?.teardown());

  test('start hands the root CLI the code and URL; finish polls once per interval until approved, then seals the refresh token', async () => {
    const { started, done } = await authorizeByDevice(t);
    assert.match(started.userCode, /^WDJB-/);
    assert.equal(started.verificationUri, `${t.fake.origin}/activate`);
    assert.equal(started.interval, 1);
    assert.ok(Date.parse(started.expiresAt) > Date.now());
    assert.deepEqual(done, { authorized: true, scopes: ['drive.read', 'drive.meta'] });
    assert.deepEqual(t.sleeps, [1000, 1000, 1000]); // pending, pending, approved
    const file = `${t.env.state}/store/oauth/drive.enc`;
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const rt = t.sealedRefreshToken();
    assert.match(rt, /^rt-/);
    assert.equal(fs.readFileSync(file).includes(rt), false, 'sealed, not plaintext');
    assert.equal((await t.h.call('oauth.finish', { handle: started.handle })).error.code, 'not_found', 'a handle is single use');
  });

  test('nothing secret reaches the logs', async () => {
    const dbg = await t.fake.debug();
    const log = t.h.logs.join('\n');
    for (const secret of [...Object.keys(dbg.access), t.sealedRefreshToken(), 'WDJB-']) assert.equal(log.includes(secret), false, secret);
  });

  test('flow must match the site, device flow takes no port', async () => {
    assert.equal((await t.h.call('oauth.start', { siteId: 'drive', flow: 'redirect' })).error.code, 'bad_request');
    assert.equal((await t.h.call('oauth.start', { siteId: 'drive', flow: 'device', port: 4000 })).error.code, 'bad_request');
    assert.equal((await t.h.call('oauth.start', { siteId: 'ghost', flow: 'device' })).error.code, 'not_found');
  });
});

describe('device flow: provider answers', () => {
  test('slow_down adds 5 seconds to the interval from then on', async () => {
    const t = await setup({ provider: ['--slow-down-at', '2'] });
    try {
      await authorizeByDevice(t);
      assert.deepEqual(t.sleeps, [1000, 1000, 6000]);
      assert.equal((await t.fake.debug()).slow_downs, 1);
    } finally {
      await t.teardown();
    }
  });

  test('access_denied is oauth_denied and seals nothing', async () => {
    const t = await setup({ provider: ['--deny'] });
    try {
      const started = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'device' });
      assert.equal((await t.h.call('oauth.finish', { handle: started.handle })).error.code, 'oauth_denied');
      assert.equal(fs.existsSync(`${t.env.state}/store/oauth/drive.enc`), false);
    } finally {
      await t.teardown();
    }
  });

  test('an expired device code is a timeout', async () => {
    const t = await setup({ provider: ['--device-expires', '1', '--pending', '50'], oauth: { sleep: () => sleep(1200) } });
    try {
      const started = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'device' });
      assert.equal((await t.h.call('oauth.finish', { handle: started.handle })).error.code, 'timeout');
    } finally {
      await t.teardown();
    }
  });

  test('a provider that issues no refresh token is an error, nothing is sealed', async () => {
    const t = await setup({ provider: ['--no-refresh-token'] });
    try {
      const started = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'device' });
      const res = await t.h.call('oauth.finish', { handle: started.handle });
      assert.equal(res.error.code, 'oauth_error');
      assert.match(res.error.message, /no refresh token/);
      assert.equal(fs.existsSync(`${t.env.state}/store/oauth/drive.enc`), false);
    } finally {
      await t.teardown();
    }
  });

  test('the client secret credential is sent when present; without it a confidential provider refuses', async () => {
    const t = await setup({ provider: ['--client-secret', 'S3CRET-VALUE'] });
    try {
      const refused = await t.h.call('oauth.start', { siteId: 'drive', flow: 'device' });
      assert.equal(refused.error.code, 'oauth_error');
      assert.match(refused.error.message, /invalid_client/);
      fs.writeFileSync(path.join(t.env.creds, 'vault-helper.site.drive.oauth-client-secret'), 'S3CRET-VALUE\n');
      await authorizeByDevice(t);
      await t.h.ok('token.mint', { leaseId: 'lse_cs01', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
      assert.equal((await t.fake.debug()).bad_client, 1);
      assert.equal(t.h.logs.join('\n').includes('S3CRET-VALUE'), false);
      assert.equal(t.env.files().some((f) => fs.readFileSync(f).includes('S3CRET-VALUE')), false);
    } finally {
      await t.teardown();
    }
  });
});

describe('token.mint, rotation, revoke', () => {
  let t;
  before(async () => {
    t = await setup();
    await authorizeByDevice(t);
  });
  after(() => t?.teardown());

  test('mints an access token the provider accepts; the answer carries type, expiry and scopes', async () => {
    const before = Date.now();
    const res = await t.h.ok('token.mint', { leaseId: 'lse_m001', siteId: 'drive', minutes: 30, scopes: ['drive.read'] });
    assert.match(res.accessToken, /^at-/);
    assert.equal(res.tokenType, 'Bearer');
    assert.deepEqual(res.scopes, ['drive.read']);
    assert.equal(await t.fake.resource(res.accessToken), 200);
    // provider says 3600 s, the lease asked for 30 minutes: the lease wins
    const exp = Date.parse(res.expiresAt);
    assert.ok(exp >= before + 30 * MIN - 2000 && exp <= Date.now() + 30 * MIN, res.expiresAt);
    assert.deepEqual(t.h.helper.deps.leases.list().map((l) => l.leaseId), ['lse_m001']);
    assert.equal((await t.fake.debug()).last_refresh_scope, 'drive.read');
  });

  test('expiresAt is the smallest of provider expiry, request, site maxMinutes and accessTtlMaxMinutes', async () => {
    // minutes 120 > accessTtlMaxMinutes 45 (site maxMinutes is 60)
    const before = Date.now();
    const res = await t.h.ok('token.mint', { leaseId: 'lse_m002', siteId: 'drive', minutes: 120, scopes: ['drive.read'] });
    const exp = Date.parse(res.expiresAt);
    assert.ok(exp >= before + 45 * MIN - 2000 && exp <= Date.now() + 45 * MIN, res.expiresAt);
  });

  test('a provider expiry shorter than the lease wins', async () => {
    const s = await setup({ provider: ['--expires-in', '120'] });
    try {
      await authorizeByDevice(s);
      const res = await s.h.ok('token.mint', { leaseId: 'lse_m003', siteId: 'drive', minutes: 30, scopes: ['drive.read'] });
      const left = Date.parse(res.expiresAt) - Date.now();
      assert.ok(left > 100_000 && left <= 120_000, String(left));
    } finally {
      await s.teardown();
    }
  });

  test('the refresh token rotates: a new one is sealed before each access token is returned, the old one is dead', async () => {
    const first = t.sealedRefreshToken();
    await t.h.ok('token.mint', { leaseId: 'lse_r001', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
    const second = t.sealedRefreshToken();
    await t.h.ok('token.mint', { leaseId: 'lse_r002', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
    const third = t.sealedRefreshToken();
    assert.equal(new Set([first, second, third]).size, 3);
    const dbg = await t.fake.debug();
    assert.equal(dbg.live_refresh, 1);
    assert.equal(dbg.refresh_reuse, 0);
    assert.equal(t.h.logs.join('\n').includes(third), false);
  });

  test('concurrent mints are serialised: each uses the refresh token the previous one left', async () => {
    const results = await Promise.all([1, 2, 3].map((i) => mint(t, { leaseId: `lse_c00${i}`, minutes: 5 })));
    assert.deepEqual(results.map((r) => r.ok), [true, true, true]);
    assert.equal((await t.fake.debug()).refresh_reuse, 0);
  });

  test('scopes must be a subset of the site scopes', async () => {
    assert.equal((await mint(t, { scopes: ['drive.write'] })).error.code, 'bad_request');
    assert.equal((await mint(t, { scopes: [] })).error.code, 'bad_request');
    assert.equal((await mint(t, { scopes: 'drive.read' })).error.code, 'bad_request');
    assert.equal((await mint(t, { minutes: 0 })).error.code, 'bad_request');
    const all = await t.h.ok('token.mint', { leaseId: 'lse_all1', siteId: 'drive', minutes: 5 });
    assert.deepEqual(all.scopes, ['drive.read', 'drive.meta']);
    assert.equal((await mint(t, { leaseId: 'lse_all1' })).error.code, 'conflict', 'a lease id is used once');
  });

  test('token.revoke calls the revoke endpoint and the token stops working; it is idempotent', async () => {
    const res = await t.h.ok('token.mint', { leaseId: 'lse_v001', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
    assert.equal(await t.fake.resource(res.accessToken), 200);
    assert.deepEqual(await t.h.ok('token.revoke', { leaseId: 'lse_v001' }), { revoked: true });
    assert.equal(await t.fake.resource(res.accessToken), 401);
    assert.deepEqual(await t.h.ok('token.revoke', { leaseId: 'lse_v001' }), { revoked: true });
    assert.equal(fs.existsSync(`${t.env.state}/leases/lse_v001.enc`), false);
    assert.equal((await t.h.call('token.revoke', { leaseId: 'lse_never' })).error.code, 'not_found');
  });

  test('the minted token is sealed with the lease, never in plaintext', async () => {
    const res = await t.h.ok('token.mint', { leaseId: 'lse_s001', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
    const blob = fs.readFileSync(`${t.env.state}/leases/lse_s001.enc`);
    assert.equal(blob.includes(res.accessToken), false);
    const sealed = new Sealer(t.env.storeKey).open('lease', 'lse_s001', blob);
    assert.equal(sealed.token.accessToken, res.accessToken);
  });

  test('ping lists token leases', async () => {
    const ping = await t.h.ok('ping');
    assert.ok(ping.leases.some((l) => l.siteId === 'drive'));
  });
});

describe('token lifecycle without a revoke endpoint or authorization', () => {
  test('no revokeUrl: unsupported', async () => {
    const t = await setup({ site: { revokeUrl: null } });
    try {
      await authorizeByDevice(t);
      await t.h.ok('token.mint', { leaseId: 'lse_n001', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
      assert.deepEqual(await t.h.ok('token.revoke', { leaseId: 'lse_n001' }), { revoked: 'unsupported' });
    } finally {
      await t.teardown();
    }
  });

  test('not authorized yet, or a refresh token the provider rejects: needs_authorize', async () => {
    const t = await setup();
    try {
      assert.equal((await mint(t)).error.code, 'needs_authorize');
      await t.h.helper.deps.store.put('oauth', 'drive', { v: 1, refreshToken: 'rt-bogus', scopes: [] });
      assert.equal((await mint(t)).error.code, 'needs_authorize');
      assert.equal(t.h.helper.deps.leases.list().length, 0);
    } finally {
      await t.teardown();
    }
  });

  test('session.open on an oauth site is refused: tokens come from token.mint', async () => {
    const t = await setup();
    try {
      const res = await t.h.call('session.open', { leaseId: 'lse_x', siteId: 'drive', minutes: 5, endsAt: new Date(Date.now() + 60_000).toISOString() });
      assert.equal(res.error.code, 'bad_request');
    } finally {
      await t.teardown();
    }
  });

  test('a token lease that ended while the helper was down is revoked at the next start', async () => {
    const t = await setup();
    let again;
    try {
      await authorizeByDevice(t);
      const res = await t.h.ok('token.mint', { leaseId: 'lse_d001', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
      assert.equal(await t.fake.resource(res.accessToken), 200);
      // The helper dies; the lease end passes; a new helper starts on the same state.
      await t.h.stop();
      const store = t.h.helper.deps.store;
      const sealed = await store.get('lease', 'lse_d001');
      await store.put('lease', 'lse_d001', { ...sealed, endsAt: new Date(Date.now() - 1000).toISOString() });
      again = await startHelper(t.env, { extensions: { oauth: { sleep: async () => {} } } });
      await again.helper.idle();
      assert.equal(await t.fake.resource(res.accessToken), 401);
      assert.equal(fs.existsSync(`${t.env.state}/leases/lse_d001.enc`), false);
    } finally {
      await teardown(() => again?.stop(), () => t.teardown());
    }
  });
});

/** Open the authorization URL like the owner's browser would, then hit the callback the provider redirects to. */
async function approve(t, authUrl) {
  const res = await fetch(authUrl, { redirect: 'manual' });
  assert.equal(res.status, 302);
  return res.headers.get('location');
}

function rawGet(port, urlPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: urlPath, headers, agent: false }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
  });
}

const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

const refused = (port) =>
  new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    s.once('connect', () => {
      s.destroy();
      resolve(false);
    });
    s.once('error', () => resolve(true));
  });

describe('redirect flow', () => {
  let t;
  before(async () => {
    t = await setup({ site: { flow: 'redirect' } });
  });
  after(() => t?.teardown());
  afterEach(() => {
    t?.h.helper.deps.oauth.shutdown();
  });

  test('listens on 127.0.0.1 only, PKCE S256 + state; one callback; the code is exchanged with the verifier', async () => {
    const port = await freePort();
    const started = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'redirect', port });
    assert.deepEqual(started.listen, { host: '127.0.0.1', port });
    assert.equal(started.redirectUri, `http://127.0.0.1:${port}/callback`);
    const url = new URL(started.authUrl);
    assert.equal(url.origin + url.pathname, `${t.fake.origin}/authorize`);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('client_id'), 'client-1');
    assert.equal(url.searchParams.get('scope'), 'drive.read drive.meta');
    assert.ok(url.searchParams.get('state').length >= 32);
    assert.ok(url.searchParams.get('code_challenge').length >= 43);
    assert.ok(Date.parse(started.expiresAt) - Date.now() > 9 * MIN);
    assert.equal(REDIRECT_TTL_MS, 10 * MIN);

    // bound to loopback only
    const listening = t.h.helper.deps.oauth.pendingCount();
    assert.equal(listening, 1);

    const callback = new URL(await approve(t, started.authUrl));
    assert.equal(callback.origin, `http://127.0.0.1:${port}`);
    // a callback with another state or a foreign Host header is not the one
    assert.equal(await rawGet(port, `/callback?code=x&state=wrong`), 400);
    assert.equal(await rawGet(port, `${callback.pathname}${callback.search}`, { Host: 'evil.example:80' }), 404);
    assert.equal(await rawGet(port, '/other'), 404);
    assert.equal(await rawGet(port, `${callback.pathname}${callback.search}`), 200);
    // the listener is gone after the one callback
    await sleep(50);
    assert.equal(await refused(port), true);

    const done = await t.h.ok('oauth.finish', { handle: started.handle });
    assert.deepEqual(done, { authorized: true, scopes: ['drive.read', 'drive.meta'] });
    const dbg = await t.fake.debug();
    assert.deepEqual([dbg.code_exchanges, dbg.pkce_failures], [1, 0]);
    assert.match(t.sealedRefreshToken(), /^rt-/);
    const res = await t.h.ok('token.mint', { leaseId: 'lse_rd01', siteId: 'drive', minutes: 5, scopes: ['drive.read'] });
    assert.equal(await t.fake.resource(res.accessToken), 200);
  });

  test('finish may be called before the owner arrives: it waits for the callback', async () => {
    const started = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'redirect' });
    const finishing = t.h.call('oauth.finish', { handle: started.handle });
    await sleep(100);
    assert.equal((await t.h.call('oauth.finish', { handle: started.handle })).error.code, 'conflict', 'one finish at a time');
    const callback = new URL(await approve(t, started.authUrl));
    assert.equal(await rawGet(started.listen.port, `${callback.pathname}${callback.search}`), 200);
    assert.equal((await finishing).ok, true);
  });

  test('the provider denying is oauth_denied', async () => {
    const s = await setup({ provider: ['--deny'], site: { flow: 'redirect' } });
    try {
      const started = await s.h.ok('oauth.start', { siteId: 'drive', flow: 'redirect' });
      const callback = new URL(await approve(s, started.authUrl));
      assert.equal(await rawGet(started.listen.port, `${callback.pathname}${callback.search}`), 200);
      assert.equal((await s.h.call('oauth.finish', { handle: started.handle })).error.code, 'oauth_denied');
    } finally {
      await s.teardown();
    }
  });

  test('no callback within the time limit: the listener closes and finish times out', async () => {
    const s = await setup({ site: { flow: 'redirect' }, oauth: { redirectTtlMs: 300 } });
    try {
      const started = await s.h.ok('oauth.start', { siteId: 'drive', flow: 'redirect' });
      const res = await s.h.call('oauth.finish', { handle: started.handle });
      assert.equal(res.error.code, 'timeout');
      assert.equal(await refused(started.listen.port), true);
      assert.equal(s.h.helper.deps.oauth.pendingCount(), 0);
    } finally {
      await s.teardown();
    }
  });

  test('a port in use is a conflict; flow must be redirect; a second start for the site replaces the first', async () => {
    const taken = net.createServer();
    await new Promise((r) => taken.listen(0, '127.0.0.1', r));
    try {
      const res = await t.h.call('oauth.start', { siteId: 'drive', flow: 'redirect', port: taken.address().port });
      assert.equal(res.error.code, 'conflict');
    } finally {
      taken.close();
    }
    assert.equal((await t.h.call('oauth.start', { siteId: 'drive', flow: 'device' })).error.code, 'bad_request');
    assert.equal((await t.h.call('oauth.start', { siteId: 'drive', flow: 'redirect', port: 80 })).error.code, 'bad_request');
    const first = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'redirect' });
    const second = await t.h.ok('oauth.start', { siteId: 'drive', flow: 'redirect' });
    assert.equal((await t.h.call('oauth.finish', { handle: first.handle })).error.code, 'not_found');
    assert.equal(await refused(first.listen.port), true);
    assert.equal(await refused(second.listen.port), false);
  });
});
