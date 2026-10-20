// Late failures log out, "remember this device", trusted localStorage, exact
// host:port navigation, stop during a lease end. Real Chromium (heavy).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { after, before, describe, test } from 'node:test';
import { Sealer } from '../seal.js';
import {
  FAST, SKIP_BROWSER, SMS_CODE, descendants, eventually, fakeSite, inSeconds, open, scratch, sleep, startFakeSite, startHelper, teardown,
  waitForExit,
} from './support.js';

async function setup({ fakeArgs = ['--no-challenge'], config } = {}) {
  const env = scratch();
  let site, h;
  const down = () => teardown(() => h?.stop(), () => site?.stop(), () => env.cleanup());
  try {
    site = await startFakeSite(fakeArgs);
    h = await startHelper(env, { config });
  } catch (err) {
    await down().catch(() => {});
    throw err;
  }
  const install = async (over, creds) => {
    const s = fakeSite(site, over);
    env.writeSite(s);
    env.writeCreds(s.id, creds);
    await h.ok('site.reload');
    return s;
  };
  return { env, site, h, install, teardown: down };
}

describe('a failure after the credentials went in logs out and closes the browser', { skip: SKIP_BROWSER }, () => {
  let t;
  before(async () => {
    t = await setup({ config: { timeouts: { ...FAST, successMs: 2500 } } });
  });
  after(() => t?.teardown());

  test('success check that never holds: the session the site opened is logged out before the error returns', async () => {
    await t.install({ id: 'late', recipe: { successCheck: { selector: '#never' } } });
    const logoutsBefore = (await t.site.debug()).logouts;
    const res = await open(t.h, { siteId: 'late' });
    assert.equal(res.error.code, 'totp_failed');
    const dbg = await t.site.debug();
    assert.equal(dbg.sessions, 0, 'no session is left at the site');
    assert.equal(dbg.logouts, logoutsBefore + 1);
    assert.equal(t.h.helper.deps.leases.list().length, 0);
  });

  test('the recipe time budget running out: logged out, timeout returned', async () => {
    const s = await setup({ config: { timeouts: { ...FAST, successMs: 60_000 } } });
    try {
      await s.install({ id: 'budget', recipe: { successCheck: { selector: '#never' }, timeoutSeconds: 5 } });
      const res = await open(s.h, { siteId: 'budget' });
      assert.equal(res.error.code, 'timeout');
      const dbg = await s.site.debug();
      assert.equal(dbg.logins, 1);
      assert.equal(dbg.sessions, 0);
      assert.equal(dbg.logouts, 1);
    } finally {
      await s.teardown();
    }
  });

  test('the whole operation timing out while the browser waits: the cookies are captured first, then it is logged out', async () => {
    const s = await setup({ config: { timeouts: { ...FAST, openMs: 6000, successMs: 60_000 } } });
    try {
      await s.install({ id: 'abort', recipe: { successCheck: { selector: '#never' }, timeoutSeconds: 120 } });
      const res = await open(s.h, { siteId: 'abort' });
      assert.equal(res.error.code, 'timeout');
      const dbg = await s.site.debug();
      assert.equal(dbg.logins, 1);
      assert.equal(dbg.sessions, 0, 'the session was logged out although the browser was killed by the timeout');
      assert.equal(dbg.logouts, 1);
    } finally {
      await s.teardown();
    }
  });

  test('a lease that cannot be sealed: the login is logged out and nothing is handed out', async () => {
    const s = await setup();
    try {
      await s.install({ id: 'seal' });
      fs.writeFileSync(`${s.env.state}/leases`, 'a file where the lease directory should be');
      const res = await open(s.h, { siteId: 'seal' });
      assert.equal(res.ok, false);
      assert.equal(res.error.code, 'internal');
      const dbg = await s.site.debug();
      assert.equal(dbg.sessions, 0);
      assert.equal(dbg.logouts, 1);
      assert.equal(s.h.helper.deps.leases.list().length, 0);
      assert.equal(s.h.logs.join('\n').includes('FAKE'), false);
    } finally {
      await s.teardown();
    }
  });

  test('no logout recipe and no logoutUrl: the failure is still reported as before', async () => {
    await t.install({ id: 'nologout', recipe: { successCheck: { selector: '#never' }, logout: null } });
    const res = await open(t.h, { siteId: 'nologout' });
    assert.equal(res.error.code, 'totp_failed');
  });

  test('a wrong password does not slow the error down by more than the abandon budget', async () => {
    await t.install({ id: 'wrongpw' }, { password: 'nope' });
    const sessions = (await t.site.debug()).sessions;
    const started = Date.now();
    const res = await open(t.h, { siteId: 'wrongpw' });
    assert.equal(res.error.code, 'login_failed');
    assert.ok(Date.now() - started < 25_000, `${Date.now() - started} ms`);
    assert.equal((await t.site.debug()).sessions, sessions);
  });
});

describe('challenge.remember', { skip: SKIP_BROWSER }, () => {
  let t;
  before(async () => {
    t = await setup({ fakeArgs: ['--require-remember'] });
  });
  after(() => t?.teardown());

  const attended = async (id) => {
    const started = await t.h.ok('site.test', { siteId: id, attended: true });
    assert.equal(started.state, 'challenge');
    return t.h.ok('challenge.submit', { handle: started.handle, code: SMS_CODE });
  };

  test('with the selector the "remember this device" box is ticked: the next login skips the challenge', async () => {
    const challenge = { codeSelector: '#code', submit: '#go', remember: '#remember' };
    await t.install({ id: 'remember', recipe: { challenge } });
    assert.equal((await attended('remember')).state, 'ok');
    const res = await open(t.h, { siteId: 'remember', leaseId: 'lse_rem1' });
    assert.equal(res.ok, true);
    assert.equal(res.data.trustUsed, true);
    await t.h.ok('session.close', { leaseId: 'lse_rem1' });
  });

  test('without it the site does not remember the device: the challenge comes back', async () => {
    await t.install({ id: 'forget' });
    assert.equal((await attended('forget')).state, 'ok');
    const res = await open(t.h, { siteId: 'forget' });
    assert.equal(res.error.code, 'challenge_required');
  });

  test('an absent remember control is skipped, not an error', async () => {
    const challenge = { codeSelector: '#code', submit: '#go', remember: '#not-on-this-page' };
    await t.install({ id: 'absent', recipe: { challenge } });
    assert.equal((await attended('absent')).state, 'ok');
  });
});

describe('trusted localStorage and exact origins', { skip: SKIP_BROWSER }, () => {
  let t;
  before(async () => {
    t = await setup();
  });
  after(() => t?.teardown());

  test('keys matching trustStorageKeys stay in the helper (sealed trust jar), the rest is returned for the allowed origin only', async () => {
    await t.install({ id: 'ls', recipe: { trustStorageKeys: ['^device_'] } });
    const res = await t.h.ok('session.open', { leaseId: 'lse_ls01', siteId: 'ls', minutes: 5, endsAt: inSeconds(120) });
    const origins = res.storageState.origins;
    assert.deepEqual(origins.map((o) => o.origin), [t.site.origin]);
    assert.deepEqual(origins[0].localStorage, [{ name: 'theme', value: 'dark' }]);
    assert.equal(JSON.stringify(res.storageState).includes('LS-TRUST-VALUE'), false);

    const trust = new Sealer(t.env.storeKey).open('trust', 'ls', fs.readFileSync(`${t.env.state}/store/trust/ls.enc`));
    assert.deepEqual(trust.origins, [{ origin: t.site.origin, localStorage: [{ name: 'device_token', value: 'LS-TRUST-VALUE' }] }]);
    assert.equal(fs.readFileSync(`${t.env.state}/store/trust/ls.enc`).includes('LS-TRUST-VALUE'), false);
    // the second login starts with the trusted key loaded
    const again = await t.h.ok('session.open', { leaseId: 'lse_ls02', siteId: 'ls', minutes: 5, endsAt: inSeconds(120) });
    assert.equal(again.trustUsed, true);
    await t.h.ok('session.close', { leaseId: 'lse_ls01' });
    await t.h.ok('session.close', { leaseId: 'lse_ls02' });
  });

  test('without trustStorageKeys everything is returned (as before)', async () => {
    await t.install({ id: 'ls-all' });
    const res = await t.h.ok('session.open', { leaseId: 'lse_ls03', siteId: 'ls-all', minutes: 5, endsAt: inSeconds(120) });
    assert.deepEqual(res.storageState.origins[0].localStorage.map((i) => i.name).sort(), ['device_token', 'theme']);
    await t.h.ok('session.close', { leaseId: 'lse_ls03' });
    assert.equal(fs.existsSync(`${t.env.state}/store/trust/ls-all.enc`), false);
  });
});

describe('navigation is exact host:port', { skip: SKIP_BROWSER }, () => {
  let t, other;
  before(async () => {
    t = await setup();
    other = await startFakeSite(['--no-challenge']);
  });
  after(() => teardown(() => other?.stop(), () => t?.teardown()));

  test('a login page that redirects to the same host name on another port fails closed', async () => {
    await t.install({ id: 'port', loginUrl: `${t.site.origin}/bounce?to=${encodeURIComponent(`${other.origin}/login`)}` });
    const res = await open(t.h, { siteId: 'port' });
    assert.equal(res.error.code, 'recipe_error');
    assert.match(res.error.message, new RegExp(`disallowed host ${other.host.replace('.', '\\.')} was blocked`));
    assert.equal((await t.site.debug()).sessions, 0);
    assert.equal(t.h.helper.deps.leases.list().length, 0);
  });

  test('a redirect that stays inside the allowed host:port is fine', async () => {
    await t.install({ id: 'hop', loginUrl: `${t.site.origin}/bounce?to=${encodeURIComponent(`${t.site.origin}/login`)}` });
    const ok = await open(t.h, { siteId: 'hop', leaseId: 'lse_hop1' });
    assert.equal(ok.ok, true);
    await t.h.ok('session.close', { leaseId: 'lse_hop1' });
  });
});

describe('helper stop during a lease end', { skip: SKIP_BROWSER }, () => {
  test('the sealed lease is kept when the logout was not completed; the next start picks it up', async () => {
    const t = await setup({ config: { timeouts: { ...FAST, stepMs: 1000 }, logoutRetryMs: [0, 4000] } });
    let again;
    try {
      await t.install({ id: 'stopme', recipe: { logout: { steps: [{ click: '#no-such-button' }] } } });
      await t.h.ok('session.open', { leaseId: 'lse_stop1', siteId: 'stopme', minutes: 5, endsAt: inSeconds(300) });
      const closing = t.h.call('session.close', { leaseId: 'lse_stop1' }).catch(() => null);
      await sleep(2500); // first attempt failed, the second waits for its delay
      await t.h.stop();
      await closing;
      await sleep(4500);
      const file = `${t.env.state}/leases/lse_stop1.enc`;
      assert.equal(fs.existsSync(file), true, 'not shredded before the logout completed');
      again = await startHelper(t.env, { config: { timeouts: { ...FAST, stepMs: 1000 }, logoutRetryMs: [0] } });
      assert.deepEqual((await again.ok('ping')).leases.map((l) => l.leaseId), ['lse_stop1']);
    } finally {
      await teardown(() => again?.stop(), () => t.teardown());
    }
  });

  test('stop() during an in-flight logout aborts it and leaves no browser open', async () => {
    // The logout waits up to a minute for a button that never comes.
    const t = await setup({ config: { timeouts: { ...FAST, stepMs: 60_000 }, logoutRetryMs: [0] } });
    try {
      await t.install({ id: 'inflight', recipe: { logout: { steps: [{ click: '#no-such-button' }] } } });
      await t.h.ok('session.open', { leaseId: 'lse_inf1', siteId: 'inflight', minutes: 5, endsAt: inSeconds(300) });
      const pool = t.h.helper.deps.pool;
      assert.equal(pool.active, 0, 'the login closed its browser');
      const before = new Set(descendants().map((p) => p.pid));
      const closing = t.h.call('session.close', { leaseId: 'lse_inf1' }).catch(() => null);
      await eventually(() => pool.active === 1, 'the logout browser to be up');
      const browser = descendants().filter((p) => !before.has(p.pid)).map((p) => p.pid);
      assert.ok(browser.length > 0, 'the browser processes were found by PID');

      await t.h.stop();
      assert.equal(pool.active, 0, 'the pool is empty once stop() returned');
      await waitForExit(browser, 'the logout browser');
      await closing;
      assert.equal(fs.existsSync(`${t.env.state}/leases/lse_inf1.enc`), true, 'the interrupted logout keeps the sealed lease');
    } finally {
      await t.teardown();
    }
  });
});
