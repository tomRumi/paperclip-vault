// Failure codes, the allowedHosts guard and the queue, with real Chromium.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import {
  FAST, OTHER_SECRET, PASSWORD, SKIP_BROWSER, fakeSite, open, scratch, startFakeSite, startHelper, teardown,
} from './support.js';

const QUICK = FAST;

async function setup({ fakeArgs = ['--no-challenge'], config } = {}) {
  const env = scratch();
  let site, h;
  const down = () => teardown(() => h?.stop(), () => site?.stop(), () => env.cleanup());
  try {
    site = await startFakeSite(fakeArgs);
    h = await startHelper(env, { config: { timeouts: QUICK, ...config } });
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

describe('failure codes', { skip: SKIP_BROWSER }, () => {
  let t;
  before(async () => {
    t = await setup();
  });
  after(() => t?.teardown());

  const code = async (over, creds, params) => {
    const s = await t.install(over, creds);
    const res = await open(t.h, { siteId: s.id, ...params });
    assert.equal(res.ok, false, `expected a failure for ${s.id}`);
    assert.equal(t.h.helper.deps.leases.list().length, 0, 'a failed login leaves no lease');
    return res.error;
  };

  test('a wrong TOTP code is totp_failed, without echoing any secret', async () => {
    const err = await code({}, { totp: OTHER_SECRET });
    assert.equal(err.code, 'totp_failed');
    assert.equal(JSON.stringify(err).includes(OTHER_SECRET), false);
    assert.ok((await t.site.debug()).bad_totp >= 1);
  });

  test('a wrong password is login_failed', async () => {
    const err = await code({}, { password: `${PASSWORD}x` });
    assert.equal(err.code, 'login_failed');
    assert.equal(JSON.stringify(err).includes(PASSWORD), false);
  });

  test('a missing credential is missing_credential', async () => {
    assert.equal((await code({}, { totp: null })).code, 'missing_credential');
  });

  test('a selector that never shows up is recipe_error', async () => {
    const err = await code({ recipe: { steps: [{ click: '#does-not-exist' }] } });
    assert.equal(err.code, 'recipe_error');
    assert.match(err.message, /step 1: selector not found/);
  });

  test('an optional step whose selector is absent is skipped, a required one is not', async () => {
    const s = fakeSite(t.site);
    s.recipe.steps = [...s.recipe.steps.slice(0, 4), { click: '#nope', optional: true }, ...s.recipe.steps.slice(4)];
    t.env.writeSite(s);
    await t.h.ok('site.reload');
    const res = await open(t.h, { siteId: s.id, leaseId: 'lse_opt1' });
    assert.equal(res.ok, true);
    await t.h.ok('session.close', { leaseId: 'lse_opt1' });
  });

  test('a CAPTCHA is reported as needs_interactive', async () => {
    const err = await code({ id: 'captcha', loginUrl: `${t.site.origin}/login-captcha`, recipe: { steps: [{ waitFor: '.g-recaptcha' }] } });
    assert.equal(err.code, 'needs_interactive');
  });

  test('an unreachable site is site_unreachable', async () => {
    const err = await code({ id: 'down', loginUrl: 'http://127.0.0.1:1/login', allowedHosts: ['127.0.0.1:1'] });
    assert.equal(err.code, 'site_unreachable');
  });

  test('a success check that never holds fails the login, named after the last credential entered', async () => {
    const err = await code({ id: 'nosuccess', recipe: { successCheck: { selector: '#never' } } });
    assert.equal(err.code, 'totp_failed');
  });
});

describe('allowedHosts guard', { skip: SKIP_BROWSER }, () => {
  let t;
  before(async () => {
    t = await setup();
  });
  after(() => t?.teardown());

  test('a login page that redirects to another host is blocked', async () => {
    await t.install({ id: 'redir', loginUrl: `${t.site.origin}/out` });
    const res = await open(t.h, { siteId: 'redir' });
    assert.equal(res.error.code, 'recipe_error');
    assert.match(res.error.message, new RegExp(`disallowed host localhost:${t.site.port} was blocked`));
    assert.equal((await t.site.debug()).sessions, 0);
  });

  test('a navigation to another host during the recipe is blocked, even when the success check still holds', async () => {
    const s = fakeSite(t.site, { id: 'leave' });
    s.recipe.steps.push({ click: '#out', optional: false });
    t.env.writeSite(s);
    t.env.writeCreds('leave');
    await t.h.ok('site.reload');
    const res = await open(t.h, { siteId: 'leave' });
    assert.equal(res.error.code, 'recipe_error');
    assert.match(res.error.message, /disallowed host/);
  });

  test('sub-resources from other hosts are aborted, the login itself works', async () => {
    assert.equal((await t.site.debug()).foreign_host_requests, 0);
    await t.install({ id: 'plain' });
    const res = await open(t.h, { siteId: 'plain', leaseId: 'lse_pl01' });
    assert.equal(res.ok, true);
    await t.h.ok('session.close', { leaseId: 'lse_pl01' });
    // the dashboard embeds an image from localhost:<port>, a host outside allowedHosts
    assert.equal((await t.site.debug()).foreign_host_requests, 0);
  });
});

describe('queue', { skip: SKIP_BROWSER }, () => {
  const logins = (h, ids, minutes = 5) =>
    Promise.all(ids.map((siteId, i) => open(h, { siteId, leaseId: `lse_q${siteId}${i}`, minutes })));

  test('one login per site at a time', async () => {
    const t = await setup({ fakeArgs: ['--no-challenge', '--password-delay', '1'] });
    try {
      await t.install({ id: 'solo' });
      const results = await logins(t.h, ['solo', 'solo']);
      assert.deepEqual(results.map((r) => r.ok), [true, true]);
      assert.equal((await t.site.debug()).max_in_flight_password, 1);
      assert.equal(t.h.helper.deps.leases.list().length, 2);
    } finally {
      await t.teardown();
    }
  });

  test('different sites log in in parallel, at most 3 browsers at once', async () => {
    const t = await setup({ fakeArgs: ['--no-challenge', '--password-delay', '1.5'], config: { timeouts: { ...QUICK, stepMs: 15_000, successMs: 12_000 } } });
    try {
      const ids = ['s1', 's2', 's3', 's4'];
      for (const id of ids) await t.install({ id });
      const results = await logins(t.h, ids);
      assert.deepEqual(results.map((r) => r.ok), [true, true, true, true]);
      assert.equal((await t.site.debug()).max_in_flight_password, 3);
    } finally {
      await t.teardown();
    }
  });
});
