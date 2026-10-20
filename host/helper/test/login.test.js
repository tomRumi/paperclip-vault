// Real headless Chromium against tests/fakes/fake_site.py.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { after, before, describe, test } from 'node:test';
import { Sealer } from '../seal.js';
import {
  PASSWORD, SKIP_BROWSER, SMS_CODE, TOTP_SECRET, fakeSite, inSeconds, open, scratch, sleep,
  startFakeSite, startHelper, teardown,
} from './support.js';

describe('password + TOTP login', { skip: SKIP_BROWSER }, () => {
  let env, site, h;

  before(async () => {
    env = scratch();
    site = await startFakeSite();
    env.writeSite(fakeSite(site));
    env.writeCreds('fake');
    h = await startHelper(env);
  });

  after(() => teardown(() => h?.stop(), () => site?.stop(), () => env?.cleanup()));

  test('ping reports version, browsers and no leases', async () => {
    const data = await h.ok('ping');
    assert.match(data.version, /^\d+\.\d+\.\d+$/);
    assert.equal(data.browsers, true);
    assert.deepEqual(data.leases, []);
  });

  test('an untrusted device meets the challenge: refused unattended, solved attended', async () => {
    const res = await open(h);
    assert.equal(res.ok, false);
    assert.equal(res.error.code, 'challenge_required');
    assert.equal((await site.debug()).sessions, 0);
    assert.equal(h.helper.deps.leases.list().length, 0);

    const started = await h.ok('site.test', { siteId: 'fake', attended: true });
    assert.equal(started.state, 'challenge');
    assert.match(started.handle, /^chl_[0-9a-f]{16}$/);

    const wrong = await h.call('challenge.submit', { handle: started.handle, code: '000000' });
    assert.equal(wrong.error.code, 'login_failed');
    const done = await h.ok('challenge.submit', { handle: started.handle, code: SMS_CODE });
    assert.deepEqual([done.state, done.trustUsed, done.loggedOut], ['ok', false, true]);

    const dbg = await site.debug();
    assert.equal(dbg.challenges_passed, 1);
    assert.equal(dbg.sessions, 0, 'the test login was logged out again');
    assert.equal(fs.existsSync(`${env.state}/store/trust/fake.enc`), true);
    assert.equal((await h.call('challenge.submit', { handle: started.handle, code: SMS_CODE })).error.code, 'not_found');
  });

  let first;
  test('the trusted device skips the challenge; trust cookies never leave; cookies end with the lease', async () => {
    const before = await site.debug();
    const endsAt = inSeconds(120);
    const res = await h.ok('session.open', { leaseId: 'lse_aaaa', siteId: 'fake', minutes: 5, endsAt });
    first = res;
    assert.equal(res.trustUsed, true);
    assert.equal((await site.debug()).challenges_served, before.challenges_served, 'no challenge was shown');
    assert.equal(res.expiresAt, endsAt);

    const names = res.storageState.cookies.map((c) => c.name).sort();
    assert.deepEqual(names, ['pre', 'pref', 'sid']);
    assert.equal(JSON.stringify(res).includes('device_trust'), false);
    const endsSec = Math.floor(Date.parse(endsAt) / 1000);
    for (const c of res.storageState.cookies) {
      assert.ok(c.expires > 0 && c.expires <= endsSec, `${c.name} expires ${c.expires} must be <= ${endsSec}`);
    }
    // pref lives a year on the site, sid and pre are session cookies: all end with the lease
    assert.deepEqual(res.storageState.cookies.map((c) => c.expires), [endsSec, endsSec, endsSec]);
    assert.ok(Array.isArray(res.storageState.origins));
    assert.equal(await site.meStatus(res.storageState.cookies), 200);

    const ping = await h.ok('ping');
    assert.deepEqual(ping.leases, [{ leaseId: 'lse_aaaa', siteId: 'fake', endsAt }]);
    assert.ok(['on', 'off'].includes(ping.sandbox), 'the sandbox mode is reported once a browser ran');
  });

  test('session.close logs out server-side, shreds the lease file, and is idempotent', async () => {
    assert.equal(fs.existsSync(`${env.state}/leases/lse_aaaa.enc`), true);
    assert.deepEqual(await h.ok('session.close', { leaseId: 'lse_aaaa' }), { loggedOut: true });
    assert.equal(await site.meStatus(first.storageState.cookies), 401);
    assert.equal(fs.existsSync(`${env.state}/leases/lse_aaaa.enc`), false);
    assert.deepEqual((await h.ok('ping')).leases, []);
    assert.deepEqual(await h.ok('session.close', { leaseId: 'lse_aaaa' }), { loggedOut: true });
    assert.equal((await h.call('session.close', { leaseId: 'lse_zzzz' })).error.code, 'not_found');
  });

  test('sealed files hold no readable secrets, the key is needed, and nothing is logged', async () => {
    const res = await h.ok('session.open', { leaseId: 'lse_bbbb', siteId: 'fake', minutes: 5, endsAt: inSeconds(120) });
    const sid = res.storageState.cookies.find((c) => c.name === 'sid').value;
    const files = env.files();
    assert.ok(files.some((f) => f.endsWith('leases/lse_bbbb.enc')) && files.some((f) => f.endsWith('store/trust/fake.enc')));
    for (const f of files) {
      assert.equal(fs.statSync(f).mode & 0o777, 0o600, f);
      const bytes = fs.readFileSync(f);
      for (const needle of [sid, 'device_trust', 'cookies']) assert.equal(bytes.includes(needle), false, `${f} contains ${needle}`);
    }
    const lease = fs.readFileSync(`${env.state}/leases/lse_bbbb.enc`);
    assert.throws(() => new Sealer(Buffer.alloc(32, 7)).open('lease', 'lse_bbbb', lease), (e) => e.code === 'seal_unreadable');
    assert.equal(new Sealer(env.storeKey).open('lease', 'lse_bbbb', lease).site.id, 'fake');

    const logs = h.logs.join('\n');
    for (const secret of [PASSWORD, TOTP_SECRET, sid, 'device_trust']) assert.equal(logs.includes(secret), false, `log leaks ${secret}`);
    await h.ok('session.close', { leaseId: 'lse_bbbb' });
  });

  test('a lease ends by itself at endsAt: server-side logout, lease file shredded', async () => {
    const res = await h.ok('session.open', { leaseId: 'lse_cccc', siteId: 'fake', minutes: 1, endsAt: inSeconds(5) });
    assert.equal(await site.meStatus(res.storageState.cookies), 200);
    for (let i = 0; i < 60 && (await site.meStatus(res.storageState.cookies)) === 200; i += 1) await sleep(250);
    assert.equal(await site.meStatus(res.storageState.cookies), 401);
    await h.helper.idle();
    assert.deepEqual((await h.ok('ping')).leases, []);
    assert.equal(fs.existsSync(`${env.state}/leases/lse_cccc.enc`), false);
    assert.deepEqual(await h.ok('session.close', { leaseId: 'lse_cccc' }), { loggedOut: true });
  });

  test('minutes and site.maxMinutes bound the lease; bad parameters are refused', async () => {
    const res = await h.ok('session.open', { leaseId: 'lse_dddd', siteId: 'fake', minutes: 1, endsAt: inSeconds(3600) });
    const left = Date.parse(res.expiresAt) - Date.now();
    assert.ok(left <= 60_000 && left > 40_000, `lease length ${left} ms must follow minutes`);
    await h.ok('session.close', { leaseId: 'lse_dddd' });
    const bad = async (over) => (await open(h, over)).error?.code;
    assert.equal(await bad({ minutes: 0 }), 'bad_request');
    assert.equal(await bad({ minutes: 481 }), 'bad_request');
    assert.equal(await bad({ endsAt: new Date(Date.now() - 1000).toISOString() }), 'bad_request');
    assert.equal(await bad({ leaseId: '../x' }), 'bad_request');
    assert.equal(await bad({ siteId: 'nope' }), 'not_found');
  });

  test('a lease id is used once, also when two requests race for it', async () => {
    const params = { leaseId: 'lse_dup1', siteId: 'fake', minutes: 5, endsAt: inSeconds(120) };
    const results = await Promise.all([h.call('session.open', params), h.call('session.open', params)]);
    assert.deepEqual(results.map((r) => r.ok).sort(), [false, true]);
    assert.equal(results.find((r) => !r.ok).error.code, 'conflict');
    assert.equal((await h.call('session.open', params)).error.code, 'conflict');
    assert.deepEqual(await h.ok('session.close', { leaseId: 'lse_dup1' }), { loggedOut: true });
    assert.equal((await site.debug()).sessions, 0, 'no stray session from the refused request');
  });
});
