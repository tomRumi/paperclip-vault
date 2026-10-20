// Logout variants and restart recovery, with real Chromium.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { SKIP_BROWSER, fakeSite, inSeconds, scratch, sleep, startFakeSite, startHelper, teardown } from './support.js';

describe('logout variants', { skip: SKIP_BROWSER }, () => {
  let env, site, h;
  before(async () => {
    env = scratch();
    site = await startFakeSite(['--no-challenge']);
    h = await startHelper(env);
  });
  after(() => teardown(() => h?.stop(), () => site?.stop(), () => env?.cleanup()));

  async function loggedOutVia(id, over) {
    env.writeSite(fakeSite(site, { id, ...over }));
    env.writeCreds(id);
    await h.ok('site.reload');
    const leaseId = `lse_${id}`;
    const res = await h.ok('session.open', { leaseId, siteId: id, minutes: 5, endsAt: inSeconds(120) });
    assert.equal(await site.meStatus(res.storageState.cookies), 200);
    const closed = await h.ok('session.close', { leaseId });
    return { closed, status: await site.meStatus(res.storageState.cookies) };
  }

  test('recipe.logout steps', async () => {
    const r = await loggedOutVia('steps', {});
    assert.deepEqual([r.closed.loggedOut, r.status], [true, 401]);
  });

  test('logoutUrl: GET, and POST when the site answers 405', async () => {
    const get = await loggedOutVia('url-get', { logoutUrl: `${site.origin}/logout`, recipe: { logout: null } });
    assert.deepEqual([get.closed.loggedOut, get.status], [true, 401]);
    const post = await loggedOutVia('url-post', { logoutUrl: `${site.origin}/logout-post`, recipe: { logout: null } });
    assert.deepEqual([post.closed.loggedOut, post.status], [true, 401]);
  });

  test('no logout at all: unsupported, the session stays valid on the site, the sealed copy is gone', async () => {
    const r = await loggedOutVia('nologout', { recipe: { logout: null } });
    assert.deepEqual([r.closed.loggedOut, r.status], ['unsupported', 200]);
    assert.equal(fs.existsSync(`${env.state}/leases/lse_nologout.enc`), false);
  });

  test('a logout that cannot work reports false and still shreds the lease', async () => {
    const r = await loggedOutVia('badlogout', { recipe: { logout: { steps: [{ click: '#no-such-button' }] } } });
    assert.deepEqual([r.closed.loggedOut, r.status], [false, 200]);
    assert.equal(fs.existsSync(`${env.state}/leases/lse_badlogout.enc`), false);
  });
});

describe('restart recovery', { skip: SKIP_BROWSER }, () => {
  test('sealed leases survive a restart: past ones are logged out, running ones resume, junk is dropped', async () => {
    const env = scratch();
    let site, a, b;
    try {
      site = await startFakeSite(['--no-challenge']);
      env.writeSite(fakeSite(site));
      env.writeCreds('fake');
      a = await startHelper(env);
      const short = await a.ok('session.open', { leaseId: 'lse_short', siteId: 'fake', minutes: 1, endsAt: inSeconds(8) });
      const long = await a.ok('session.open', { leaseId: 'lse_long', siteId: 'fake', minutes: 5, endsAt: inSeconds(600) });
      assert.equal((await site.debug()).sessions, 2);
      // helper goes away without logging anyone out (a crash or a service restart)
      await a.stop();
      assert.equal((await site.debug()).sessions, 2, 'stopping the helper does not end leases');
      assert.deepEqual(fs.readdirSync(`${env.state}/leases`).sort(), ['lse_long.enc', 'lse_short.enc']);
      // the site file is edited away meanwhile: logout must not depend on it
      fs.rmSync(path.join(env.sites, 'fake.json'));
      fs.writeFileSync(`${env.state}/leases/lse_junk.enc`, 'not a sealed file');
      while (Date.now() < Date.parse(short.expiresAt) + 200) await sleep(100);

      b = await startHelper(env);
      await b.helper.idle();
      assert.equal(await site.meStatus(short.storageState.cookies), 401, 'expired lease was logged out on start');
      assert.equal(await site.meStatus(long.storageState.cookies), 200, 'running lease is untouched');
      assert.deepEqual(fs.readdirSync(`${env.state}/leases`), ['lse_long.enc']);
      assert.deepEqual((await b.ok('ping')).leases, [{ leaseId: 'lse_long', siteId: 'fake', endsAt: long.expiresAt }]);
      assert.ok(b.logs.some((l) => l.includes('dropping unreadable sealed lease') && l.includes('lse_junk')));
      assert.deepEqual(await b.ok('session.close', { leaseId: 'lse_short' }), { loggedOut: true });
      // the resumed lease is closed with its sealed snapshot of the site, though the site file is gone
      assert.deepEqual(await b.ok('session.close', { leaseId: 'lse_long' }), { loggedOut: true });
      assert.equal(await site.meStatus(long.storageState.cookies), 401);
    } finally {
      await teardown(() => a?.stop(), () => b?.stop(), () => site?.stop(), () => env.cleanup());
    }
  });
});
