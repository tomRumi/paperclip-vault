// Interactive one-time login with a real Xvfb and headed Chromium; x11vnc is
// replaced by test/fixtures/vnc-stub.mjs (VAULT_VNC_CMD). The "owner" is the
// test driving the headed browser's page. Heavy: run under the shared lock.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, test } from 'node:test';
import { vncAuthFile, xauthFile } from '../interactive.js';
import { Sealer } from '../seal.js';
import { freshCode, base32Decode } from '../totp.js';
import {
  PASSWORD, SKIP_BROWSER, TOTP_SECRET, USER, descendants, eventually, fakeSite, inSeconds, scratch, startFakeSite, startHelper, teardown,
} from './support.js';

const MINUTE_MS = 4000; // 15 "minutes" = 60 s: long enough for the login tests, 2 "minutes" = 8 s for the timeout test
const STUB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures/vnc-stub.mjs');

/** PIDs of this process's descendants whose command line contains `text` (the Xvfb, Chromium and VNC stub the helper started). */
const pgrep = (text) => descendants().filter((p) => p.cmd.includes(text)).map((p) => String(p.pid));

/** The same, direct children only. */
const ownChildren = (text) => descendants().filter((p) => p.ppid === process.pid && p.cmd.includes(text)).map((p) => String(p.pid));

const portOpen = (port) =>
  new Promise((resolve) => {
    // the stub ignores connections; x11vnc -once would not: only ever used on the stub
    const s = net.connect(port, '127.0.0.1');
    s.once('connect', () => {
      s.destroy();
      resolve(true);
    });
    s.once('error', () => resolve(false));
  });

/** First byte of the X server's answer to a connection setup (0 failed, 1 success), with MIT-MAGIC-COOKIE-1 `cookie` or none. */
function x11Reply(display, cookie) {
  const pad = (b) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);
  const name = Buffer.from(cookie ? 'MIT-MAGIC-COOKIE-1' : '');
  const head = Buffer.alloc(12);
  head.write('l', 0);
  head.writeUInt16LE(11, 2);
  head.writeUInt16LE(0, 4);
  head.writeUInt16LE(name.length, 6);
  head.writeUInt16LE(cookie?.length ?? 0, 8);
  return new Promise((resolve, reject) => {
    const s = net.connect(`/tmp/.X11-unix/X${display.slice(1)}`, () => s.write(Buffer.concat([head, pad(name), pad(cookie ?? Buffer.alloc(0))])));
    s.once('data', (d) => {
      s.destroy();
      resolve(d[0]);
    });
    s.once('error', reject);
  });
}

describe('vncAuthFile', () => {
  test('is the VNC password file format: "password" encrypts to dbd83cfd727a1458, padded and truncated to 8 bytes', () => {
    assert.equal(vncAuthFile('password').toString('hex'), 'dbd83cfd727a1458');
    assert.equal(vncAuthFile('passwordEXTRA').toString('hex'), 'dbd83cfd727a1458');
    assert.equal(vncAuthFile('abc').length, 8);
    assert.notEqual(vncAuthFile('abc').toString('hex'), vncAuthFile('abd').toString('hex'));
  });
});

describe('xauthFile', () => {
  test('is one libXau entry: local family, host name, display number, MIT-MAGIC-COOKIE-1 and the cookie, big-endian lengths', () => {
    const cookie = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    assert.equal(
      xauthFile(99, cookie, 'box').toString('hex'),
      `0100${'0003'}${Buffer.from('box').toString('hex')}${'0002'}${Buffer.from('99').toString('hex')}${'0012'}${Buffer.from('MIT-MAGIC-COOKIE-1').toString('hex')}${'0010'}${cookie.toString('hex')}`,
    );
  });
});

describe('interactive login', { skip: SKIP_BROWSER }, () => {
  let env, site, h, stubLog, profile, firstCookie;
  const started = [];
  const interactiveSite = (over = {}) => {
    // loginUrl is where the browser starts and where session.open looks for the logged-in state: "/" lands on
    // /dashboard with a session and on /login without.
    const s = fakeSite(site, { id: 'inter', type: 'interactive', acceptNoLogout: true, loginUrl: `${site.origin}/`, ...over });
    s.recipe.logout = null;
    s.recipe.steps = [];
    delete s.recipe.challenge;
    return s;
  };
  const stubRuns = () => (fs.existsSync(stubLog) ? fs.readFileSync(stubLog, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);

  before(async () => {
    env = scratch();
    site = await startFakeSite(['--no-challenge']);
    stubLog = path.join(env.root, 'vnc.log');
    profile = `${env.state}/profiles/inter`;
    h = await startHelper(env, {
      extensions: {
        env: { ...process.env, VAULT_VNC_CMD: STUB, VNC_STUB_LOG: stubLog },
        interactive: { minuteMs: MINUTE_MS }, // the hard timeout counts minutes of this length
      },
    });
    env.writeSite(interactiveSite());
    env.writeSite(fakeSite(site, { id: 'pw' }));
    await h.ok('site.reload');
  });

  after(() => teardown(() => h?.stop(), () => site?.stop(), () => env?.cleanup()));

  const gone = async (display, vncPort) => {
    await eventually(() => pgrep(`Xvfb ${display}`).length === 0, `Xvfb ${display} to exit`);
    await eventually(() => pgrep(`--user-data-dir=${profile}`).length === 0, 'Chromium to exit');
    if (vncPort) await eventually(async () => !(await portOpen(vncPort)), 'the VNC stub to exit');
    await eventually(() => !fs.existsSync(`${env.root}/vnc.pw`), 'the one-time password file to be removed');
    await eventually(() => !fs.existsSync(`${env.root}/vnc.xauth`), 'the X cookie file to be removed');
    assert.equal(h.helper.deps.interactive.isActive(), false);
  };

  /** What the owner does in the VNC window. */
  async function ownerLogsIn() {
    const page = h.helper.deps.interactive.activeContext().pages()[0];
    await page.fill('#email', USER);
    await page.click('#next');
    await page.fill('#password', PASSWORD);
    await page.click('#login');
    await page.fill('#otp', await freshCode(base32Decode(TOTP_SECRET)));
    await page.click('#verify');
    await page.waitForSelector('#avatar');
  }

  test('start: Xvfb on a free display, headed Chromium on the profile, VNC bound to localhost with a one-time password', async () => {
    const res = await h.ok('interactive.start', { siteId: 'inter', minutes: 15 });
    started.push(res);
    assert.match(res.display, /^:\d+$/);
    assert.ok(res.vncPort >= 5900 && res.vncPort <= 5999);
    assert.match(res.vncPassword, /^[a-zA-Z2-9]{8}$/);
    assert.ok(Math.abs(Date.parse(res.expiresAt) - (Date.now() + 15 * MINUTE_MS)) < 3000, 'expiresAt follows the (shortened) minute');

    const xvfb = pgrep(`Xvfb ${res.display}`);
    assert.equal(xvfb.length, 1);
    // Xvfb is not reachable over TCP nor over the abstract socket any local user could attach to, and wants a cookie
    const xauth = `${env.root}/vnc.xauth`;
    const argv = descendants().find((p) => String(p.pid) === xvfb[0]).cmd;
    assert.match(argv, / -nolisten tcp /);
    assert.match(argv, / -nolisten local /);
    assert.ok(argv.includes(` -auth ${xauth} `), argv);
    assert.equal(fs.readFileSync('/proc/net/unix', 'utf8').includes(`@/tmp/.X11-unix/X${res.display.slice(1)}`), false, 'no abstract X11 socket');
    assert.equal(fs.statSync(xauth).mode & 0o777, 0o600);
    const entry = fs.readFileSync(xauth);
    firstCookie = entry.subarray(-16);
    assert.deepEqual(entry, xauthFile(res.display.slice(1), firstCookie), 'the file is one MIT-MAGIC-COOKIE-1 entry for this display');
    assert.notDeepEqual(firstCookie, Buffer.alloc(16));
    // the X server: refuses a client without the cookie, accepts one with it (Chromium needs it to open its window)
    assert.equal(await x11Reply(res.display, null), 0, 'refused without a cookie');
    assert.equal(await x11Reply(res.display, Buffer.alloc(16)), 0, 'refused with a wrong cookie');
    assert.equal(await x11Reply(res.display, firstCookie), 1, 'accepted with the cookie');
    assert.ok(pgrep(`--user-data-dir=${profile}`).length > 0, 'Chromium runs on profiles/<id>');
    assert.equal(fs.statSync(profile).mode & 0o777, 0o700);

    const [run] = stubRuns();
    const arg = (n) => run.args[run.args.indexOf(n) + 1];
    assert.equal(arg('-display'), res.display);
    assert.ok(run.args.includes('-localhost'));
    assert.ok(run.args.includes('-once'));
    assert.equal(arg('-rfbport'), String(res.vncPort));
    assert.equal(arg('-timeout'), '900');
    assert.equal(arg('-rfbauth'), `${env.root}/vnc.pw`);
    assert.equal(arg('-auth'), xauth, 'x11vnc gets the cookie file');
    assert.equal(run.pwMode, 0o600);
    assert.equal(run.pwHex, vncAuthFile(res.vncPassword).toString('hex'), 'the file holds the password that was handed out');
    assert.equal(await portOpen(res.vncPort), true);
    const logs = h.logs.join('\n');
    assert.equal(logs.includes(res.vncPassword), false, 'the VNC password is not logged');
    assert.equal(logs.includes(run.pwHex), false);

    // the browser reached the login page
    const page = h.helper.deps.interactive.activeContext().pages()[0];
    assert.match(page.url(), new RegExp(`^${site.origin}/login`));
  });

  test('while it runs: a second start, another site, session.open and site.test of the same site are refused', async () => {
    assert.equal((await h.call('interactive.start', { siteId: 'inter', minutes: 5 })).error.code, 'conflict');
    env.writeSite({ ...interactiveSite(), id: 'inter2' });
    await h.ok('site.reload');
    assert.equal((await h.call('interactive.start', { siteId: 'inter2', minutes: 5 })).error.code, 'conflict');
    const open = await h.call('session.open', { leaseId: 'lse_busy', siteId: 'inter', minutes: 5, endsAt: inSeconds(60) });
    assert.equal(open.error.code, 'conflict');
    assert.equal((await h.call('site.test', { siteId: 'inter' })).error.code, 'conflict');
  });

  test('finish before the owner is logged in: login_failed, the session stays up for another try', async () => {
    const res = await h.call('interactive.finish', { siteId: 'inter' });
    assert.equal(res.error.code, 'login_failed');
    assert.equal(h.helper.deps.interactive.isActive(), true);
    assert.equal(fs.existsSync(`${env.state}/store/session/inter.enc`), false);
  });

  test('the VNC server ends with its client: start again gives a new VNC password for the same browser', async () => {
    const first = started[0];
    process.kill(stubRuns()[0].pid, 'SIGTERM');
    await eventually(async () => !(await portOpen(first.vncPort)), 'the first VNC stub to exit');
    const again = await h.ok('interactive.start', { siteId: 'inter', minutes: 15 });
    assert.equal(again.display, first.display);
    assert.notEqual(again.vncPassword, first.vncPassword);
    assert.equal(stubRuns().length, 2);
    assert.equal(await portOpen(again.vncPort), true);
    started[0] = again;
  });

  test('finish after the owner logged in: success check verified, storageState sealed, everything stopped', async () => {
    await ownerLogsIn();
    const { display, vncPort } = started[0];
    const done = await h.ok('interactive.finish', { siteId: 'inter' });
    assert.equal(done.sealed, true);
    assert.ok(done.cookies >= 1);

    const file = `${env.state}/store/session/inter.enc`;
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const sealed = new Sealer(env.storeKey).open('session', 'inter', fs.readFileSync(file));
    const sid = sealed.cookies.find((c) => c.name === 'sid');
    assert.ok(sid);
    assert.equal(fs.readFileSync(file).includes(sid.value), false);
    assert.equal(await site.meStatus(sealed.cookies), 200);
    await gone(display, vncPort);
    assert.equal((await h.call('interactive.finish', { siteId: 'inter' })).error.code, 'not_found');
  });

  test('session.open re-opens the profile headless and hands out a copy; the lease end cannot log out (unsupported)', async () => {
    const endsAt = inSeconds(120);
    const res = await h.ok('session.open', { leaseId: 'lse_int1', siteId: 'inter', minutes: 5, endsAt });
    assert.equal(await site.meStatus(res.storageState.cookies), 200);
    assert.equal(res.storageState.cookies.find((c) => c.name === 'sid').expires, Math.floor(Date.parse(endsAt) / 1000));
    assert.deepEqual(await h.ok('session.close', { leaseId: 'lse_int1' }), { loggedOut: 'unsupported' });
    assert.equal(await site.meStatus(res.storageState.cookies), 200, 'the owner\'s login is untouched');
    assert.equal(pgrep(`--user-data-dir=${profile}`).length, 0);
    assert.deepEqual(await h.ok('site.test', { siteId: 'inter' }), { state: 'ok', trustUsed: false, loggedOut: 'unsupported' });
  });

  test('a session the site no longer accepts is needs_interactive', async () => {
    const sealed = await h.helper.deps.store.get('session', 'inter');
    const header = sealed.cookies.map((c) => `${c.name}=${c.value}`).join('; ');
    await fetch(`${site.origin}/logout`, { headers: { Cookie: header }, redirect: 'manual' });
    const res = await h.call('session.open', { leaseId: 'lse_int2', siteId: 'inter', minutes: 5, endsAt: inSeconds(60) });
    assert.equal(res.error.code, 'needs_interactive');
    assert.equal(h.helper.deps.leases.list().length, 0);
  });

  test('no stored session: needs_interactive; ping says so', async () => {
    env.writeSite({ ...interactiveSite(), id: 'fresh' });
    await h.ok('site.reload');
    const res = await h.call('session.open', { leaseId: 'lse_int3', siteId: 'fresh', minutes: 5, endsAt: inSeconds(60) });
    assert.equal(res.error.code, 'needs_interactive');
    const ping = await h.ok('ping');
    assert.equal(ping.sites.find((s) => s.siteId === 'fresh').state, 'needs_interactive');
  });

  test('the hard timeout stops everything: Xvfb, Chromium, VNC, password file', async () => {
    const res = await h.ok('interactive.start', { siteId: 'inter', minutes: 2 });
    assert.equal(h.helper.deps.interactive.isActive(), true);
    await gone(res.display, res.vncPort);
    assert.equal((await h.call('interactive.finish', { siteId: 'inter' })).error.code, 'not_found');
    // and the next login can start
    const next = await h.ok('interactive.start', { siteId: 'inter', minutes: 15 });
    assert.notDeepEqual(fs.readFileSync(`${env.root}/vnc.xauth`).subarray(-16), firstCookie, 'every session gets a fresh cookie');
    await ownerLogsIn();
    await h.ok('interactive.finish', { siteId: 'inter' });
    await gone(next.display, next.vncPort);
  });

  test('the owner closing the browser ends the login', async () => {
    const res = await h.ok('interactive.start', { siteId: 'inter', minutes: 15 });
    await h.helper.deps.interactive.activeContext().close();
    await gone(res.display, res.vncPort);
  });

  test('x11vnc missing: dependency_missing, and nothing stays running', async () => {
    const env2 = scratch();
    let h2;
    try {
      h2 = await startHelper(env2, { extensions: { env: { ...process.env, VAULT_VNC_CMD: '/nonexistent/x11vnc' } } });
      env2.writeSite(interactiveSite());
      await h2.ok('site.reload');
      const res = await h2.call('interactive.start', { siteId: 'inter', minutes: 5 });
      assert.equal(res.error.code, 'dependency_missing');
      assert.match(res.error.message, /x11vnc is not installed/);
      await eventually(() => pgrep(`--user-data-dir=${env2.state}/profiles/inter`).length === 0, 'Chromium to exit');
      await eventually(() => ownChildren('Xvfb :').length === 0, 'Xvfb to exit');
      assert.equal(h2.helper.deps.interactive.isActive(), false);
    } finally {
      await teardown(() => h2?.stop(), () => env2.cleanup());
    }
  });

  test('a VNC server that listens beyond localhost is refused and stopped', async () => {
    const env4 = scratch();
    let h4;
    try {
      h4 = await startHelper(env4, { extensions: { env: { ...process.env, VAULT_VNC_CMD: STUB, VNC_STUB_LOG: path.join(env4.root, 'v.log'), VNC_STUB_HOST: '0.0.0.0' } } });
      env4.writeSite(interactiveSite());
      await h4.ok('site.reload');
      const res = await h4.call('interactive.start', { siteId: 'inter', minutes: 5 });
      assert.equal(res.error.code, 'browser_unavailable');
      assert.match(res.error.message, /beyond localhost/);
      await eventually(() => ownChildren('Xvfb :').length === 0, 'Xvfb to exit');
      await eventually(() => pgrep(`--user-data-dir=${env4.state}/profiles/inter`).length === 0, 'Chromium to exit');
    } finally {
      await teardown(() => h4?.stop(), () => env4.cleanup());
    }
  });

  test('parameters: minutes at most 15, interactive sites only', async () => {
    assert.equal((await h.call('interactive.start', { siteId: 'inter', minutes: 16 })).error.code, 'bad_request');
    assert.equal((await h.call('interactive.start', { siteId: 'inter' })).error.code, 'bad_request');
    assert.equal((await h.call('interactive.start', { siteId: 'pw', minutes: 5 })).error.code, 'bad_request');
    assert.equal((await h.call('interactive.start', { siteId: 'ghost', minutes: 5 })).error.code, 'not_found');
  });

  test('two starts at once: exactly one runs, the other is a conflict, whichever site it is for', async () => {
    const env5 = scratch();
    let h5;
    try {
      h5 = await startHelper(env5, { extensions: { env: { ...process.env, VAULT_VNC_CMD: STUB, VNC_STUB_LOG: path.join(env5.root, 'v.log') } } });
      env5.writeSite(interactiveSite());
      env5.writeSite({ ...interactiveSite(), id: 'inter2' });
      await h5.ok('site.reload');
      for (const [a, b] of [['inter', 'inter'], ['inter', 'inter2']]) {
        const results = await Promise.all([a, b].map((siteId) => h5.call('interactive.start', { siteId, minutes: 5 })));
        assert.deepEqual(results.map((r) => r.ok ?? false).sort(), [false, true], JSON.stringify(results));
        assert.equal(results.find((r) => !r.ok).error.code, 'conflict');
        assert.equal(ownChildren('Xvfb :').length, 1, 'one Xvfb');
        await h5.helper.deps.interactive.shutdown();
        await eventually(() => ownChildren('Xvfb :').length === 0, 'Xvfb to exit');
      }
    } finally {
      await teardown(() => h5?.stop(), () => env5.cleanup());
    }
  });

  test('helper stop tears a running login down', async () => {
    const env3 = scratch();
    let h3;
    try {
      h3 = await startHelper(env3, { extensions: { env: { ...process.env, VAULT_VNC_CMD: STUB, VNC_STUB_LOG: path.join(env3.root, 'v.log') } } });
      env3.writeSite(interactiveSite());
      await h3.ok('site.reload');
      const res = await h3.ok('interactive.start', { siteId: 'inter', minutes: 15 });
      await h3.stop();
      await eventually(() => pgrep(`Xvfb ${res.display}`).length === 0, 'Xvfb to exit');
      await eventually(() => pgrep(`--user-data-dir=${env3.state}/profiles/inter`).length === 0, 'Chromium to exit');
      await eventually(async () => !(await portOpen(res.vncPort)), 'the VNC stub to exit');
    } finally {
      await teardown(() => h3?.stop(), () => env3.cleanup());
    }
  });
});
