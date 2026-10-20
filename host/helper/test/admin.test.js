// Dispatcher, token auth against a running helper, site.reload, site.forget, CLI entry.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, test } from 'node:test';
import { normalizeConfig } from '../config.js';
import { VAULTD_OPS } from '../helper.js';
import { SKIP_BROWSER, fakeSite, inSeconds, rawCall, scratch, sleep, startFakeSite, startHelper, teardown } from './support.js';

const MAIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../main.js');

describe('running helper', () => {
  let env, h;
  before(async () => {
    env = scratch();
    h = await startHelper(env);
  });
  after(() => teardown(() => h?.stop(), () => env?.cleanup()));

  test('every op refuses a missing or wrong token', async () => {
    for (const op of ['ping', 'session.open', 'session.close', 'site.test', 'challenge.submit', 'session.import', 'site.forget', 'site.reload', 'nonsense']) {
      for (const token of [undefined, 'wrong', env.token.slice(1)]) {
        const res = await rawCall(env.sock, { op, ...(token === undefined ? {} : { token }) });
        assert.equal(res.error?.code, 'unauthorized', `${op} with ${token}`);
      }
    }
    assert.equal((await h.call('ping')).ok, true);
  });

  test('vaultd\'s token may call five ops only; every other op, unknown ones included, needs the admin token', async () => {
    assert.deepEqual([...VAULTD_OPS].sort(), ['ping', 'session.close', 'session.open', 'token.mint', 'token.revoke']);
    const adminOps = [
      'challenge.submit', 'interactive.finish', 'interactive.start', 'oauth.finish', 'oauth.start',
      'session.import', 'site.forget', 'site.reload', 'site.test', 'nonsense', 'constructor', '__proto__',
    ];
    for (const op of adminOps) {
      const res = await rawCall(env.sock, { op, token: env.token });
      assert.deepEqual([op, res.error?.code, res.error?.message], [op, 'unauthorized', 'this operation needs the admin token']);
    }
    for (const op of [...VAULTD_OPS]) {
      assert.notEqual((await rawCall(env.sock, { op, token: env.token })).error?.code, 'unauthorized', op);
    }
    assert.equal((await rawCall(env.sock, { op: 'ping', token: env.adminToken })).ok, true);
    assert.equal((await rawCall(env.sock, { op: 'site.reload', token: env.adminToken })).ok, true);
  });

  test('unknown ops, inherited property names and bad parameters are refused', async () => {
    assert.equal((await h.call('nonsense')).error.code, 'unknown_op');
    assert.equal((await h.call('constructor')).error.code, 'unknown_op');
    assert.equal((await h.call('__proto__')).error.code, 'unknown_op');
    assert.equal((await h.call('session.close', {})).error.code, 'bad_request');
    assert.equal((await h.call('challenge.submit', { handle: 'chl_x', code: 'x'.repeat(65) })).error.code, 'bad_request');
    assert.equal((await h.call('challenge.submit', { handle: 'chl_x', code: '1' })).error.code, 'not_found');
  });

  test('site files with unknown keys are rejected on reload and the site is not served', async () => {
    const site = { origin: 'http://127.0.0.1:9', host: '127.0.0.1:9' };
    env.writeSite(fakeSite(site, { id: 'good' }));
    env.writeSite({ ...fakeSite(site, { id: 'sneaky' }), surprise: true });
    const nested = fakeSite(site, { id: 'nested' });
    nested.recipe.steps[0].run = 'evil()';
    env.writeSite(nested);
    const res = await h.ok('site.reload');
    assert.equal(res.sites, 1);
    assert.deepEqual(res.errors.map((e) => e.file).sort(), ['nested.json', 'sneaky.json']);
    assert.match(res.errors.find((e) => e.file === 'sneaky.json').message, /unknown key "surprise"/);
    assert.match(res.errors.find((e) => e.file === 'nested.json').message, /unknown key "run"/);
    assert.equal((await h.call('site.test', { siteId: 'sneaky' })).error.code, 'not_found');
    assert.equal((await h.call('session.open', { leaseId: 'lse_x', siteId: 'sneaky', minutes: 1, endsAt: inSeconds(60) })).error.code, 'not_found');
  });

  test('site.forget wipes the trust jar, oauth and session stores and the browser profile', async () => {
    const { store } = h.helper.deps;
    for (const kind of ['trust', 'oauth', 'session']) await store.put(kind, 'gone', { n: 1 });
    await store.put('trust', 'kept', { n: 1 });
    const profile = path.join(env.state, 'profiles/gone');
    fs.mkdirSync(path.join(profile, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(profile, 'Default/Cookies'), 'x');
    assert.deepEqual(await h.ok('site.forget', { siteId: 'gone' }), { forgotten: true });
    for (const kind of ['trust', 'oauth', 'session']) assert.equal(await store.get(kind, 'gone'), null);
    assert.equal(fs.existsSync(profile), false);
    assert.deepEqual(await store.get('trust', 'kept'), { n: 1 });
    assert.deepEqual(await h.ok('site.forget', { siteId: 'gone' }), { forgotten: true }, 'idempotent');
  });

  test('extension ops plug into the table', async () => {
    const env2 = scratch();
    const seen = [];
    let h2;
    try {
      h2 = await startHelper(env2, {
        extensions: { ops: { 'token.mint': async (params, deps) => (seen.push(Object.keys(params)), { minted: deps.config.maxBrowsers }) } },
      });
      assert.deepEqual(await h2.ok('token.mint', { leaseId: 'x' }), { minted: 3 });
      assert.deepEqual(seen, [['leaseId']], 'the token never reaches handlers');
    } finally {
      await teardown(() => h2?.stop(), () => env2.cleanup());
    }
  });
});

describe('site.forget with an active lease', { skip: SKIP_BROWSER }, () => {
  test('the lease is logged out first', async () => {
    const env = scratch();
    let site, h;
    try {
      site = await startFakeSite(['--no-challenge']);
      h = await startHelper(env);
      env.writeSite(fakeSite(site));
      env.writeCreds('fake');
      await h.ok('site.reload');
      const res = await h.ok('session.open', { leaseId: 'lse_fgt1', siteId: 'fake', minutes: 5, endsAt: inSeconds(120) });
      await h.ok('site.forget', { siteId: 'fake' });
      assert.equal(await site.meStatus(res.storageState.cookies), 401);
      assert.deepEqual((await h.ok('ping')).leases, []);
      assert.equal(await h.helper.deps.store.get('trust', 'fake'), null);
    } finally {
      await teardown(() => h?.stop(), () => site?.stop(), () => env.cleanup());
    }
  });
});

describe('config', () => {
  test('defaults are the production paths, unknown keys are rejected', () => {
    const c = normalizeConfig({}, { CREDENTIALS_DIRECTORY: '/run/creds' });
    assert.equal(c.socketPath, '/run/vault-helper/helper.sock');
    assert.equal(c.tokenFile, '/etc/vault/helper.token');
    assert.equal(c.adminTokenFile, '/etc/vault/helper-admin.token');
    assert.equal(c.socketGroup, 'vault');
    assert.equal(c.timeouts.openMs, 50_000);
    assert.equal(c.sitesDir, '/etc/vault/sites');
    assert.equal(c.stateDir, '/var/lib/vault-helper');
    assert.equal(c.credentialsDir, '/run/creds');
    assert.equal(c.allowNoSandbox, false);
    assert.equal(c.maxBrowsers, 3);
    assert.throws(() => normalizeConfig({ allowNoSandbox: true, extra: 1 }), /unknown key "extra"/);
    assert.throws(() => normalizeConfig({ allowNoSandbox: 'yes' }), /boolean/);
    assert.throws(() => normalizeConfig({ socketMode: '660' }), /octal/);
    assert.throws(() => normalizeConfig({ timeouts: { nope: 100 } }), /unknown timeouts key/);
  });
});

describe('main.js', () => {
  test('starts from helper.json, serves ping, stops cleanly on SIGTERM; refuses a bad setup', async () => {
    const env = scratch();
    let child, exit;
    try {
      fs.writeFileSync(path.join(env.root, 'token'), `${env.token}\n`);
      fs.writeFileSync(path.join(env.root, 'admin-token'), `${env.adminToken}\n`);
      const cfgFile = path.join(env.root, 'helper.json');
      fs.writeFileSync(cfgFile, JSON.stringify({
        socketPath: env.sock, socketGroup: null, tokenFile: path.join(env.root, 'token'), adminTokenFile: path.join(env.root, 'admin-token'), sitesDir: env.sites, stateDir: env.state,
        credentialsDir: env.creds, allowNoSandbox: true,
      }));
      child = spawn('node', [MAIN, '--config', cfgFile], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, CREDENTIALS_DIRECTORY: '' } });
      exit = new Promise((r) => child.once('exit', (code) => r(code)));
      let err = '';
      child.stderr.on('data', (d) => (err += d));
      for (let i = 0; i < 100 && !fs.existsSync(env.sock); i += 1) await sleep(50);
      const res = await rawCall(env.sock, { op: 'ping', token: env.token });
      assert.equal(res.ok, true);
      assert.equal(res.data.browsers, true);
      child.kill('SIGTERM');
      assert.equal(await exit, 0);
      assert.equal(fs.existsSync(env.sock), false);
      assert.equal(err.includes(env.token) || err.includes(env.adminToken), false);

      // short token
      fs.writeFileSync(path.join(env.root, 'token'), 'short');
      const bad = spawn('node', [MAIN, '--config', cfgFile], { stdio: 'ignore' });
      assert.equal(await new Promise((r) => bad.once('exit', r)), 1);
      // short or missing admin token
      fs.writeFileSync(path.join(env.root, 'token'), `${env.token}\n`);
      fs.writeFileSync(path.join(env.root, 'admin-token'), 'short');
      const badAdmin = spawn('node', [MAIN, '--config', cfgFile], { stdio: 'ignore' });
      assert.equal(await new Promise((r) => badAdmin.once('exit', r)), 1);
      fs.rmSync(path.join(env.root, 'admin-token'));
      const noAdmin = spawn('node', [MAIN, '--config', cfgFile], { stdio: 'ignore' });
      assert.equal(await new Promise((r) => noAdmin.once('exit', r)), 1);
      // missing --config
      const none = spawn('node', [MAIN], { stdio: 'ignore' });
      assert.equal(await new Promise((r) => none.once('exit', r)), 2);
    } finally {
      await teardown(
        async () => {
          if (child?.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); // an assertion failed before SIGTERM
          await exit;
        },
        () => env.cleanup(),
      );
    }
  });
});
