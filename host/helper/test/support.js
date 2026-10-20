// Test harness: scratch dirs, the fake site subprocess, an in-process helper
// and a socket client. Everything lives under one mkdtemp in /tmp (short
// paths: AF_UNIX limit) and is removed by env.cleanup().
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeConfig } from '../config.js';
import { VAULTD_OPS, createHelper } from '../helper.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FAKE_SITE = path.resolve(HERE, '../../../tests/fakes/fake_site.py');
export const FAKE_OAUTH = path.resolve(HERE, '../../../tests/fakes/fake_oauth.py');
export const SKIP_BROWSER = process.env.SKIP_BROWSER === '1' ? 'SKIP_BROWSER=1' : false;

export const USER = 'tester@example.test';
export const PASSWORD = 'correct horse battery';
export const TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
export const SMS_CODE = '424242';
export const OTHER_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

export const FAST = { stepMs: 10_000, optionalMs: 1500, successMs: 8000, pollMs: 100, openMs: 240_000 };

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Poll `fn` until it returns truthy; fails with `what` after `ms`.
 * For things only observable from outside (a process gone, a port closed).
 */
export async function eventually(fn, what, ms = 15_000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await fn()) return;
    await sleep(50);
  }
  assert.fail(`timed out waiting for ${what}`);
}

/**
 * Run every teardown step, each one even if an earlier one threw (a step may
 * be undefined: the `before` that should have created it failed). The first
 * error, or an AggregateError for several, is rethrown after all have run.
 */
export async function teardown(...steps) {
  const errors = [];
  for (const step of steps) {
    try {
      await step?.();
    } catch (err) {
      errors.push(err);
    }
  }
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1) throw new AggregateError(errors, `${errors.length} teardown steps failed`);
}

/** Live (not zombie) processes whose parent chain leads to this process: [{ pid, ppid, cmd }]. Read from /proc, no pattern matching. */
export function descendants() {
  const children = new Map(); // ppid -> [{ pid, ppid, cmd }]
  for (const name of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = fs.readFileSync(`/proc/${name}/stat`, 'utf8');
      const [state, ppid] = stat.slice(stat.lastIndexOf(')') + 2).split(' '); // after "pid (comm) "
      if (state === 'Z') continue;
      const cmd = fs.readFileSync(`/proc/${name}/cmdline`, 'utf8').replaceAll('\0', ' ').trim() || stat.slice(stat.indexOf('(') + 1, stat.lastIndexOf(')'));
      const entry = { pid: Number(name), ppid: Number(ppid), cmd };
      children.set(entry.ppid, [...(children.get(entry.ppid) ?? []), entry]);
    } catch {
      // gone while we looked
    }
  }
  const found = [];
  const queue = [process.pid];
  while (queue.length > 0) {
    for (const child of children.get(queue.shift()) ?? []) {
      found.push(child);
      queue.push(child.pid);
    }
  }
  return found;
}

/** Resolves when none of `pids` is a live descendant any more; fails after `ms`. */
export async function waitForExit(pids, what, ms = 15_000) {
  await eventually(() => {
    const live = new Set(descendants().map((p) => p.pid));
    return pids.every((pid) => !live.has(pid));
  }, `${what} to exit`, ms);
}

export function scratch() {
  const root = fs.mkdtempSync('/tmp/pvh-');
  const dirs = {
    root,
    creds: path.join(root, 'c'),
    state: path.join(root, 's'),
    sites: path.join(root, 'sites'),
    sock: path.join(root, 'h.sock'),
  };
  for (const d of [dirs.creds, dirs.state, dirs.sites]) fs.mkdirSync(d, { mode: 0o700 });
  const storeKey = randomBytes(32);
  fs.writeFileSync(path.join(dirs.creds, 'vault-helper.storekey'), storeKey);
  const token = randomBytes(32).toString('base64');
  const adminToken = randomBytes(32).toString('base64');
  return {
    ...dirs,
    storeKey,
    token,
    adminToken,
    writeSite(site) {
      fs.writeFileSync(path.join(dirs.sites, `${site.id}.json`), JSON.stringify(site));
    },
    writeCreds(siteId, { username = USER, password = PASSWORD, totp = TOTP_SECRET } = {}) {
      const set = (part, value) => {
        const file = path.join(dirs.creds, `vault-helper.site.${siteId}.${part}`);
        if (value === null) fs.rmSync(file, { force: true });
        else fs.writeFileSync(file, value);
      };
      set('username', username);
      set('password', password);
      set('totp', totp);
    },
    files() {
      const out = [];
      const walk = (d) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) walk(p);
          else out.push(p);
        }
      };
      walk(dirs.state);
      return out;
    },
    cleanup() {
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

export async function startFakeSite(args = []) {
  return startFake(FAKE_SITE, args);
}

/** The fake OAuth provider; `debug()` returns what it saw, `get(path, headers)` calls it as a client. */
export async function startFakeOauth(args = []) {
  const fake = await startFake(FAKE_OAUTH, args);
  return {
    ...fake,
    get: (p, headers = {}) => fetch(`${fake.origin}${p}`, { headers, redirect: 'manual' }),
    /** Status of the protected resource for an access token. */
    resource: async (accessToken) => (await fetch(`${fake.origin}/api/me`, { headers: { Authorization: `Bearer ${accessToken}` } })).status,
  };
}

/** An oauth site file pointing at a fake provider. */
export function oauthSite(provider, over = {}) {
  const { oauth: oauthOver, ...rest } = over;
  return {
    schema: 1,
    id: 'drive',
    displayName: 'Drive',
    type: 'oauth',
    kind: 'owner',
    purpose: 'read the shared drive',
    loginUrl: null,
    logoutUrl: null,
    allowedHosts: [provider.host],
    allowedAgents: [],
    roles: [],
    maxMinutes: 60,
    recipe: null,
    oauth: {
      flow: 'device',
      authUrl: `${provider.origin}/authorize`,
      tokenUrl: `${provider.origin}/token`,
      deviceUrl: `${provider.origin}/device`,
      revokeUrl: `${provider.origin}/revoke`,
      clientId: 'client-1',
      scopes: ['drive.read', 'drive.meta'],
      accessTtlMaxMinutes: 45,
      ...oauthOver,
    },
    ...rest,
  };
}

async function startFake(script, args) {
  const child = spawn('python3', ['-I', '-B', script, ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  const exited = new Promise((resolve) => child.once('exit', resolve));
  let port;
  try {
    port = await new Promise((resolve, reject) => {
      let buf = '';
      child.stdout.on('data', (d) => {
        buf += d;
        const nl = buf.indexOf('\n');
        if (nl >= 0) resolve(JSON.parse(buf.slice(0, nl)).port);
      });
      child.once('exit', () => reject(new Error('fake server exited early')));
    });
  } catch (err) {
    child.kill('SIGKILL');
    await exited;
    throw err;
  }
  const origin = `http://127.0.0.1:${port}`;
  return {
    port,
    origin,
    host: `127.0.0.1:${port}`,
    /** Kill the server and resolve when it has exited. */
    stop: () => {
      child.kill('SIGKILL');
      return exited;
    },
    debug: async () => (await fetch(`${origin}/_debug`)).json(),
    /** Status of /api/me for a cookie list as returned in a storageState. */
    meStatus: async (cookies) => {
      const header = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
      return (await fetch(`${origin}/api/me`, { headers: { Cookie: header } })).status;
    },
  };
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** A site file for the fake site; `over` replaces top-level keys, `recipe` is merged. */
export function fakeSite(site, over = {}) {
  const { recipe: recipeOver, ...rest } = over;
  return {
    schema: 1,
    id: 'fake',
    displayName: 'Fake site',
    type: 'password-totp',
    kind: 'test',
    purpose: 'test site',
    loginUrl: `${site.origin}/login`,
    logoutUrl: null,
    allowedHosts: [site.host],
    allowedAgents: [],
    roles: ['QA'],
    maxMinutes: 60,
    recipe: recipeOver === null ? null : {
      steps: [
        { fill: '#email', from: 'username' },
        { click: '#next' },
        { fill: '#password', from: 'password' },
        { click: '#login' },
        { fill: '#otp', from: 'totp', optional: true },
        { click: '#verify', optional: true },
      ],
      successCheck: { urlMatches: `^${escapeRe(site.origin)}/dashboard`, selector: '#avatar' },
      logout: { steps: [{ click: '#logout' }] },
      challenge: { codeSelector: '#code', submit: '#go' },
      trustCookies: ['^device_'],
      timeoutSeconds: 30,
      ...recipeOver,
    },
    oauth: null,
    ...rest,
  };
}

/** Send one request line, read the one response line. */
export function rawCall(sockPath, body) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    s.on('data', (d) => (buf += d));
    s.on('end', () => {
      try {
        resolve(JSON.parse(buf));
      } catch (err) {
        reject(err);
      }
    });
    s.on('error', reject);
    s.write(typeof body === 'string' ? body : `${JSON.stringify(body)}\n`);
  });
}

/**
 * Start an in-process helper on the scratch dirs. `logs` collects every log
 * line (tests assert no secret appears in them).
 */
export async function startHelper(env, { config = {}, extensions = {} } = {}) {
  const logs = [];
  const log = (level, msg, fields = {}) => logs.push(JSON.stringify({ level, msg, ...fields }));
  const cfg = normalizeConfig(
    {
      socketPath: env.sock,
      sitesDir: env.sites,
      stateDir: env.state,
      credentialsDir: env.creds,
      tokenFile: path.join(env.root, 'token'),
      allowNoSandbox: true,
      socketGroup: null,
      timeouts: FAST,
      logoutRetryMs: [0, 200],
      ...config,
    },
    {},
  );
  const helper = createHelper({ config: cfg, token: env.token, adminToken: env.adminToken, storeKey: env.storeKey }, { log, ...extensions });
  await helper.start();
  /** Admin ops go with the admin token, the others with vaultd's. */
  const call = async (op, params = {}) => rawCall(env.sock, { op, token: VAULTD_OPS.has(op) ? env.token : env.adminToken, ...params });
  /** call() that throws unless ok, returning data. */
  const ok = async (op, params) => {
    const res = await call(op, params);
    if (!res.ok) throw new Error(`${op} failed: ${res.error.code} ${res.error.message}`);
    return res.data;
  };
  return { helper, call, ok, logs, stop: () => helper.stop() };
}

export function inSeconds(s) {
  return new Date(Date.now() + s * 1000).toISOString();
}

let leaseCounter = 0;
export function open(h, over = {}) {
  leaseCounter += 1;
  return h.call('session.open', {
    leaseId: `lse_${String(leaseCounter).padStart(4, '0')}`,
    siteId: 'fake',
    minutes: 5,
    endsAt: inSeconds(300),
    ...over,
  });
}
