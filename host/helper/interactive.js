// Interactive sites (those that block automation, e.g. Google): the owner logs
// in once by hand, the session is sealed, and agents later get copies of it.
//
//   interactive.start  { siteId, minutes<=15 } -> { display, vncPort, vncPassword, expiresAt }
//     Xvfb :<free> -nolisten tcp -nolisten local -auth <cookie file>, headed
//     Chromium on profiles/<id>, and x11vnc -localhost (127.0.0.1 only, one
//     client, one-time password). The password and the VNC port go to the root
//     CLI only. Xvfb listens on the filesystem socket only (the abstract one
//     would be open to every local user, PrivateTmp does not hide it) and wants
//     a fresh MIT-MAGIC-COOKIE-1 per session, held in an Xauthority file (0600)
//     that Xvfb, x11vnc and Chromium (XAUTHORITY) get.
//   interactive.finish { siteId } -> { sealed: true, cookies }
//     verifies recipe.successCheck in the browser, seals the exported
//     storageState in store/session/<id>.enc, stops everything.
//
// Everything is torn down at the hard timeout, when the owner closes the
// browser, or when Xvfb dies. One interactive login at a time.
//
// The login strategy for `session.open` on an interactive site (headless
// re-open of the profile, success check, refreshed copy) lives here too.
//
// VNC_CMD: the x11vnc binary can be replaced through the environment variable
// VAULT_VNC_CMD (the helper passes the same arguments); the tests use that.
import { createCipheriv, randomBytes, randomInt } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { CONTEXT_OPTIONS, installGuard } from './browser.js';
import { HelperError, bad } from './errors.js';
import { ID_RE, needInt, needString } from './params.js';
import { awaitOutcome, Deadline, successHolds } from './recipe.js';
import { cookieAllowed, urlAllowed } from './sites.js';

const FIRST_DISPLAY = 99;
const DISPLAY_TRIES = 8;
const VNC_PORTS = [5900, 5999];
const START_WAIT_MS = 8_000;
const KILL_GRACE_MS = 2_000;
const MAX_MINUTES = 15;
const SCREEN = '1280x800x24';
// Password characters without look-alikes. VNC authentication uses 8.
const PASSWORD_CHARS = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

// The fixed DES key of the VNC password file format (bit-reversed per byte, as VNC does).
const VNC_FILE_KEY = Buffer.from([23, 82, 107, 6, 35, 78, 88, 7].map((b) => parseInt(b.toString(2).padStart(8, '0').split('').reverse().join(''), 2)));

// The VNC password file and the Xauthority file are written directly (not via vncpasswd/xauth) so no secret is ever in an argv.
/**
 * The content of an x11vnc `-rfbauth` file: the password, zero padded to 8
 * bytes, DES-encrypted with the fixed VNC key. Node's DES is only reachable as
 * 3DES-EDE with three identical keys, which is single DES.
 */
export function vncAuthFile(password) {
  const cipher = createCipheriv('des-ede3-ecb', Buffer.concat([VNC_FILE_KEY, VNC_FILE_KEY, VNC_FILE_KEY]), null);
  cipher.setAutoPadding(false);
  const plain = Buffer.alloc(8);
  plain.write(password.slice(0, 8), 'latin1');
  return Buffer.concat([cipher.update(plain), cipher.final()]);
}

/**
 * An Xauthority file with one entry: the MIT-MAGIC-COOKIE-1 `cookie` for
 * local connections to display `n`. Entry layout (libXau): family (u16), then
 * address, display number, auth name and auth data, each as u16 length +
 * bytes; all numbers big-endian. Family 256 is "local" (address: host name).
 */
export function xauthFile(n, cookie, hostname = os.hostname()) {
  const field = (data) => {
    const bytes = Buffer.from(data);
    const len = Buffer.alloc(2);
    len.writeUInt16BE(bytes.length);
    return Buffer.concat([len, bytes]);
  };
  const family = Buffer.alloc(2);
  family.writeUInt16BE(256);
  return Buffer.concat([family, field(hostname), field(String(n)), field('MIT-MAGIC-COOKIE-1'), field(cookie)]);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** The part of a storageState a site may keep: cookies of its hosts, localStorage of its origins. */
export function scopeState(state, site) {
  return {
    cookies: state.cookies.filter((c) => cookieAllowed(c, site)),
    origins: (state.origins ?? []).filter((o) => urlAllowed(o.origin, site.allowedHosts)),
  };
}

/** Is something already listening on 127.0.0.1:port? (Binding fails.) Only for choosing a port: binding races with a server that is starting. */
function portInUse(port) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(true));
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(false)));
  });
}

const LOOPBACK_LISTEN = new Set(['0100007F', '00000000000000000000000001000000']); // 127.0.0.1, ::1 as /proc/net/tcp{,6} prints them

/**
 * The local addresses (as /proc/net/tcp prints them) of the sockets listening
 * on `port`. Reading the kernel table detects a server without touching it: a
 * connection would count as the client of `x11vnc -once`.
 */
function listeners(port) {
  const hex = port.toString(16).toUpperCase().padStart(4, '0');
  const found = [];
  for (const table of ['/proc/net/tcp', '/proc/net/tcp6']) {
    let text = '';
    try {
      text = fs.readFileSync(table, 'utf8');
    } catch {
      continue;
    }
    for (const line of text.split('\n').slice(1)) {
      const cols = line.trim().split(/\s+/);
      const [addr, p] = (cols[1] ?? '').split(':');
      if (p === hex && cols[3] === '0A') found.push(addr);
    }
  }
  return found;
}

async function freeVncPort() {
  for (let port = VNC_PORTS[0]; port <= VNC_PORTS[1]; port += 1) {
    if (!(await portInUse(port))) return port;
  }
  throw new HelperError('conflict', 'no free port in 5900-5999 for the VNC server');
}

function displayFree(n) {
  return !fs.existsSync(`/tmp/.X${n}-lock`) && !fs.existsSync(`/tmp/.X11-unix/X${n}`);
}

/** A child process that keeps its last stderr line (for a start-up failure) and tells when it is gone. */
function launch(cmd, args, what, env = process.env) {
  const child = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'pipe'], env });
  const proc = { child, what, exited: false, stderr: '' };
  proc.gone = new Promise((resolve) => {
    child.once('exit', (code, signal) => {
      proc.exited = true;
      resolve({ code, signal });
    });
    child.once('error', (err) => {
      proc.exited = true;
      proc.spawnError = err;
      resolve({ error: err });
    });
  });
  child.stderr.on('data', (d) => {
    proc.stderr = (proc.stderr + d).slice(-400);
  });
  proc.stop = async () => {
    if (proc.exited) return;
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS);
    await proc.gone;
    clearTimeout(timer);
  };
  proc.why = () => proc.stderr.trim().split('\n').pop().slice(0, 200);
  return proc;
}

function missing(proc, what) {
  return proc.spawnError?.code === 'ENOENT' ? new HelperError('dependency_missing', `${what} is not installed`) : null;
}

/**
 * @param options.env  process environment (VAULT_VNC_CMD)
 * @param options.stateDir  helper state directory (profiles/<id>)
 * @param options.runDir    directory of the one-time VNC password file (vnc.pw, 0600) and the Xauthority file (vnc.xauth, 0600)
 * @param options.minuteMs  length of a minute for the hard timeout (tests shorten it)
 * @param options.abandon   async ({ site, state, landingUrl }) best-effort logout (LeaseManager#abandon)
 */
export function createInteractive({ pool, store, log, siteLocks, abandon, stateDir, runDir, timeouts, env = process.env, clock = Date.now, minuteMs = 60_000 }) {
  let active = null;

  const profileDir = (siteId) => path.join(stateDir, 'profiles', siteId);
  const passwordFile = () => path.join(runDir, 'vnc.pw');
  const xauthPath = () => path.join(runDir, 'vnc.xauth');

  // ---- processes ---------------------------------------------------------------------
  async function startXvfb() {
    for (let i = 0; i < DISPLAY_TRIES; i += 1) {
      const n = FIRST_DISPLAY + i;
      if (!displayFree(n)) continue;
      // A fresh cookie for every attempt and session; only whoever gets the file can connect.
      await fsp.mkdir(runDir, { recursive: true, mode: 0o755 });
      await fsp.rm(xauthPath(), { force: true });
      await fsp.writeFile(xauthPath(), xauthFile(n, randomBytes(16)), { mode: 0o600, flag: 'wx' });
      const proc = launch('Xvfb', [`:${n}`, '-nolisten', 'tcp', '-nolisten', 'local', '-auth', xauthPath(), '-screen', '0', SCREEN], 'Xvfb');
      const until = Date.now() + START_WAIT_MS;
      while (!proc.exited && !fs.existsSync(`/tmp/.X11-unix/X${n}`) && Date.now() < until) await sleep(50);
      if (!proc.exited && fs.existsSync(`/tmp/.X11-unix/X${n}`)) return { proc, display: `:${n}` };
      await proc.stop();
      const gone = missing(proc, 'Xvfb');
      if (gone) throw gone;
      log('warn', 'Xvfb did not start', { display: n, reason: proc.why() });
    }
    throw new HelperError('browser_unavailable', 'Xvfb could not be started on a free display');
  }

  async function startVnc(a, minutes) {
    const port = await freeVncPort();
    const password = Array.from({ length: 8 }, () => PASSWORD_CHARS[randomInt(PASSWORD_CHARS.length)]).join('');
    await fsp.mkdir(runDir, { recursive: true, mode: 0o755 });
    await fsp.rm(passwordFile(), { force: true });
    await fsp.writeFile(passwordFile(), vncAuthFile(password), { mode: 0o600, flag: 'wx' });
    const cmd = env.VAULT_VNC_CMD || 'x11vnc';
    const proc = launch(cmd, [
      '-display', a.display,
      '-auth', xauthPath(),
      '-localhost',
      '-rfbport', String(port),
      '-rfbauth', passwordFile(),
      '-once',
      '-timeout', String(Math.min(900, minutes * 60)),
    ], 'x11vnc', env);
    // Listening is read from the kernel table, never probed by connecting or binding.
    const until = Date.now() + START_WAIT_MS;
    while (!proc.exited && listeners(port).length === 0 && Date.now() < until) await sleep(50);
    const bound = listeners(port);
    // The VNC server must be reachable from this host only (an ssh tunnel brings the owner in).
    const exposed = bound.some((addr) => !LOOPBACK_LISTEN.has(addr));
    if (proc.exited || bound.length === 0 || exposed) {
      await proc.stop();
      await fsp.rm(passwordFile(), { force: true });
      throw missing(proc, 'x11vnc')
        ?? new HelperError('browser_unavailable', exposed ? 'the VNC server listens beyond localhost; stopped' : `x11vnc did not start${proc.why() ? `: ${proc.why()}` : ''}`);
    }
    a.vnc = proc;
    a.vncPort = port;
    // x11vnc -once ends with its first client; the owner can start the VNC server again.
    void proc.gone.then(() => {
      if (a.vnc === proc) a.vnc = null;
    });
    return { vncPort: port, vncPassword: password };
  }

  async function teardown(a, reason) {
    if (a.done) return a.done;
    a.done = (async () => {
      clearTimeout(a.timer);
      if (active === a) active = null;
      await a.browser?.close();
      await a.vnc?.stop();
      await fsp.rm(passwordFile(), { force: true }).catch(() => {});
      await a.xvfb?.stop();
      await fsp.rm(xauthPath(), { force: true }).catch(() => {});
      a.releaseLock?.();
      log('info', 'interactive login stopped', { siteId: a.site.id, reason });
    })();
    return a.done;
  }

  // ---- ops -------------------------------------------------------------------------------
  function siteOf(deps, params) {
    const siteId = needString(params, 'siteId', ID_RE);
    const site = deps.sites().get(siteId);
    if (!site) throw new HelperError('not_found', `unknown site ${siteId}`);
    if (site.type !== 'interactive') throw bad(`site ${siteId} is not an interactive site`);
    return site;
  }

  const ops = {
    async 'interactive.start'(params, deps) {
      const site = siteOf(deps, params);
      const minutes = needInt(params, 'minutes', 1, MAX_MINUTES);
      if (active) {
        if (active.site.id !== site.id) throw new HelperError('conflict', `an interactive login for ${active.site.id} is running`);
        if (active.starting) throw new HelperError('conflict', 'the interactive login is starting; wait for it');
        if (active.vnc) throw new HelperError('conflict', 'the interactive login is already running; connect to it or finish it');
        // The VNC server ended with its client: offer a new connection to the same browser.
        const creds = await startVnc(active, Math.max(1, Math.ceil((active.expiresAtMs - clock()) / minuteMs)));
        return { display: active.display, ...creds, expiresAt: new Date(active.expiresAtMs).toISOString() };
      }
      // Claim the slot before the first await: a second start must find it taken.
      const expiresAtMs = clock() + minutes * minuteMs;
      const a = { site, expiresAtMs, releaseLock: null, done: null, starting: true };
      active = a;
      try {
        try {
          a.releaseLock = await siteLocks.acquire(site.id, AbortSignal.timeout(2_000));
        } catch {
          throw new HelperError('conflict', `a login for ${site.id} is running; try again in a moment`);
        }
        const { proc, display } = await startXvfb();
        a.xvfb = proc;
        a.display = display;
        void proc.gone.then(() => {
          if (active === a && !a.done) void teardown(a, 'xvfb_exited');
        });
        await fsp.mkdir(profileDir(site.id), { recursive: true, mode: 0o700 });
        const slot = await pool.checkoutProfile(deps.opSignal(timeouts.openMs), site.allowedHosts, {
          userDataDir: profileDir(site.id),
          headless: false,
          env: { ...process.env, DISPLAY: display, XAUTHORITY: xauthPath() },
          contextOptions: { viewport: null, acceptDownloads: false, permissions: [] },
          // A person signs in here: no automation banner, and none of the flags that make sites refuse the sign-in.
          ignoreDefaultArgs: ['--enable-automation'],
          args: ['--disable-blink-features=AutomationControlled', '--window-position=0,0', '--window-size=1280,800'],
        });
        a.browser = slot;
        a.context = slot.context;
        a.guard = await installGuard(slot.context, site);
        slot.context.on('close', () => {
          if (active === a && !a.done) void teardown(a, 'browser_closed');
        });
        const page = slot.context.pages()[0] ?? (await slot.context.newPage());
        // A failed first load is not fatal: the owner can type the address.
        await page.goto(site.loginUrl, { waitUntil: 'domcontentloaded', timeout: 20_000 }).catch(() => {});
        Object.assign(a, await startVnc(a, minutes));
        a.timer = setTimeout(() => {
          void teardown(a, 'timeout');
        }, minutes * minuteMs);
        a.timer.unref?.();
        a.starting = false;
        log('info', 'interactive login started', { siteId: site.id, display, vncPort: a.vncPort });
        return { display, vncPort: a.vncPort, vncPassword: a.vncPassword, expiresAt: new Date(expiresAtMs).toISOString() };
      } catch (err) {
        await teardown(a, 'start_failed');
        throw err;
      }
    },

    async 'interactive.finish'(params, deps) {
      const siteId = needString(params, 'siteId', ID_RE);
      const a = active;
      if (!a || a.site.id !== siteId || a.done) throw new HelperError('not_found', 'no interactive login is running for this site');
      const { site } = a;
      const deadline = new Deadline(timeouts.successMs);
      let holds = false;
      for (;;) {
        for (const page of a.context.pages()) {
          if (await successHolds(page, site.recipe.successCheck)) holds = true;
        }
        if (holds || deadline.expired()) break;
        await sleep(timeouts.pollMs);
      }
      // The browser stays up: the owner may carry on and finish again.
      if (!holds) throw new HelperError('login_failed', 'the success check does not hold in the browser yet');
      const blocked = a.guard.blockedNavigation();
      if (blocked) throw new HelperError('recipe_error', `navigation to disallowed host ${blocked.host} was blocked`);
      const state = scopeState(await a.context.storageState(), site);
      if (state.cookies.length === 0) throw new HelperError('login_failed', 'the browser holds no cookie of this site');
      try {
        await store.put('session', site.id, state);
      } catch (err) {
        // Not sealed: the session is of no use to us, so do not leave it open at the site.
        await abandon({ site, state: await a.context.storageState().catch(() => state), landingUrl: a.context.pages()[0]?.url() });
        await teardown(a, 'seal_failed');
        throw err;
      }
      await teardown(a, 'finished');
      log('info', 'interactive session sealed', { siteId: site.id, cookies: state.cookies.length });
      return { sealed: true, cookies: state.cookies.length };
    },
  };

  // ---- session.open strategy ---------------------------------------------------------------
  const strategy = {
    /** An interactive login is running for this site: session.open must not touch its profile. */
    busy: (site) => active?.site.id === site.id,

    /**
     * site.test: the same re-open and success check, but no lease: logging out
     * afterwards would end the owner's one session.
     */
    async test(site, { signal }) {
      const release = await siteLocks.acquire(site.id, signal);
      try {
        await strategy.login(site, { signal });
      } finally {
        release();
      }
      return { state: 'ok', trustUsed: false, loggedOut: 'unsupported' };
    },

    /**
     * Re-open the stored session headless (on the profile when there is one,
     * with the sealed cookies added), check it still works, seal the refreshed
     * state and return a copy.
     */
    async login(site, { signal }) {
      const stored = await store.get('session', site.id);
      if (!stored) throw new HelperError('needs_interactive', 'no stored session; run vault-site interactive');
      const dir = profileDir(site.id);
      const hasProfile = fs.existsSync(dir);
      const slot = hasProfile
        ? await pool.checkoutProfile(signal, site.allowedHosts, { userDataDir: dir, headless: true, contextOptions: { ...CONTEXT_OPTIONS } })
        : await pool.checkout(signal, site.allowedHosts);
      try {
        // Session cookies do not survive in a Chromium profile, so the sealed state is added to it.
        let context = slot.context;
        if (hasProfile) await context.addCookies(stored.cookies);
        else context = await slot.browser.newContext({ ...CONTEXT_OPTIONS, storageState: stored });
        const guard = await installGuard(context, site);
        const page = context.pages()[0] ?? (await context.newPage());
        const deadline = new Deadline(site.recipe.timeoutSeconds * 1000);
        try {
          await page.goto(site.loginUrl, { waitUntil: 'domcontentloaded', timeout: deadline.budget(timeouts.stepMs) });
        } catch (err) {
          if (signal?.aborted) throw signal.reason instanceof HelperError ? signal.reason : new HelperError('timeout', 'operation timed out');
          const blocked = await guard.blockedNavigationWithin(500);
          if (blocked) throw new HelperError('recipe_error', `navigation to disallowed host ${blocked.host} was blocked`);
          throw new HelperError('site_unreachable', 'the site could not be reached');
        }
        const outcome = await awaitOutcome(page, site.recipe, { deadline, timeouts, blockedNavigation: guard.blockedNavigation, signal });
        const blocked = guard.blockedNavigation();
        if (blocked) throw new HelperError('recipe_error', `navigation to disallowed host ${blocked.host} was blocked`);
        if (outcome !== 'success') throw new HelperError('needs_interactive', 'the stored session was rejected by the site; run vault-site interactive');
        const state = scopeState(await context.storageState(), site);
        await store.put('session', site.id, state);
        return { kind: 'done', session: { liveState: state, deliverState: state, landingUrl: page.url(), trustUsed: false } };
      } finally {
        await slot.close();
      }
    },
  };

  return {
    ops,
    strategy,
    isActive: () => active !== null,
    /** The browser context of the running interactive login (diagnostics and tests: it plays the owner at the keyboard). */
    activeContext: () => active?.context ?? null,
    async shutdown() {
      if (active) await teardown(active, 'helper_stop');
    },
  };
}
