// Login strategy for `password-totp` sites: run the recipe in a fresh context
// that carries the sealed device-trust jar, then split the result into the
// live session (sealed per lease) and the copy handed to the caller.
import { randomBytes } from 'node:crypto';
import { CONTEXT_OPTIONS, installGuard } from './browser.js';
import { HelperError } from './errors.js';
import { awaitOutcome, DEFAULT_TIMEOUTS, Deadline, rememberDevice, runSteps } from './recipe.js';
import { urlAllowed } from './sites.js';

const CHALLENGE_TTL_MS = 5 * 60_000;
const CHALLENGE_ATTEMPTS = 3;
const SNAPSHOT_MS = 2_000;

function firstLine(err) {
  return String(err?.message ?? err).split('\n')[0].slice(0, 200);
}

/** The cookies and url of a live context, for a logout after a failure; null when the browser is already gone. */
async function snapshot(context, page) {
  if (!context) return null;
  try {
    const state = await Promise.race([
      context.storageState(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('snapshot timed out')), SNAPSHOT_MS).unref()),
    ]);
    return { state, landingUrl: page?.url() };
  } catch {
    return null;
  }
}

/**
 * @param abandon async ({ site, state, landingUrl }) -> best-effort logout of a
 *   session that will never become a lease (LeaseManager#abandon)
 */
export function createPasswordStrategy({ pool, store, creds, log, abandon, timeouts = DEFAULT_TIMEOUTS, clock }) {
  /** @type {Map<string, object>} attended logins waiting for a challenge code */
  const pending = new Map();

  /** The sealed device-trust jar: { cookies, origins } (origins hold the trusted localStorage keys). */
  async function loadJar(site) {
    try {
      const jar = await store.get('trust', site.id);
      return { cookies: jar?.cookies ?? [], origins: jar?.origins ?? [] };
    } catch (err) {
      if (err.code !== 'seal_unreadable') throw err;
      log('warn', 'trust jar unreadable, continuing without it', { siteId: site.id });
      return { cookies: [], origins: [] };
    }
  }

  /** A login that is abandoned after credentials went in: close the browser, then log out of whatever session it holds. */
  async function discard({ site, slot, context, page }) {
    const snap = await snapshot(context, page);
    await slot.close();
    if (snap) await abandon({ site, ...snap });
  }

  function blockedError(guard) {
    const blocked = guard?.blockedNavigation();
    return blocked ? new HelperError('recipe_error', `navigation to disallowed host ${blocked.host} was blocked`) : null;
  }

  /** Turn whatever went wrong into the error the caller sees. A blocked top-level navigation explains most failures after it. */
  function mapError(err, signal, guard) {
    if (signal?.aborted) {
      return signal.reason instanceof HelperError ? signal.reason : new HelperError('timeout', 'operation timed out');
    }
    if (err instanceof HelperError && err.code !== 'recipe_error') return err;
    return blockedError(guard) ?? (err instanceof HelperError ? err : new HelperError('recipe_error', firstLine(err)));
  }

  async function navigate(page, site, guard, deadline) {
    let response;
    try {
      response = await page.goto(site.loginUrl, { waitUntil: 'domcontentloaded', timeout: deadline.budget(timeouts.stepMs) });
    } catch (err) {
      if (/net::ERR_/.test(err.message ?? '')) {
        const blocked = await guard.blockedNavigationWithin(500);
        if (blocked) throw new HelperError('recipe_error', `navigation to disallowed host ${blocked.host} was blocked`);
        throw new HelperError('site_unreachable', 'the login page could not be loaded');
      }
      throw err;
    }
    const blocked = blockedError(guard);
    if (blocked) throw blocked;
    if (response && response.status() >= 500) throw new HelperError('site_unreachable', `the login page answered ${response.status()}`);
  }

  /** Split a finished login into the sealed live state and what the caller may receive. */
  async function finish(site, context, page, { trustUsed }) {
    const state = await context.storageState();
    const cookiePatterns = site.recipe.trustCookies.map((re) => new RegExp(re));
    const keyPatterns = site.recipe.trustStorageKeys.map((re) => new RegExp(re));
    const isTrustCookie = (c) => cookiePatterns.some((re) => re.test(c.name));
    const isTrustKey = (item) => keyPatterns.some((re) => re.test(item.name));
    const trustCookies = state.cookies.filter(isTrustCookie);
    const trustOrigins = state.origins
      .map((o) => ({ origin: o.origin, localStorage: o.localStorage.filter(isTrustKey) }))
      .filter((o) => o.localStorage.length > 0);
    if (trustCookies.length > 0 || trustOrigins.length > 0) await store.put('trust', site.id, { cookies: trustCookies, origins: trustOrigins });
    else await store.shred('trust', site.id);
    // The jar loaded into the context holds trust items only, and trust items
    // are withheld, so every remaining cookie was set by this login. Origins
    // are returned only for allowed host:port origins.
    const origins = state.origins
      .filter((o) => urlAllowed(o.origin, site.allowedHosts))
      .map((o) => ({ origin: o.origin, localStorage: o.localStorage.filter((i) => !isTrustKey(i)) }))
      .filter((o) => o.localStorage.length > 0);
    return {
      liveState: state,
      deliverState: { cookies: state.cookies.filter((c) => !isTrustCookie(c)), origins },
      landingUrl: page.url(),
      trustUsed,
    };
  }

  function drop(handle) {
    const p = pending.get(handle);
    if (!p) return null;
    pending.delete(handle);
    clearTimeout(p.timer);
    return p;
  }

  async function classify(outcome, site, ctx) {
    if (outcome === 'captcha') throw new HelperError('needs_interactive', 'a CAPTCHA is shown; use an interactive login');
    const blocked = blockedError(ctx.guard);
    if (blocked) throw blocked;
    throw new HelperError(
      ctx.lastFrom === 'totp' ? 'totp_failed' : 'login_failed',
      ctx.lastFrom === 'totp' ? 'the site did not accept the one-time code' : 'the site did not accept the login',
    );
  }

  /**
   * Log in. Resolves { kind: 'done', session } or, for an attended run that
   * meets the trust challenge, { kind: 'challenge', handle, expiresAt } (the
   * browser stays open until submitChallenge or the TTL).
   */
  async function login(site, { signal, attended = false }) {
    const jar = await loadJar(site);
    const trustUsed = jar.cookies.length > 0 || jar.origins.length > 0;
    // The pool kills the browser when its signal aborts. Ours follows `signal`
    // only after the cookies of a login that is under way have been captured,
    // so a timeout can still log out.
    const killer = new AbortController();
    let submitted = false; // a credential has been read: a session may exist at the site
    let context;
    let page;
    let guard;
    let captured = null;
    const onAbort = () => {
      captured = submitted ? snapshot(context, page) : Promise.resolve(null);
      void captured.then(() => killer.abort(signal.reason));
    };
    if (signal?.aborted) killer.abort(signal.reason);
    else signal?.addEventListener('abort', onAbort, { once: true });
    let slot;
    try {
      slot = await pool.checkout(killer.signal, site.allowedHosts);
    } catch (err) {
      signal?.removeEventListener('abort', onAbort);
      throw mapError(err, signal);
    }
    try {
      context = await slot.browser.newContext({
        ...CONTEXT_OPTIONS,
        ...(trustUsed ? { storageState: jar } : {}),
      });
      guard = await installGuard(context, site);
      page = await context.newPage();
      const deadline = new Deadline(site.recipe.timeoutSeconds * 1000);
      const secret = async (part) => {
        const value = await creds.site(site.id, part);
        submitted = true;
        return value;
      };
      await navigate(page, site, guard, deadline);
      const { lastFrom } = await runSteps(page, site.recipe.steps, { secret, deadline, timeouts, clock });
      const outcome = await awaitOutcome(page, site.recipe, {
        deadline,
        timeouts,
        blockedNavigation: guard.blockedNavigation,
        signal,
      });
      const ctx = { guard, lastFrom };
      if (outcome === 'success') {
        const session = await finish(site, context, page, { trustUsed });
        signal?.removeEventListener('abort', onAbort);
        await slot.close();
        return { kind: 'done', session };
      }
      if (outcome === 'challenge') {
        if (!attended) throw new HelperError('challenge_required', 'the site asks for a code on this device; run an attended test');
        signal?.removeEventListener('abort', onAbort);
        const handle = `chl_${randomBytes(8).toString('hex')}`;
        const entry = { site, slot, context, page, guard, attempts: 0, trustUsed };
        entry.timer = setTimeout(() => {
          const p = drop(handle);
          if (p) void discard(p);
        }, CHALLENGE_TTL_MS);
        pending.set(handle, entry);
        return { kind: 'challenge', handle, expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString() };
      }
      return await classify(outcome, site, ctx);
    } catch (err) {
      signal?.removeEventListener('abort', onAbort);
      // Credentials went in and the login did not complete (failed success
      // check, seal failure, timeout, ...): log out of any session the site
      // opened, then close the browser. The error is returned afterwards.
      const snap = captured ? await captured : submitted ? await snapshot(context, page) : null;
      await slot.close();
      if (snap) await abandon({ site, ...snap });
      throw mapError(err, signal, guard);
    }
  }

  /**
   * Enter the code of an attended challenge; on success the trust jar is
   * stored. A wrong code leaves the handle open for a retry (3 attempts).
   */
  async function submitChallenge(handle, code, { signal } = {}) {
    const p = pending.get(handle);
    if (!p) throw new HelperError('not_found', 'no such challenge (expired or finished)');
    const { site, page, context, guard } = p;
    try {
      const deadline = new Deadline(site.recipe.timeoutSeconds * 1000);
      await page.locator(site.recipe.challenge.codeSelector).first().fill(code, { timeout: deadline.budget(timeouts.stepMs) });
      if (site.recipe.challenge.remember) await rememberDevice(page, site.recipe.challenge.remember, { deadline, timeouts });
      await page.locator(site.recipe.challenge.submit).first().click({ timeout: deadline.budget(timeouts.stepMs) });
      const outcome = await awaitOutcome(page, site.recipe, {
        deadline,
        timeouts,
        blockedNavigation: guard.blockedNavigation,
        signal,
      });
      if (outcome === 'success') {
        const session = await finish(site, context, page, { trustUsed: false });
        drop(handle);
        await p.slot.close();
        return { site, session };
      }
      p.attempts += 1;
      if (p.attempts >= CHALLENGE_ATTEMPTS) {
        drop(handle);
        await discard(p);
      }
      throw new HelperError('login_failed', 'the site did not accept the challenge code');
    } catch (err) {
      const mapped = mapError(err, signal, guard);
      if (mapped.code !== 'login_failed' && drop(handle)) await discard(p);
      throw mapped;
    }
  }

  async function shutdown() {
    for (const handle of [...pending.keys()]) {
      const p = drop(handle);
      if (p) await p.slot.close();
    }
  }

  return { login, submitChallenge, shutdown, pendingCount: () => pending.size };
}
