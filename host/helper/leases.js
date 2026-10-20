// Lease lifecycle: seal the live session (or the minted access token of an
// OAuth lease) per lease, end it on our own timer (logout / revoke, then
// shred), and pick every sealed lease up again after a restart. For a token
// lease `loggedOut` in the results means "revoked".
import { request } from 'playwright-core';
import { CONTEXT_OPTIONS, installGuard } from './browser.js';
import { HelperError } from './errors.js';
import { Deadline, DEFAULT_TIMEOUTS, runSteps } from './recipe.js';
import { urlAllowed } from './sites.js';

const RECENT_MS = 60 * 60_000;
const LOGOUT_BUDGET_MS = 30_000;
const ABANDON_BUDGET_MS = 15_000; // browser start included
const ABANDON_RECIPE_MS = 6_000; // the logout steps themselves
const ABANDON_STEP_MS = 3_000; // a login that failed mostly has no session: do not wait long for a logout button
export const DEFAULT_LOGOUT_RETRY_MS = Object.freeze([0, 2_000, 5_000]);

/** Copy of a storageState whose every cookie expires no later than `endsAtMs`; session cookies get `endsAtMs`. */
export function clampState(state, endsAtMs) {
  const endsSec = Math.floor(endsAtMs / 1000);
  return {
    cookies: state.cookies.map((c) => ({
      ...c,
      expires: c.expires > 0 ? Math.min(Math.floor(c.expires), endsSec) : endsSec,
    })),
    origins: state.origins,
  };
}

export class LeaseManager {
  #store;
  #pool;
  #creds;
  #log;
  #timeouts;
  #retryMs;
  #revoke;
  #now;
  #stopSignal;
  #leases = new Map(); // leaseId -> { leaseId, siteId, endsAtMs, timer }
  #closing = new Map(); // leaseId -> Promise<result>
  #recent = new Map(); // leaseId -> { loggedOut, reason, at }
  #reserved = new Set();
  #stopped = false;

  /**
   * @param revoke async (sealedLease, signal) -> true | false | 'unsupported'
   *   ends a token lease at the provider (oauth.js)
   * @param signal the helper's stop signal: it aborts every logout in flight
   */
  constructor({ store, pool, creds, log, revoke, timeouts = DEFAULT_TIMEOUTS, logoutRetryMs = DEFAULT_LOGOUT_RETRY_MS, now = Date.now, signal }) {
    this.#revoke = revoke;
    this.#store = store;
    this.#pool = pool;
    this.#creds = creds;
    this.#log = log;
    this.#timeouts = timeouts;
    this.#retryMs = logoutRetryMs;
    this.#now = now;
    this.#stopSignal = signal;
  }

  /** Signal for one logout / revoke attempt: its time budget, or the helper stopping. */
  #attemptSignal(ms) {
    return AbortSignal.any([AbortSignal.timeout(ms), ...(this.#stopSignal ? [this.#stopSignal] : [])]);
  }

  has(leaseId) {
    return this.#leases.has(leaseId) || this.#closing.has(leaseId);
  }

  /**
   * Claim a lease id for the duration of a login, so two requests for the
   * same id cannot both log in. Returns the release function.
   */
  reserve(leaseId) {
    if (this.has(leaseId) || this.#reserved.has(leaseId)) throw new HelperError('conflict', 'lease already exists');
    this.#reserved.add(leaseId);
    return () => this.#reserved.delete(leaseId);
  }

  list() {
    return [...this.#leases.values()].map((l) => ({
      leaseId: l.leaseId,
      siteId: l.siteId,
      endsAt: new Date(l.endsAtMs).toISOString(),
    }));
  }

  /**
   * Seal the live session (or, for an OAuth lease, `token`: the access token to
   * revoke) and arm the end-of-lease timer. The site is stored with the lease,
   * so logout still works after the site file changed or went.
   */
  async register({ leaseId, site, endsAtMs, liveState, landingUrl, token }) {
    await this.#store.put('lease', leaseId, {
      v: 1,
      leaseId,
      site,
      endsAt: new Date(endsAtMs).toISOString(),
      ...(token ? { token } : { landingUrl, state: liveState }),
    });
    this.#track({ leaseId, siteId: site.id, endsAtMs });
  }

  #track(lease) {
    const delay = Math.max(0, lease.endsAtMs - this.#now());
    lease.timer = setTimeout(() => {
      this.close(lease.leaseId, 'expired').catch((err) => this.#log('error', 'lease end failed', { leaseId: lease.leaseId, error: err.code ?? err.name }));
    }, delay);
    this.#leases.set(lease.leaseId, lease);
  }

  /** End a lease now: log out server-side, close, shred. Idempotent; remembers the result for an hour. */
  close(leaseId, reason) {
    const running = this.#closing.get(leaseId);
    if (running) return running;
    const lease = this.#leases.get(leaseId);
    if (!lease) {
      const done = this.#recent.get(leaseId);
      if (done) return Promise.resolve({ loggedOut: done.loggedOut, reason: done.reason });
      return Promise.reject(new HelperError('not_found', 'unknown lease'));
    }
    clearTimeout(lease.timer);
    const p = this.#end(lease, reason).finally(() => this.#closing.delete(leaseId));
    this.#closing.set(leaseId, p);
    return p;
  }

  async closeSite(siteId, reason) {
    const ids = [...this.#leases.values()].filter((l) => l.siteId === siteId).map((l) => l.leaseId);
    await Promise.allSettled(ids.map((id) => this.close(id, reason)));
  }

  async #end(lease, reason) {
    let loggedOut = false;
    try {
      const sealed = await this.#store.get('lease', lease.leaseId);
      if (sealed) loggedOut = await this.#attempts(sealed, (signal) => (sealed.token ? this.#revoke(sealed, signal) : this.#logout(sealed, signal)));
      else this.#log('error', 'sealed lease file missing at lease end', { leaseId: lease.leaseId });
    } catch (err) {
      this.#log('error', 'sealed lease unreadable at lease end', { leaseId: lease.leaseId, error: err.code ?? err.name });
    }
    if (this.#stopped && loggedOut === false) {
      // Stopped before the logout could be completed: the sealed lease stays,
      // the next start finds it past its end and logs out then.
      this.#log('warn', 'lease end interrupted by stop; sealed lease kept', { leaseId: lease.leaseId });
      return { loggedOut, reason };
    }
    await this.#store.shred('lease', lease.leaseId);
    this.#leases.delete(lease.leaseId);
    const now = this.#now();
    this.#recent.set(lease.leaseId, { loggedOut, reason, at: now });
    for (const [id, r] of this.#recent) if (now - r.at > RECENT_MS) this.#recent.delete(id);
    this.#log('info', 'lease ended', { leaseId: lease.leaseId, siteId: lease.siteId, reason, loggedOut });
    return { loggedOut, reason };
  }

  async #attempts(sealed, run) {
    let last = false;
    for (let attempt = 0; attempt < this.#retryMs.length; attempt += 1) {
      if (this.#stopped) break;
      if (this.#retryMs[attempt] > 0) await new Promise((r) => setTimeout(r, this.#retryMs[attempt]));
      if (this.#stopped) break;
      try {
        last = await run(this.#attemptSignal(LOGOUT_BUDGET_MS));
        if (last !== false) return last;
      } catch (err) {
        this.#log('warn', 'lease end attempt failed', { leaseId: sealed.leaseId, attempt: attempt + 1, error: err.code ?? err.name });
      }
    }
    return last;
  }

  /**
   * Best-effort logout of a session that never became a lease (a login that
   * failed after the credentials were submitted, or whose lease could not be
   * sealed). Resolves true | false | 'unsupported'; never throws. One attempt
   * with its own short budget: the caller is about to return an error.
   */
  async abandon({ site, state, landingUrl }) {
    try {
      if (state.cookies.length === 0) return 'unsupported'; // nothing could have been established
      const here = landingUrl && urlAllowed(landingUrl, site.allowedHosts) ? landingUrl : undefined;
      const done = await this.#logout({ site, state, landingUrl: here }, this.#attemptSignal(ABANDON_BUDGET_MS), { budgetMs: ABANDON_RECIPE_MS, stepMs: ABANDON_STEP_MS });
      this.#log('info', 'abandoned login logged out', { siteId: site.id, loggedOut: done });
      return done;
    } catch (err) {
      this.#log('warn', 'could not log out an abandoned login', { siteId: site.id, error: err.code ?? err.name });
      return false;
    }
  }

  /** One logout attempt: true, false, or 'unsupported' when the site offers no way to log out. */
  async #logout({ site, state, landingUrl }, signal, { budgetMs = LOGOUT_BUDGET_MS, stepMs = this.#timeouts.stepMs } = {}) {
    const steps = site.recipe?.logout?.steps;
    if (steps) {
      return this.#pool.with(signal, site.allowedHosts, async (browser) => {
        const context = await browser.newContext({ ...CONTEXT_OPTIONS, storageState: state });
        await installGuard(context, site);
        const page = await context.newPage();
        const deadline = new Deadline(budgetMs);
        const timeouts = { ...this.#timeouts, stepMs, optionalMs: Math.min(this.#timeouts.optionalMs, stepMs) };
        await page.goto(landingUrl ?? site.loginUrl, { waitUntil: 'domcontentloaded', timeout: deadline.budget(stepMs) });
        await runSteps(page, steps, {
          secret: (part) => this.#creds.site(site.id, part),
          deadline,
          timeouts,
        });
        return true;
      });
    }
    if (site.logoutUrl) {
      if (!urlAllowed(site.logoutUrl, site.allowedHosts)) return false;
      const api = await request.newContext({ storageState: state });
      // A request context takes no signal: disposing it fails the pending request.
      const onAbort = () => void api.dispose().catch(() => {});
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
      try {
        // Redirects are not followed: the first answer already tells whether the
        // logout was accepted, and a redirect could leave allowedHosts.
        const opts = { maxRedirects: 0, failOnStatusCode: false, timeout: 20_000 };
        let res = await api.get(site.logoutUrl, opts);
        if (res.status() === 405) res = await api.post(site.logoutUrl, opts);
        return res.status() < 400;
      } finally {
        signal.removeEventListener('abort', onAbort);
        await api.dispose();
      }
    }
    return 'unsupported';
  }

  /** After a restart: re-arm every sealed lease; those past their end are logged out now. */
  async recover() {
    const summary = { resumed: 0, ended: 0, dropped: 0 };
    for (const leaseId of await this.#store.list('lease')) {
      let sealed;
      try {
        sealed = await this.#store.get('lease', leaseId);
      } catch (err) {
        this.#log('error', 'dropping unreadable sealed lease', { leaseId, error: err.code ?? err.name });
        await this.#store.shred('lease', leaseId);
        summary.dropped += 1;
        continue;
      }
      const endsAtMs = Date.parse(sealed.endsAt);
      this.#track({ leaseId, siteId: sealed.site.id, endsAtMs });
      if (endsAtMs <= this.#now()) {
        void this.close(leaseId, 'expired_while_down').catch(() => {});
        summary.ended += 1;
      } else {
        summary.resumed += 1;
      }
    }
    this.#log('info', 'lease recovery', summary);
    return summary;
  }

  /** Resolves when no lease end is in progress (recovery of expired leases included). */
  async idle() {
    while (this.#closing.size > 0) await Promise.allSettled([...this.#closing.values()]);
  }

  /** Stop all timers; sealed leases stay on disk and resume at the next start. */
  stop() {
    this.#stopped = true;
    for (const l of this.#leases.values()) clearTimeout(l.timer);
  }
}
