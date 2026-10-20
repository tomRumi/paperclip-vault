// Recipe runner: fill / click / press / waitFor only, no scripts. Values come
// from a lazy `secret(from)` callback and are never logged or put in errors.
import { HelperError } from './errors.js';
import { base32Decode, freshCode } from './totp.js';

export const DEFAULT_TIMEOUTS = Object.freeze({
  stepMs: 15_000, // wait for a required selector
  optionalMs: 3_000, // docs/DESIGN.md section 5: optional step is skipped after 3 s
  successMs: 15_000, // wait for success / challenge after the last step
  pollMs: 250,
  openMs: 50_000, // whole session.open: queueing, browser start, login; below vaultd's 60 s call timeout so the helper's answer wins the race (docs/DESIGN.md section 4)
});

const CAPTCHA_SELECTOR = [
  'iframe[src*="recaptcha"]',
  'iframe[src*="hcaptcha"]',
  'iframe[src*="challenges.cloudflare.com"]',
  '.g-recaptcha',
  '.h-captcha',
  '.cf-turnstile',
].join(', ');

export class Deadline {
  constructor(ms, now = Date.now) {
    this.at = now() + ms;
    this.now = now;
  }
  remaining() {
    return this.at - this.now();
  }
  /** Spent, give or take timer jitter: a wait that was capped by the budget has just run out. */
  expired() {
    return this.remaining() < 100;
  }
  /** Milliseconds to wait for something, capped by `cap`; throws timeout when the budget is spent. */
  budget(cap) {
    if (this.expired()) throw new HelperError('timeout', 'login time budget exhausted');
    return Math.min(this.remaining(), cap);
  }
}

function isTimeout(err) {
  return err?.name === 'TimeoutError';
}

/** Wait for `selector` to be visible. Returns the locator, or null when `optional` and absent. */
async function locate(page, selector, { optional, deadline, timeouts, label }) {
  const locator = page.locator(selector).first();
  const wait = deadline.budget(optional ? timeouts.optionalMs : timeouts.stepMs);
  try {
    await locator.waitFor({ state: 'visible', timeout: wait });
    return locator;
  } catch (err) {
    if (!isTimeout(err)) throw err;
    if (optional) return null;
    if (deadline.expired()) throw new HelperError('timeout', 'login time budget exhausted');
    throw new HelperError('recipe_error', `${label}: selector not found`);
  }
}

/**
 * Run `steps` on `page`. Returns { lastFrom } where lastFrom is the
 * `from` of the last executed fill step (used to tell a bad password from a
 * bad TOTP code when the success check later fails).
 */
export async function runSteps(page, steps, { secret, deadline, timeouts = DEFAULT_TIMEOUTS, clock }) {
  let lastFrom = null;
  for (let i = 0; i < steps.length; i += 1) {
    const s = steps[i];
    const label = `step ${i + 1}`;
    const optional = s.optional === true;
    try {
      if (s.fill !== undefined) {
        const target = await locate(page, s.fill, { optional, deadline, timeouts, label });
        if (!target) continue;
        let value;
        if (s.from === 'totp') {
          value = await freshCode(base32Decode(await secret('totp')), clock);
        } else {
          value = await secret(s.from);
        }
        await target.fill(value, { timeout: deadline.budget(timeouts.stepMs) });
        lastFrom = s.from;
      } else if (s.click !== undefined) {
        const target = await locate(page, s.click, { optional, deadline, timeouts, label });
        if (!target) continue;
        await target.click({ timeout: deadline.budget(timeouts.stepMs) });
      } else if (s.press !== undefined) {
        if (s.selector !== undefined) {
          const target = await locate(page, s.selector, { optional, deadline, timeouts, label });
          if (!target) continue;
          await target.press(s.press, { timeout: deadline.budget(timeouts.stepMs) });
        } else {
          await page.keyboard.press(s.press);
        }
      } else if (s.waitFor !== undefined) {
        if (!(await locate(page, s.waitFor, { optional, deadline, timeouts, label }))) continue;
      }
    } catch (err) {
      if (err instanceof HelperError) throw err;
      if (isTimeout(err)) {
        if (deadline.expired()) throw new HelperError('timeout', 'login time budget exhausted');
        throw new HelperError('recipe_error', `${label}: action timed out`);
      }
      throw new HelperError('recipe_error', `${label}: ${String(err.message).split('\n')[0].slice(0, 200)}`);
    }
  }
  return { lastFrom };
}

/**
 * Tick the "remember this device" control when it is there (a checkbox is
 * checked, never toggled; anything else is clicked). Absent: nothing happens.
 */
export async function rememberDevice(page, selector, { deadline, timeouts = DEFAULT_TIMEOUTS }) {
  const target = await locate(page, selector, { optional: true, deadline, timeouts, label: 'remember' });
  if (!target) return false;
  const tickable = await target.evaluate((el) => el instanceof HTMLInputElement && (el.type === 'checkbox' || el.type === 'radio'));
  if (tickable) await target.check({ timeout: deadline.budget(timeouts.stepMs) });
  else await target.click({ timeout: deadline.budget(timeouts.stepMs) });
  return true;
}

async function safeVisible(page, selector) {
  try {
    return await page.locator(selector).first().isVisible();
  } catch {
    return false; // page navigating; the next poll sees the settled document
  }
}

export async function successHolds(page, check) {
  if (check.urlMatches !== undefined && !new RegExp(check.urlMatches).test(page.url())) return false;
  if (check.selector !== undefined && !(await safeVisible(page, check.selector))) return false;
  return true;
}

/**
 * After the last step, wait until one of: the success check holds ('success'),
 * the trust challenge is showing ('challenge'), a CAPTCHA is showing
 * ('captcha'), or time runs out ('none').
 */
export async function awaitOutcome(page, recipe, { deadline, timeouts = DEFAULT_TIMEOUTS, blockedNavigation, signal }) {
  const until = Math.min(deadline.at, deadline.now() + timeouts.successMs);
  for (;;) {
    if (blockedNavigation()) return 'none';
    if (await successHolds(page, recipe.successCheck)) return 'success';
    if (recipe.challenge && (await safeVisible(page, recipe.challenge.codeSelector))) return 'challenge';
    if (await safeVisible(page, CAPTCHA_SELECTOR)) return 'captcha';
    if (deadline.now() >= until) {
      if (deadline.expired()) throw new HelperError('timeout', 'login time budget exhausted');
      return 'none';
    }
    if (signal?.aborted) throw new HelperError('timeout', 'operation cancelled');
    await new Promise((r) => setTimeout(r, timeouts.pollMs));
  }
}
