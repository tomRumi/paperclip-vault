// Chromium management: sandbox policy (docs/DESIGN.md section 4), the global browser limit,
// and the allowedHosts navigation guard installed on every context.
import { chromium } from 'playwright-core';
import { HelperError } from './errors.js';
import { startProxy } from './proxy.js';
import { Semaphore } from './queue.js';
import { urlAllowed } from './sites.js';

const PROBE_MS = 20_000;
const PROBE_RETRY_MS = 60_000;

export const CONTEXT_OPTIONS = Object.freeze({
  acceptDownloads: false,
  serviceWorkers: 'block',
  permissions: [],
});

export class BrowserPool {
  #sem;
  #allowNoSandbox;
  #log;
  #engine;
  #stop;
  #sandbox = null; // 'on' | 'off' once known
  #probe = null;
  #launching = new Set(); // promises of browser starts in progress
  #open = new Set(); // close() of every browser that is up

  /** `signal` (the helper's stop signal) also ends the startup probe. */
  constructor({ maxBrowsers = 3, allowNoSandbox = false, log, engine = chromium, signal }) {
    this.#sem = new Semaphore(maxBrowsers);
    this.#allowNoSandbox = allowNoSandbox;
    this.#log = log;
    this.#engine = engine;
    this.#stop = signal;
  }

  /** Browsers that are up or starting. */
  get active() {
    return this.#open.size + this.#launching.size;
  }

  /** 'on', 'off' (--no-sandbox) or null while no browser has been started. */
  get sandbox() {
    return this.#sandbox;
  }

  /**
   * Can a browser be started here? True once any launch has worked; before
   * that one probe launch decides (a failed probe is remembered for a minute,
   * so a broken install does not make every ping wait).
   */
  async works() {
    if (this.#sandbox !== null) return true;
    this.#probe ??= (async () => {
      try {
        const slot = await this.checkout(AbortSignal.any([AbortSignal.timeout(PROBE_MS), ...(this.#stop ? [this.#stop] : [])]), []);
        await slot.close();
        return true;
      } catch (err) {
        this.#log('warn', 'browser probe failed', { error: err.code ?? err.name });
        setTimeout(() => {
          this.#probe = null;
        }, PROBE_RETRY_MS).unref();
        return false;
      }
    })();
    return this.#probe;
  }

  /** `start({ chromiumSandbox, args })` runs the engine call; this decides the sandbox mode around it. */
  async #launch(allowedHosts, proxy, start) {
    // Playwright does not run route handlers for the hops of a redirect, so a
    // server could bounce the browser to another host behind installGuard().
    // The resolver rule closes that gap for the whole browser (redirects,
    // sub-resources, workers, WebSockets): any host name outside allowedHosts
    // fails with ERR_NAME_NOT_RESOLVED. It is per host name (any port);
    // installGuard() adds the exact host:port check for ordinary requests.
    //
    // Neither keeps a 307/308 hop from being sent to another port of an allowed
    // host, with the cookies or the password. So the browser also gets a
    // proxy of its own (proxy.js) that connects to the exact host:port pairs of
    // allowedHosts only; loopback is proxied too (<-loopback> removes the
    // implicit bypass).
    const args = [
      `--host-resolver-rules=${hostResolverRules(allowedHosts)}`,
      `--proxy-server=http://127.0.0.1:${proxy.port}`,
      '--proxy-bypass-list=<-loopback>',
    ];
    // Try the Chromium sandbox first; fall back to --no-sandbox only when
    // helper.json allows it. Playwright adds --no-sandbox unless told otherwise.
    if (this.#sandbox !== 'off') {
      try {
        const browser = await start({ chromiumSandbox: true, args });
        if (this.#sandbox === null) this.#log('info', 'chromium sandbox active');
        this.#sandbox = 'on';
        return browser;
      } catch (err) {
        if (!this.#allowNoSandbox) {
          throw new HelperError(
            'browser_unavailable',
            `chromium could not start with its sandbox and allowNoSandbox is false: ${firstLine(err)}`,
          );
        }
        this.#log('warn', 'chromium sandbox unavailable; falling back to --no-sandbox (allowNoSandbox=true)', {
          reason: firstLine(err),
        });
      }
    }
    try {
      const browser = await start({ chromiumSandbox: false, args });
      this.#sandbox = 'off';
      return browser;
    } catch (err) {
      throw new HelperError('browser_unavailable', `chromium could not start: ${firstLine(err)}`);
    }
  }

  /**
   * Take one of the browser slots and start a browser that can reach only
   * `allowedHosts`. `close()` frees both.
   * If `signal` aborts the browser is killed, which fails whatever is pending
   * on it; callers map that to `timeout`.
   */
  async checkout(signal, allowedHosts) {
    const slot = await this.#slot(signal, allowedHosts, (o) => this.#engine.launch({ headless: true, ...o }));
    return { browser: slot.handle, close: slot.close };
  }

  /**
   * Like checkout(), but a Chromium with a persistent profile directory (cookies
   * and storage survive in `userDataDir`) and one default context, which is
   * returned. `headless:false` needs a display in `env.DISPLAY`.
   */
  async checkoutProfile(signal, allowedHosts, { userDataDir, headless, env, contextOptions = {}, args = [], ignoreDefaultArgs }) {
    const slot = await this.#slot(signal, allowedHosts, (o) =>
      this.#engine.launchPersistentContext(userDataDir, {
        headless,
        env,
        ...contextOptions,
        ...(ignoreDefaultArgs ? { ignoreDefaultArgs } : {}),
        ...o,
        args: [...o.args, ...args],
      }));
    return { context: slot.handle, close: slot.close };
  }

  async #slot(signal, allowedHosts, start) {
    const release = await this.#sem.acquire(signal);
    let proxy;
    let handle;
    const launching = (async () => {
      proxy = await startProxy(allowedHosts);
      return this.#launch(allowedHosts, proxy, start);
    })();
    this.#launching.add(launching);
    try {
      handle = await launching;
    } catch (err) {
      await proxy?.close();
      release();
      throw err;
    } finally {
      this.#launching.delete(launching);
    }
    let closing = null;
    // Everyone who calls close() waits for the same close, so a caller never
    // returns while the browser is still shutting down.
    const close = () => {
      closing ??= (async () => {
        signal?.removeEventListener('abort', onAbort);
        this.#open.delete(close);
        try {
          await handle.close();
        } catch {
          // browser already gone
        } finally {
          await proxy.close();
          release();
        }
      })();
      return closing;
    };
    const onAbort = () => {
      void close();
    };
    this.#open.add(close);
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
    return { handle, close };
  }

  /** Close every browser, those still starting included. Resolves when all of them are gone. */
  async closeAll() {
    while (this.active > 0) {
      await Promise.allSettled([...this.#launching]);
      await Promise.allSettled([...this.#open].map((close) => close()));
    }
  }

  async with(signal, allowedHosts, fn) {
    const slot = await this.checkout(signal, allowedHosts);
    try {
      return await fn(slot.browser);
    } finally {
      await slot.close();
    }
  }
}

export function hostResolverRules(allowedHosts) {
  const names = [...new Set(allowedHosts.map((h) => h.replace(/:[0-9]+$/, '')))];
  return ['MAP * ~NOTFOUND', ...names.map((n) => `EXCLUDE ${n}`)].join(', ');
}

function firstLine(err) {
  return String(err?.message ?? err).split('\n')[0].slice(0, 300);
}

function hostOf(url) {
  try {
    return new URL(url).host || url.split(':')[0];
  } catch {
    return '(unparseable)';
  }
}

/**
 * Abort every request to a host outside `site.allowedHosts` (navigations and
 * sub-resources alike: the login form holds the password, so no third-party
 * script may load into it), and record what was blocked. Blocked top-level
 * navigations (the ones that break a login) are told apart from blocked
 * sub-resources. Redirect hops to other host names are stopped by the browser's
 * resolver rule (see BrowserPool); every hop and every main-frame URL is also
 * checked here with its port.
 */
export async function installGuard(context, site) {
  const blocked = [];
  const seen = new WeakSet();
  const waiters = [];
  const record = (request) => {
    if (seen.has(request)) return;
    seen.add(request);
    const host = hostOf(request.url());
    const navigation = request.isNavigationRequest() && request.frame().parentFrame() === null;
    const entry = { host, navigation };
    blocked.push(entry);
    if (navigation) while (waiters.length > 0) waiters.pop()(entry);
  };
  await context.route('**/*', (route) => {
    const request = route.request();
    if (urlAllowed(request.url(), site.allowedHosts)) return route.continue();
    record(request);
    return route.abort('blockedbyclient');
  });
  // The resolver rule only knows host names, and route handlers do not see the
  // hops of a redirect. So every request event (each redirect hop is one) and
  // every main-frame URL is checked against host:port here: a redirect to the
  // same host name on another port, or a document that ends up there, is
  // recorded as a blocked navigation and fails the login closed.
  const check = (request) => {
    if (!urlAllowed(request.url(), site.allowedHosts)) record(request);
  };
  const checkFrame = (frame) => {
    const url = frame.url();
    if (/^(about|chrome-error):/.test(url) || urlAllowed(url, site.allowedHosts)) return; // chrome-error: the page of a failed load
    const entry = { host: hostOf(url), navigation: true };
    blocked.push(entry);
    while (waiters.length > 0) waiters.pop()(entry);
  };
  context.on('request', check);
  context.on('page', (page) => {
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) checkFrame(frame);
    });
  });
  const blockedNavigation = () => blocked.find((b) => b.navigation) ?? null;
  return {
    blocked,
    blockedNavigation,
    /**
     * The browser reports a failed navigation and the failed request on
     * separate channels; after the former, wait briefly for the latter.
     */
    async blockedNavigationWithin(ms) {
      const known = blockedNavigation();
      if (known) return known;
      return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(null), ms);
        waiters.push((entry) => {
          clearTimeout(timer);
          resolve(entry);
        });
      });
    },
  };
}
