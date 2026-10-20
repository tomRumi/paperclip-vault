// Sandbox policy (docs/DESIGN.md section 4) against a stub engine: no real Chromium needed.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BrowserPool, hostResolverRules } from '../browser.js';

function engine({ sandboxWorks }) {
  const launches = [];
  return {
    launches,
    async launch(opts) {
      launches.push(opts.chromiumSandbox);
      if (opts.chromiumSandbox && !sandboxWorks) throw new Error('No usable sandbox!\nlong call log');
      return { close: async () => {} };
    },
  };
}

test('sandbox works: used, never downgraded', async () => {
  const e = engine({ sandboxWorks: true });
  const pool = new BrowserPool({ allowNoSandbox: true, log() {}, engine: e });
  await (await pool.checkout(undefined, ['a.test'])).close();
  assert.equal(pool.sandbox, 'on');
  assert.deepEqual(e.launches, [true]);
});

test('sandbox fails and allowNoSandbox: falls back once, remembers, warns', async () => {
  const e = engine({ sandboxWorks: false });
  const logs = [];
  const pool = new BrowserPool({ allowNoSandbox: true, log: (...a) => logs.push(a), engine: e });
  await (await pool.checkout(undefined, ['a.test'])).close();
  await (await pool.checkout(undefined, ['a.test'])).close();
  assert.equal(pool.sandbox, 'off');
  assert.deepEqual(e.launches, [true, false, false]); // the sandbox is only tried until it failed once
  assert.equal(logs.filter(([, msg]) => /--no-sandbox/.test(msg)).length, 1);
});

test('sandbox fails and allowNoSandbox is false: browser_unavailable, no --no-sandbox launch', async () => {
  const e = engine({ sandboxWorks: false });
  const pool = new BrowserPool({ allowNoSandbox: false, log() {}, engine: e });
  await assert.rejects(pool.checkout(undefined, ['a.test']), (err) => err.code === 'browser_unavailable' && /allowNoSandbox is false/.test(err.message));
  assert.deepEqual(e.launches, [true]);
  assert.equal(pool.sandbox, null);
});

test('a failed launch frees its slot', async () => {
  const e = engine({ sandboxWorks: false });
  const pool = new BrowserPool({ maxBrowsers: 1, allowNoSandbox: false, log() {}, engine: e });
  await assert.rejects(pool.checkout(undefined, ['a.test']));
  await assert.rejects(pool.checkout(undefined, ['a.test'])); // would hang if the slot leaked
});

test('every browser resolves allowedHosts and nothing else (redirects cannot leave)', async () => {
  assert.equal(
    hostResolverRules(['app.example.org', '127.0.0.1:8080', 'app.example.org:8443']),
    'MAP * ~NOTFOUND, EXCLUDE app.example.org, EXCLUDE 127.0.0.1',
  );
  const seen = [];
  const e = { launch: async (o) => (seen.push(o.args), { close: async () => {} }) };
  const pool = new BrowserPool({ allowNoSandbox: true, log() {}, engine: e });
  await (await pool.checkout(undefined, ['app.example.org'])).close();
  assert.equal(seen.length, 1);
  assert.equal(seen[0][0], '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE app.example.org');
  assert.match(seen[0][1], /^--proxy-server=http:\/\/127\.0\.0\.1:\d+$/, 'every browser gets a proxy of its own');
  assert.equal(seen[0][2], '--proxy-bypass-list=<-loopback>', 'loopback is proxied too');
  assert.equal(seen[0].length, 3);
});

test('works(): a launch decides once, success is remembered, failure is not retried at once', async () => {
  const good = engine({ sandboxWorks: true });
  const pool = new BrowserPool({ allowNoSandbox: false, log() {}, engine: good });
  assert.equal(await pool.works(), true);
  assert.equal(await pool.works(), true);
  assert.deepEqual(good.launches, [true]);

  const broken = engine({ sandboxWorks: false });
  const p2 = new BrowserPool({ allowNoSandbox: false, log() {}, engine: broken });
  assert.equal(await p2.works(), false);
  assert.equal(await p2.works(), false);
  assert.deepEqual(broken.launches, [true], 'the failed probe is cached');
});

/** An engine whose launches finish when the test says so; every close is recorded. */
function slowEngine() {
  const e = { pending: [], closed: 0 };
  e.launch = () => new Promise((resolve) => e.pending.push(() => resolve({ close: async () => void (e.closed += 1) })));
  /** Finish the next launch, once it has been asked for. */
  e.finish = async () => {
    while (e.pending.length === 0) await new Promise((r) => setImmediate(r));
    e.pending.shift()();
  };
  return e;
}

test('closeAll(): closes browsers that are up and those still starting, and frees their slots', async () => {
  const e = slowEngine();
  const pool = new BrowserPool({ maxBrowsers: 2, allowNoSandbox: true, log() {}, engine: e });
  const up = pool.checkout(undefined, ['a.test']);
  await e.finish();
  await up;
  const starting = pool.checkout(undefined, ['b.test']);
  while (e.pending.length === 0) await new Promise((r) => setImmediate(r));
  assert.equal(pool.active, 2);

  const closing = pool.closeAll();
  await e.finish(); // the second launch finishes while closeAll() waits for it
  await closing;
  await starting;
  assert.equal(pool.active, 0);
  assert.equal(e.closed, 2);
  const again = pool.checkout(undefined, ['a.test']); // both slots are free again
  await e.finish();
  await (await again).close();
});

test('close() waits for a close that the abort signal already started', async () => {
  let finish;
  const e = { launch: async () => ({ close: () => new Promise((r) => (finish = r)) }) };
  const pool = new BrowserPool({ allowNoSandbox: true, log() {}, engine: e });
  const stop = new AbortController();
  const slot = await pool.checkout(stop.signal, ['a.test']);
  stop.abort();
  let done = false;
  const closing = slot.close().then(() => (done = true));
  await new Promise((r) => setImmediate(r));
  assert.equal(done, false, 'the browser is still shutting down');
  finish();
  await closing;
  assert.equal(pool.active, 0);
});

test('works(): the stop signal ends a probe that waits for a slot', async () => {
  const e = slowEngine();
  const stop = new AbortController();
  const pool = new BrowserPool({ maxBrowsers: 1, allowNoSandbox: true, log() {}, engine: e, signal: stop.signal });
  const held = pool.checkout(undefined, ['a.test']); // takes the only slot, its launch is still going
  while (e.pending.length === 0) await new Promise((r) => setImmediate(r));
  const probe = pool.works();
  await new Promise((r) => setImmediate(r));
  stop.abort();
  assert.equal(await probe, false);
  assert.equal(e.pending.length, 1, 'the probe never started a browser');
  await e.finish();
  await (await held).close();
});
