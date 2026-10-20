// Runs last (the loader imports test files in name order): after every other
// test, no process this test process started may still be running. Walks the
// parent chain from this PID through /proc, so Chromium and its helpers, Xvfb,
// the VNC stub and the fake servers are all covered, whatever their command lines.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { descendants, waitForExit } from './support.js';

test('no process started by the tests is left running', async () => {
  const left = descendants();
  try {
    await waitForExit(left.map((p) => p.pid), 'the processes started by the tests', 10_000);
  } catch {
    const still = new Set(descendants().map((p) => p.pid));
    assert.fail(`processes outlived the tests: ${left.filter((p) => still.has(p.pid)).map((p) => `${p.pid} ${p.cmd.slice(0, 80)}`).join('; ')}`);
  }
});
