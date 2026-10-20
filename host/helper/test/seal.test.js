import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { Sealer, SealedStore } from '../seal.js';
import { readStoreKey } from '../creds.js';
import { scratch } from './support.js';

test('round trip, and the plaintext is not in the blob', () => {
  const s = new Sealer(randomBytes(32));
  const blob = s.seal('trust', 'site1', { cookies: [{ name: 'device_trust', value: 'SECRETVALUE' }] });
  assert.equal(blob.includes('SECRETVALUE'), false);
  assert.equal(blob.includes('device_trust'), false);
  assert.deepEqual(s.open('trust', 'site1', blob).cookies[0].value, 'SECRETVALUE');
});

test('wrong key, tampering, truncation and re-labelling are all rejected', () => {
  const key = randomBytes(32);
  const s = new Sealer(key);
  const blob = s.seal('lease', 'lse_1', { a: 1 });
  const rejects = (fn) => assert.throws(fn, (e) => e.code === 'seal_unreadable');
  rejects(() => new Sealer(randomBytes(32)).open('lease', 'lse_1', blob));
  const flipped = Buffer.from(blob);
  flipped[flipped.length - 1] ^= 1;
  rejects(() => s.open('lease', 'lse_1', flipped));
  rejects(() => s.open('lease', 'lse_1', blob.subarray(0, 20)));
  rejects(() => s.open('lease', 'lse_2', blob)); // moved to another id
  rejects(() => s.open('trust', 'lse_1', blob)); // moved to another kind
});

test('every seal uses a fresh nonce', () => {
  const s = new Sealer(randomBytes(32));
  assert.notDeepEqual(s.seal('trust', 'x', { a: 1 }), s.seal('trust', 'x', { a: 1 }));
});

test('key must be exactly 32 bytes', async () => {
  assert.throws(() => new Sealer(Buffer.alloc(16)), TypeError);
  const env = scratch();
  try {
    fs.writeFileSync(path.join(env.creds, 'short'), 'abc');
    await assert.rejects(readStoreKey(env.creds, 'short'), /32 bytes/);
    assert.equal((await readStoreKey(env.creds)).length, 32);
  } finally {
    env.cleanup();
  }
});

test('store: atomic 0600 files, get/list, shred removes', async () => {
  const env = scratch();
  try {
    const store = new SealedStore({ root: env.state, sealer: new Sealer(env.storeKey) });
    assert.equal(await store.get('trust', 'a'), null);
    await store.put('trust', 'a', { n: 1 });
    await store.put('lease', 'lse_1', { n: 2 });
    const file = path.join(env.state, 'store/trust/a.enc');
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
    assert.deepEqual(await store.get('trust', 'a'), { n: 1 });
    assert.deepEqual(await store.list('lease'), ['lse_1']);
    assert.equal(fs.readdirSync(path.dirname(file)).some((n) => n.endsWith('.tmp')), false);
    assert.equal(await store.shred('trust', 'a'), true);
    assert.equal(await store.shred('trust', 'a'), false);
    assert.equal(fs.existsSync(file), false);
    // a file sealed under another key is reported, not silently ignored
    const other = new SealedStore({ root: env.state, sealer: new Sealer(randomBytes(32)) });
    await assert.rejects(other.get('lease', 'lse_1'), (e) => e.code === 'seal_unreadable');
    await assert.rejects(store.put('trust', '../x', {}), TypeError);
  } finally {
    env.cleanup();
  }
});
