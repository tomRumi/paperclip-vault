import assert from 'node:assert/strict';
import { test } from 'node:test';
import { base32Decode, freshCode, hotp, msUntilNextWindow, totp } from '../totp.js';
import { HelperError } from '../errors.js';

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890", 8 digits.
const RFC = Buffer.from('12345678901234567890');

test('RFC 6238 SHA-1 vectors', () => {
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [t, code] of vectors) assert.equal(totp(RFC, { now: t * 1000, digits: 8 }), code);
});

test('six digit codes are the last six digits', () => {
  assert.equal(totp(RFC, { now: 59_000 }), '287082');
  assert.equal(hotp(RFC, 0), '755224'); // RFC 4226 appendix D
});

test('base32 decoding ignores case, spaces and padding', () => {
  assert.deepEqual(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), RFC);
  assert.deepEqual(base32Decode('gezd gnbv-gy3t qojq gezd gnbv gy3t qojq'), RFC);
  assert.deepEqual(base32Decode('MZXW6==='), Buffer.from('foo'));
});

test('invalid seeds are credential errors, never echoed', () => {
  for (const bad of ['', '!!!', 'ABC1']) {
    assert.throws(() => base32Decode(bad), (e) => e instanceof HelperError && e.code === 'missing_credential' && !e.message.includes(bad || 'zzz'));
  }
});

test('freshCode waits for the next window when less than 3 s remain', async () => {
  let t = 29_000 + 30_000 * 5; // 1 s left in the window
  const waits = [];
  const code = await freshCode(RFC, {
    now: () => t,
    pause: async (ms) => {
      waits.push(ms);
      t += ms;
    },
  });
  assert.equal(waits.length, 1);
  assert.equal(code, totp(RFC, { now: t }));
  assert.equal(msUntilNextWindow(t) > 3000, true);
  // plenty of time left: no wait
  const w2 = [];
  await freshCode(RFC, { now: () => 31_000, pause: async (ms) => w2.push(ms) });
  assert.deepEqual(w2, []);
});
