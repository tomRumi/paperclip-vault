// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) on node:crypto only.
import { createHmac } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { HelperError } from './errors.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32 -> Buffer. Case, spaces, hyphens and padding are ignored. */
export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (clean.length === 0) throw new HelperError('missing_credential', 'TOTP seed is empty');
  let bits = 0;
  let acc = 0;
  const out = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new HelperError('missing_credential', 'TOTP seed is not valid base32');
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
      acc &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

export function hotp(secret, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function totp(secret, { now = Date.now(), step = 30, digits = 6 } = {}) {
  return hotp(secret, Math.floor(now / 1000 / step), digits);
}

export function msUntilNextWindow(now = Date.now(), step = 30) {
  const ms = step * 1000;
  return ms - (now % ms);
}

/**
 * Code for "now", but when fewer than `minRemainingMs` of the window are left
 * wait for the next window first so the code cannot expire in flight.
 */
export async function freshCode(
  secret,
  { now = () => Date.now(), pause = sleep, minRemainingMs = 3000, step = 30, digits = 6 } = {},
) {
  const left = msUntilNextWindow(now(), step);
  if (left < minRemainingMs) await pause(left + 50);
  return totp(secret, { now: now(), step, digits });
}
