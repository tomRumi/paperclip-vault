// Small request-parameter validators. They throw bad_request and never echo
// the offending value (it may be a secret supplied in the wrong field).
import { bad } from './errors.js';

export const ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
export const LEASE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const HANDLE_RE = /^[A-Za-z0-9_-]{1,64}$/;

export function plainObject(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw bad(`${name} must be an object`);
  }
  return value;
}

export function needString(params, key, re) {
  const v = params[key];
  if (typeof v !== 'string' || v.length === 0 || (re && !re.test(v))) {
    throw bad(`${key} missing or malformed`);
  }
  return v;
}

export function needInt(params, key, min, max) {
  const v = params[key];
  if (!Number.isInteger(v) || v < min || v > max) {
    throw bad(`${key} must be an integer in ${min}..${max}`);
  }
  return v;
}

export function optBool(params, key, fallback = false) {
  const v = params[key];
  if (v === undefined) return fallback;
  if (typeof v !== 'boolean') throw bad(`${key} must be a boolean`);
  return v;
}

export function needIsoFuture(params, key, nowMs) {
  const v = params[key];
  const ms = typeof v === 'string' ? Date.parse(v) : NaN;
  if (!Number.isFinite(ms)) throw bad(`${key} must be an ISO timestamp`);
  if (ms <= nowMs) throw bad(`${key} is in the past`);
  return ms;
}
