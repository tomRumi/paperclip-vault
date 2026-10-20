// helper.json. Every key is optional; defaults are the production paths of
// docs/DESIGN.md (section 1). Unknown keys are rejected.
import fs from 'node:fs';
import { DEFAULT_TIMEOUTS } from './recipe.js';
import { DEFAULT_LOGOUT_RETRY_MS } from './leases.js';

const DEFAULTS = Object.freeze({
  socketPath: '/run/vault-helper/helper.sock',
  socketMode: '0660',
  socketGroup: 'vault', // group name or numeric gid to chgrp the socket to; null = leave as is (tests)
  tokenFile: '/etc/vault/helper.token', // vaultd: ping, session.open/close, token.mint/revoke
  adminTokenFile: '/etc/vault/helper-admin.token', // root CLI only: the admin ops (everything outside VAULTD_OPS in helper.js)
  sitesDir: '/etc/vault/sites',
  stateDir: '/var/lib/vault-helper',
  credentialsDir: null, // null = $CREDENTIALS_DIRECTORY
  storeKeyCredential: 'vault-helper.storekey',
  allowNoSandbox: false,
  maxBrowsers: 3,
  timeouts: DEFAULT_TIMEOUTS,
  logoutRetryMs: DEFAULT_LOGOUT_RETRY_MS,
});

function fail(msg) {
  throw new Error(`helper config: ${msg}`);
}

export function normalizeConfig(raw, env = process.env) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail('must be a JSON object');
  for (const k of Object.keys(raw)) if (!(k in DEFAULTS)) fail(`unknown key "${k}"`);
  const c = { ...DEFAULTS, ...raw };
  for (const k of ['socketPath', 'tokenFile', 'adminTokenFile', 'sitesDir', 'stateDir', 'storeKeyCredential']) {
    if (typeof c[k] !== 'string' || !c[k]) fail(`${k} must be a non-empty string`);
  }
  if (!/^0[0-7]{3}$/.test(c.socketMode)) fail('socketMode must be an octal string such as "0660"');
  if (c.socketGroup !== null && typeof c.socketGroup !== 'string') fail('socketGroup must be a string or null');
  if (c.credentialsDir !== null && typeof c.credentialsDir !== 'string') fail('credentialsDir must be a string or null');
  if (typeof c.allowNoSandbox !== 'boolean') fail('allowNoSandbox must be a boolean');
  if (!Number.isInteger(c.maxBrowsers) || c.maxBrowsers < 1 || c.maxBrowsers > 8) fail('maxBrowsers must be 1..8');
  const timeouts = { ...DEFAULT_TIMEOUTS };
  for (const [k, v] of Object.entries(raw.timeouts ?? {})) {
    if (!(k in DEFAULT_TIMEOUTS)) fail(`unknown timeouts key "${k}"`);
    if (!Number.isInteger(v) || v < 10) fail(`timeouts.${k} must be an integer >= 10 (ms)`);
    timeouts[k] = v;
  }
  c.timeouts = Object.freeze(timeouts);
  if (!Array.isArray(c.logoutRetryMs) || c.logoutRetryMs.length < 1 || !c.logoutRetryMs.every((n) => Number.isInteger(n) && n >= 0)) {
    fail('logoutRetryMs must be a non-empty array of delays in ms');
  }
  c.credentialsDir = c.credentialsDir ?? env.CREDENTIALS_DIRECTORY ?? null;
  return Object.freeze(c);
}

export function loadConfig(file, env = process.env) {
  return normalizeConfig(JSON.parse(fs.readFileSync(file, 'utf8')), env);
}
