// Site files (/etc/vault/sites/<id>.json): strict schema validation, unknown
// keys rejected at every level. The vaultd side validates the same schema.
import fs from 'node:fs';
import path from 'node:path';
import { HelperError } from './errors.js';
import { ID_RE } from './params.js';

export const SITE_TYPES = ['password-totp', 'interactive', 'oauth'];
export const SITE_KINDS = ['test', 'owner', 'research'];
export const STEP_FROM = ['username', 'password', 'totp'];
const OAUTH_FLOWS = ['device', 'redirect'];

const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/;
const UUID_RE = /^[0-9a-f-]{36}$/;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const MAX_SELECTOR = 500;
const MAX_STEPS = 50;

class Problems {
  list = [];
  add(where, msg) {
    this.list.push(`${where}: ${msg}`);
  }
}

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function keys(p, where, obj, allowed) {
  if (!isObject(obj)) {
    p.add(where, 'must be an object');
    return false;
  }
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) p.add(where, `unknown key "${k}"`);
  }
  return true;
}

function str(p, where, v, { min = 1, max = 200, re } = {}) {
  if (typeof v !== 'string' || v.length < min || v.length > max || (re && !re.test(v))) {
    p.add(where, `must be a string of ${min}..${max} characters${re ? ' in the expected format' : ''}`);
    return false;
  }
  return true;
}

function int(p, where, v, min, max) {
  if (!Number.isInteger(v) || v < min || v > max) {
    p.add(where, `must be an integer in ${min}..${max}`);
    return false;
  }
  return true;
}

function regex(p, where, v) {
  if (!str(p, where, v, { max: 300 })) return;
  try {
    new RegExp(v);
  } catch {
    p.add(where, 'is not a valid regular expression');
  }
}

/**
 * Is `url` navigable under `allowedHosts`? An entry without a port matches the
 * scheme's default port only; an entry with a port matches that port exactly.
 * The scheme must be https; http is accepted for loopback hosts only (the
 * fake sites of the tests and local services).
 */
export function urlAllowed(url, allowedHosts) {
  let u;
  try {
    u = url instanceof URL ? url : new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOOPBACK.has(u.hostname))) return false;
  return allowedHosts.includes(u.host);
}

function url(p, where, v, { nullable = false } = {}) {
  if (v === null && nullable) return null;
  let u;
  try {
    u = new URL(v);
  } catch {
    p.add(where, 'must be an absolute URL');
    return undefined;
  }
  if (u.username || u.password) p.add(where, 'must not carry credentials');
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOOPBACK.has(u.hostname))) {
    p.add(where, 'must be https (http only for loopback)');
  }
  return u;
}

function step(p, where, s) {
  if (!keys(p, where, s, ['fill', 'click', 'press', 'waitFor', 'from', 'selector', 'optional'])) return;
  const ops = ['fill', 'click', 'press', 'waitFor'].filter((k) => s[k] !== undefined);
  if (ops.length !== 1) {
    p.add(where, 'must contain exactly one of fill, click, press, waitFor');
    return;
  }
  const op = ops[0];
  str(p, `${where}.${op}`, s[op], { max: MAX_SELECTOR });
  if (op === 'fill') {
    if (!STEP_FROM.includes(s.from)) p.add(`${where}.from`, `must be one of ${STEP_FROM.join(', ')}`);
  } else if (s.from !== undefined) {
    p.add(`${where}.from`, 'is only valid on a fill step');
  }
  if (op === 'press') {
    if (s.selector !== undefined) str(p, `${where}.selector`, s.selector, { max: MAX_SELECTOR });
  } else if (s.selector !== undefined) {
    p.add(`${where}.selector`, 'is only valid on a press step');
  }
  if (s.optional !== undefined && typeof s.optional !== 'boolean') p.add(`${where}.optional`, 'must be a boolean');
}

function steps(p, where, list, { min }) {
  if (!Array.isArray(list) || list.length < min || list.length > MAX_STEPS) {
    p.add(where, `must be an array of ${min}..${MAX_STEPS} steps`);
    return;
  }
  list.forEach((s, i) => step(p, `${where}[${i}]`, s));
}

function recipe(p, r, type) {
  const where = 'recipe';
  if (!keys(p, where, r, ['steps', 'successCheck', 'logout', 'challenge', 'trustCookies', 'trustStorageKeys', 'timeoutSeconds'])) return;
  // Interactive sites are logged in by hand: scripted steps are optional there.
  if (!(type === 'interactive' && r.steps === undefined)) {
    steps(p, 'recipe.steps', r.steps, { min: type === 'interactive' ? 0 : 1 });
  }
  const sc = r.successCheck;
  if (keys(p, 'recipe.successCheck', sc, ['urlMatches', 'selector'])) {
    if (sc.urlMatches === undefined && sc.selector === undefined) {
      p.add('recipe.successCheck', 'needs urlMatches and/or selector (mandatory)');
    }
    if (sc.urlMatches !== undefined) regex(p, 'recipe.successCheck.urlMatches', sc.urlMatches);
    if (sc.selector !== undefined) str(p, 'recipe.successCheck.selector', sc.selector, { max: MAX_SELECTOR });
  }
  if (r.logout !== undefined && r.logout !== null) {
    if (keys(p, 'recipe.logout', r.logout, ['steps'])) steps(p, 'recipe.logout.steps', r.logout.steps, { min: 1 });
  }
  if (r.challenge !== undefined && r.challenge !== null) {
    if (keys(p, 'recipe.challenge', r.challenge, ['codeSelector', 'submit', 'remember'])) {
      str(p, 'recipe.challenge.codeSelector', r.challenge.codeSelector, { max: MAX_SELECTOR });
      str(p, 'recipe.challenge.submit', r.challenge.submit, { max: MAX_SELECTOR });
      // "Remember this device": ticked before the code is submitted, when present.
      if (r.challenge.remember !== undefined) str(p, 'recipe.challenge.remember', r.challenge.remember, { max: MAX_SELECTOR });
    }
  }
  if (r.trustCookies !== undefined) {
    if (!Array.isArray(r.trustCookies) || r.trustCookies.length > 20) p.add('recipe.trustCookies', 'must be an array of at most 20 patterns');
    else r.trustCookies.forEach((t, i) => regex(p, `recipe.trustCookies[${i}]`, t));
  }
  // localStorage keys that hold device trust, like trustCookies: kept in the helper, never returned.
  if (r.trustStorageKeys !== undefined) {
    if (!Array.isArray(r.trustStorageKeys) || r.trustStorageKeys.length > 20) p.add('recipe.trustStorageKeys', 'must be an array of at most 20 patterns');
    else r.trustStorageKeys.forEach((t, i) => regex(p, `recipe.trustStorageKeys[${i}]`, t));
  }
  if (r.timeoutSeconds !== undefined) int(p, 'recipe.timeoutSeconds', r.timeoutSeconds, 5, 300);
}

function oauth(p, o) {
  if (!keys(p, 'oauth', o, ['flow', 'authUrl', 'tokenUrl', 'deviceUrl', 'revokeUrl', 'clientId', 'scopes', 'accessTtlMaxMinutes'])) return;
  if (!OAUTH_FLOWS.includes(o.flow)) p.add('oauth.flow', `must be one of ${OAUTH_FLOWS.join(', ')}`);
  for (const k of ['authUrl', 'tokenUrl', 'deviceUrl', 'revokeUrl']) {
    if (o[k] !== undefined && o[k] !== null) url(p, `oauth.${k}`, o[k]);
  }
  if (!o.tokenUrl) p.add('oauth.tokenUrl', 'is required');
  if (o.flow === 'redirect' && !o.authUrl) p.add('oauth.authUrl', 'is required for the redirect flow');
  if (o.flow === 'device' && !o.deviceUrl) p.add('oauth.deviceUrl', 'is required for the device flow');
  str(p, 'oauth.clientId', o.clientId, { max: 300 });
  if (!Array.isArray(o.scopes) || o.scopes.length > 50) p.add('oauth.scopes', 'must be an array of at most 50 scopes');
  else o.scopes.forEach((s, i) => str(p, `oauth.scopes[${i}]`, s, { max: 200 }));
  int(p, 'oauth.accessTtlMaxMinutes', o.accessTtlMaxMinutes, 1, 480);
}

/**
 * Validate and normalise a parsed site file. Returns a frozen object with the
 * defaults filled in; throws HelperError('bad_site') listing every problem.
 */
export function validateSite(raw) {
  const p = new Problems();
  const allowed = [
    'schema', 'id', 'displayName', 'type', 'kind', 'purpose', 'loginUrl', 'logoutUrl', 'allowedHosts',
    'allowedAgents', 'roles', 'maxMinutes', 'recipe', 'oauth', 'acceptNoLogout',
  ];
  if (!keys(p, 'site', raw, allowed)) throw new HelperError('bad_site', p.list.join('; '));

  if (raw.schema !== 1) p.add('schema', 'must be 1');
  str(p, 'id', raw.id, { max: 41, re: ID_RE });
  str(p, 'displayName', raw.displayName, { max: 100 });
  if (!SITE_TYPES.includes(raw.type)) p.add('type', `must be one of ${SITE_TYPES.join(', ')}`);
  if (!SITE_KINDS.includes(raw.kind)) p.add('kind', `must be one of ${SITE_KINDS.join(', ')}`);
  str(p, 'purpose', raw.purpose, { max: 200 });

  if (!Array.isArray(raw.allowedHosts) || raw.allowedHosts.length < 1 || raw.allowedHosts.length > 20) {
    p.add('allowedHosts', 'must be an array of 1..20 hosts');
  } else {
    raw.allowedHosts.forEach((h, i) => str(p, `allowedHosts[${i}]`, h, { max: 260, re: HOST_RE }));
  }
  if (!Array.isArray(raw.allowedAgents) || raw.allowedAgents.length > 200) p.add('allowedAgents', 'must be an array of agent ids');
  else raw.allowedAgents.forEach((a, i) => str(p, `allowedAgents[${i}]`, a, { max: 36, re: UUID_RE }));
  if (!Array.isArray(raw.roles) || raw.roles.length > 50) p.add('roles', 'must be an array of role names');
  else raw.roles.forEach((r, i) => str(p, `roles[${i}]`, r, { max: 60 }));
  const maxMinutes = raw.maxMinutes === undefined ? 60 : raw.maxMinutes;
  int(p, 'maxMinutes', maxMinutes, 1, 480);
  if (raw.acceptNoLogout !== undefined && typeof raw.acceptNoLogout !== 'boolean') p.add('acceptNoLogout', 'must be a boolean');

  const loginUrl = raw.loginUrl === undefined ? null : raw.loginUrl;
  const logoutUrl = raw.logoutUrl === undefined ? null : raw.logoutUrl;
  const hosts = Array.isArray(raw.allowedHosts) ? raw.allowedHosts : [];
  for (const [name, value] of [['loginUrl', loginUrl], ['logoutUrl', logoutUrl]]) {
    if (value === null) continue;
    const u = url(p, name, value);
    if (u && !urlAllowed(u, hosts)) p.add(name, 'host is not in allowedHosts');
  }

  if (raw.type === 'oauth') {
    if (raw.recipe !== undefined && raw.recipe !== null) p.add('recipe', 'must be null for an oauth site');
    if (raw.oauth === undefined || raw.oauth === null) p.add('oauth', 'is required for an oauth site');
    else oauth(p, raw.oauth);
  } else {
    if (loginUrl === null) p.add('loginUrl', 'is required');
    if (raw.oauth !== undefined && raw.oauth !== null) p.add('oauth', 'must be null unless type is oauth');
    if (raw.recipe === undefined || raw.recipe === null) p.add('recipe', 'is required');
    else recipe(p, raw.recipe, raw.type);
  }

  if (p.list.length > 0) throw new HelperError('bad_site', p.list.join('; '));

  const r = raw.recipe ?? null;
  const site = {
    schema: 1,
    id: raw.id,
    displayName: raw.displayName,
    type: raw.type,
    kind: raw.kind,
    purpose: raw.purpose,
    loginUrl,
    logoutUrl,
    allowedHosts: [...raw.allowedHosts],
    allowedAgents: [...raw.allowedAgents],
    roles: [...raw.roles],
    maxMinutes,
    acceptNoLogout: raw.acceptNoLogout === true,
    recipe: r && {
      steps: r.steps ?? [],
      successCheck: r.successCheck,
      logout: r.logout ?? null,
      challenge: r.challenge ?? null,
      trustCookies: r.trustCookies ?? [],
      trustStorageKeys: r.trustStorageKeys ?? [],
      timeoutSeconds: r.timeoutSeconds ?? 45,
    },
    oauth: raw.oauth ?? null,
  };
  return deepFreeze(structuredClone(site));
}

function deepFreeze(o) {
  if (o && typeof o === 'object') {
    for (const v of Object.values(o)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

/** Does a cookie's domain cover one of the site's allowed hosts (the domain itself or a parent of it)? */
export function cookieAllowed(cookie, site) {
  const host = cookie.domain.replace(/^\./, '');
  return site.allowedHosts.some((h) => {
    const hostname = h.replace(/:[0-9]+$/, '');
    return hostname === host || hostname.endsWith(`.${host}`);
  });
}

/** Interactive sites without recipe.logout must be acknowledged by the operator (docs/DESIGN.md section 4, Interactive sites). */
export function needsOwnerAck(site) {
  return site.type === 'interactive' && !site.recipe?.logout && !site.acceptNoLogout;
}

/**
 * Load every `<id>.json` of a directory. Invalid files are reported, never
 * fatal: one broken site must not take the helper down.
 */
export function loadSites(dir) {
  const sites = new Map();
  const errors = [];
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort();
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  for (const name of names) {
    try {
      const site = validateSite(JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')));
      if (`${site.id}.json` !== name) throw new HelperError('bad_site', `id ${site.id} does not match the file name`);
      sites.set(site.id, site);
    } catch (err) {
      errors.push({ file: name, message: err instanceof SyntaxError ? 'not valid JSON' : err.message });
    }
  }
  return { sites, errors };
}
