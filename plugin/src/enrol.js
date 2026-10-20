// Enrolment and the one-line root commands.
//
// Enrolment (design section 2; the direction is reversed compared with the hardening watchdog because vaultd cannot call the
// plugin and a webhook cannot return data, the ingredients are the same: one-time code, hash-only storage on the host,
// Ed25519 proof of possession, one active code, 60 minute lifetime):
//   1. An admin runs the action installCommand. The plugin creates its key pair if absent, a 16 character one-time code, and
//      shows a one-line root command (download, sha256 check against the pinned fingerprint, run).
//   2. The installer (root) stores only the hash of the code in /etc/vault/enrol.json and starts vaultd.
//   3. The job enrol-tick (every minute while a code is pending and the socket exists) sends type "enrol" with
//      {code, publicKey, pluginVersion}, signed with the key being enrolled. vaultd checks the proof, the code hash, the
//      expiry and single use, then answers {installId, vaultdVersion, apiVersion}. The plugin stores the install id and
//      deletes the code.
// The other actions here only build command lines for the admin to run as root; nothing secret is stored on the plugin side.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadKey, loadOrCreateKey } from "./keys.js";
import { readConfig } from "./config.js";
import { checkExposure } from "./exposure.js";
import { PLUGIN_ID } from "./manifest.js";

export const CODE_TTL_MS = 60 * 60 * 1000;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // no 0/O, 1/I/L, U
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SITE_ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const SERVICE_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const INSTALL_ID_RE = /^inst-[0-9a-f]{24}$/;
const SITE_TYPES = new Set(["password-totp", "interactive", "oauth"]);
const MAX_SITE_JSON_BYTES = 24 * 1024;
export const CODE_TTL_MINUTES = CODE_TTL_MS / 60000;

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const RELEASE_PINS_FILE = path.join(HERE, "release-pins.json");

/** Release pins written by scripts/release.sh: {version, baseUrl, installVaultSha256}. An unreleased build has none and
 *  then shows no install command. */
export function readReleasePins(file = RELEASE_PINS_FILE) {
  const none = { version: null, baseUrl: null, installVaultSha256: null };
  try {
    const p = JSON.parse(fs.readFileSync(file, "utf8"));
    const sha = (v) => (typeof v === "string" && /^[0-9a-f]{64}$/.test(v) ? v : null);
    const baseUrl = typeof p.baseUrl === "string" && /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9._~\/-]*\/$/.test(p.baseUrl) ? p.baseUrl : null;
    return { version: typeof p.version === "string" ? p.version : null, baseUrl, installVaultSha256: sha(p.installVaultSha256) };
  } catch {
    return none;
  }
}

export const normalizeCode = (code) => (typeof code === "string" ? code.toUpperCase().replace(/[^A-Z0-9]/g, "") : "");

/** 16 characters from a 30-letter alphabet (~78 bits), shown in groups of four. */
export function newCode(random = crypto.randomBytes) {
  const out = [];
  while (out.length < 16) {
    for (const b of random(32)) { if (b < 240 && out.length < 16) out.push(CODE_ALPHABET[b % 30]); }
  }
  return out.join("").replace(/(.{4})(?=.)/g, "$1-");
}

export class CommandRefused extends Error {
  constructor(message) { super(message); this.name = "CommandRefused"; this.code = "COMMAND_REFUSED"; }
}

// ---- site file schema: the same rules as host/vaultd/sites.py (and the helper): unknown keys are rejected at every level,
// so a secret field (password, totpSeed, token ...) can never ride along in the command. vault-site validates again on the host.
const SITE_KINDS = ["test", "owner", "research"];
const STEP_OPS = ["fill", "click", "press", "waitFor"];
const STEP_FROM = ["username", "password", "totp"];
const SITE_TOP_KEYS = new Set(["schema", "id", "displayName", "type", "kind", "purpose", "loginUrl", "logoutUrl", "allowedHosts", "allowedAgents", "roles", "maxMinutes", "recipe", "oauth", "acceptNoLogout"]);
const RECIPE_KEYS = new Set(["steps", "successCheck", "logout", "challenge", "trustCookies", "trustStorageKeys", "timeoutSeconds"]);
const OAUTH_KEYS = new Set(["flow", "authUrl", "tokenUrl", "deviceUrl", "revokeUrl", "clientId", "scopes", "accessTtlMaxMinutes"]);
const HOST_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$/;
const SITE_UUID_RE = /^[0-9a-f-]{36}$/;
const ABSOLUTE_MAX_MINUTES = 480;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;

function need(cond, msg) { if (!cond) throw new CommandRefused(`the site file is not valid: ${msg}`); }
function str(v, field, cap) { need(typeof v === "string" && v.length > 0 && v.length <= cap, `${field}: need a non-empty string of at most ${cap} characters`); }
function url(v, field, nullable = false) {
  if (v == null && nullable) return;
  str(v, field, 2000);
  need(/^https?:\/\/[^\s/]+/.test(v), `${field}: need an http(s) URL`);
}
function keys(d, allowed, field) {
  need(isObj(d), `${field}: need an object`);
  const extra = Object.keys(d).filter((k) => !allowed.has(k)).sort();
  need(extra.length === 0, `${field}: unknown keys ${JSON.stringify(extra)}`);
}
function list(v, field, cap = 64) { need(Array.isArray(v) && v.length <= cap, `${field}: need a list of at most ${cap} entries`); return v; }

function checkStep(s, field) {
  need(isObj(s), `${field}: need an object`);
  const ops = Object.keys(s).filter((k) => STEP_OPS.includes(k));
  need(ops.length === 1, `${field}: exactly one of ${STEP_OPS.join(", ")}`);
  keys(s, new Set([ops[0], "from", "optional", "selector"]), field);
  str(s[ops[0]], `${field}.${ops[0]}`, 500);
  need(!("selector" in s) || ops[0] === "press", `${field}: 'selector' belongs to press steps only`);
  if ("selector" in s) str(s.selector, `${field}.selector`, 500);
  need(("from" in s) === (ops[0] === "fill"), `${field}: 'from' belongs to fill steps only, and fill needs it`);
  need(!("from" in s) || STEP_FROM.includes(s.from), `${field}.from: one of ${STEP_FROM.join(", ")}`);
  need(!("optional" in s) || typeof s.optional === "boolean", `${field}.optional: need a boolean`);
}

function checkRecipe(r, field) {
  keys(r, RECIPE_KEYS, field);
  list(r.steps ?? [], `${field}.steps`, 40).forEach((s, i) => checkStep(s, `${field}.steps[${i}]`));
  if ("successCheck" in r) {
    keys(r.successCheck, new Set(["urlMatches", "selector"]), `${field}.successCheck`);
    need(Object.keys(r.successCheck).length > 0, `${field}.successCheck: need urlMatches or selector`);
    for (const [k, v] of Object.entries(r.successCheck)) str(v, `${field}.successCheck.${k}`, 500);
  }
  if ("logout" in r) {
    keys(r.logout, new Set(["steps"]), `${field}.logout`);
    list(r.logout.steps ?? [], `${field}.logout.steps`, 20).forEach((s, i) => checkStep(s, `${field}.logout.steps[${i}]`));
  }
  if ("challenge" in r) {
    keys(r.challenge, new Set(["codeSelector", "submit", "remember"]), `${field}.challenge`);
    need("codeSelector" in r.challenge && "submit" in r.challenge, `${field}.challenge: need codeSelector and submit`);
    for (const [k, v] of Object.entries(r.challenge)) str(v, `${field}.challenge.${k}`, 500);
  }
  // the regular expressions themselves are compiled by vault-site (Python syntax), here only shape and size
  for (const key of ["trustCookies", "trustStorageKeys"]) list(r[key] ?? [], `${field}.${key}`, 20).forEach((p, i) => str(p, `${field}.${key}[${i}]`, 200));
  need(!("timeoutSeconds" in r) || isInt(r.timeoutSeconds, 1, 300), `${field}.timeoutSeconds: 1..300`);
}

function checkOauth(o, field) {
  keys(o, OAUTH_KEYS, field);
  need(o.flow === "device" || o.flow === "redirect", `${field}.flow: device or redirect`);
  url(o.tokenUrl, `${field}.tokenUrl`);
  for (const k of ["authUrl", "deviceUrl", "revokeUrl"]) url(o[k], `${field}.${k}`, true);
  need(o.flow !== "redirect" || o.authUrl, `${field}.authUrl: needed for the redirect flow`);
  need(o.flow !== "device" || o.deviceUrl, `${field}.deviceUrl: needed for the device flow`);
  str(o.clientId, `${field}.clientId`, 300);
  const sc = list(o.scopes, `${field}.scopes`, 40);
  need(sc.length > 0 && sc.every((x) => typeof x === "string" && x.length > 0 && x.length <= 200 && !x.includes(" ")), `${field}.scopes: need non-empty scope names`);
  need(!("accessTtlMaxMinutes" in o) || isInt(o.accessTtlMaxMinutes, 1, ABSOLUTE_MAX_MINUTES), `${field}.accessTtlMaxMinutes: 1..${ABSOLUTE_MAX_MINUTES}`);
}

/** Throws CommandRefused naming the first problem; never changes the site. Mirrors validate() in host/vaultd/sites.py. */
export function validateSiteFile(site) {
  keys(site, SITE_TOP_KEYS, "site");
  need(site.schema === 1, "schema: must be 1");
  need(typeof site.id === "string" && SITE_ID_RE.test(site.id), "id: 1-41 characters: lowercase letters, digits and hyphens, starting with a letter or digit");
  str(site.displayName, "displayName", 80);
  need(SITE_TYPES.has(site.type), "type: one of password-totp, interactive, oauth");
  need(SITE_KINDS.includes(site.kind), `kind: one of ${SITE_KINDS.join(", ")}`);
  str(site.purpose, "purpose", 200);
  list(site.allowedHosts, "allowedHosts", 20).forEach((x) => need(typeof x === "string" && HOST_RE.test(x), "allowedHosts: need host names in lower case"));
  need(site.allowedHosts.length > 0, "allowedHosts: at least one host");
  list(site.allowedAgents, "allowedAgents", 200).forEach((x) => need(typeof x === "string" && SITE_UUID_RE.test(x), "allowedAgents: need agent UUIDs"));
  list(site.roles, "roles", 10).forEach((x) => str(x, "roles[]", 30));
  need(!("maxMinutes" in site) || isInt(site.maxMinutes, 1, ABSOLUTE_MAX_MINUTES), `maxMinutes: 1..${ABSOLUTE_MAX_MINUTES}`);
  if (site.type === "oauth") {
    need(site.oauth != null && site.recipe == null, "oauth sites need 'oauth' and no 'recipe'");
    checkOauth(site.oauth, "oauth");
    need(site.loginUrl == null && site.logoutUrl == null, "oauth sites have no loginUrl or logoutUrl");
  } else {
    need(site.oauth == null, "only oauth sites carry 'oauth'");
    url(site.loginUrl, "loginUrl");
    url(site.logoutUrl, "logoutUrl", true);
    need(isObj(site.recipe), "recipe: need an object");
    checkRecipe(site.recipe, "recipe");
    need("successCheck" in site.recipe, "recipe.successCheck is mandatory");
    need(site.type !== "password-totp" || (site.recipe.steps ?? []).length > 0, "password-totp sites need recipe.steps");
  }
  need(!("acceptNoLogout" in site) || typeof site.acceptNoLogout === "boolean", "acceptNoLogout: need a boolean");
}

const isSocket = (p) => { try { return fs.statSync(p).isSocket(); } catch { return false; } };

/**
 * @param {object} o
 * @param {object} o.ctx
 * @param {object} o.state          src/state.js
 * @param {Function} o.clientFor    (cfg) => vault client
 * @param {object} [o.pins]
 * @param {Function} [o.now]
 * @param {Function} [o.serviceUser]  () => name of the OS user the worker runs as (the service user)
 * @param {Function} [o.socketExists]
 * @param {string} [o.pluginVersion]
 */
export function createEnrol({ ctx, state, clientFor, pins = readReleasePins(), now = () => Date.now(), serviceUser = () => os.userInfo().username,
  socketExists = isSocket, pluginVersion = "0.0.0" }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };

  async function activity(companyId, message, metadata) {
    if (!companyId) { log.info(message, metadata); return; }
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  }

  const companyOf = (params, actor) => {
    const id = actor.companyId ?? params?.companyId;
    if (typeof id !== "string" || !UUID_RE.test(id)) throw new CommandRefused("a company id is needed: open this page from a company");
    return id;
  };

  function releaseScript() {
    if (!pins.baseUrl || !pins.installVaultSha256)
      throw new CommandRefused("This plugin build carries no release pins (official download URL and installer fingerprint), so it cannot show an install command. Install a released version of the plugin.");
    return { script: "install-vault.sh", url: `${pins.baseUrl}install-vault.sh`, sha: pins.installVaultSha256 };
  }

  /** A private temp dir (mode 0700): nobody else can swap the script between the fingerprint check and sudo. */
  const oneLine = ({ script, url, sha }, args) =>
    `d=$(mktemp -d) && curl -fsSL ${url} -o "$d/${script}" && echo "${sha}  $d/${script}" | sha256sum -c - && sudo bash "$d/${script}" ${args}`;

  /** Admin: create the key (if absent) and a one-time code, return the install line. */
  async function installCommand(params, context, actor) {
    const rel = releaseScript();
    const companyId = companyOf(params, actor);
    const user = serviceUser();
    if (!SERVICE_USER_RE.test(user)) throw new CommandRefused(`the worker runs as "${user}", which is not a valid service user name`);
    const cfg = await readConfig(ctx, companyId);
    const exposure = checkExposure(cfg);
    if (!exposure.ok) throw new CommandRefused(`refusing to create the key or a code: ${exposure.problems.map((p) => p.message).join('; ')}`);
    const key = loadOrCreateKey(cfg.dataDir);
    const code = newCode();
    const expiresAt = new Date(now() + CODE_TTL_MS).toISOString();
    // One active code: a new one replaces the previous (and an expired one).
    await state.setEnrol({ code, expiresAt, createdBy: actor.userId, companyId });
    await activity(companyId, `Vault: enrolment code created (valid ${CODE_TTL_MINUTES} minutes, single use)`, { userId: actor.userId, expiresAt });
    return { ok: true, command: oneLine(rel, `--service-user ${user} --company ${companyId} --enrol ${code}`), expiresAt, keyId: key.kid, version: pins.version,
      fingerprint: rel.sha, url: rel.url, ttlMinutes: CODE_TTL_MINUTES };
  }

  async function uninstallCommand(params) {
    const rel = releaseScript();
    return { ok: true, command: oneLine(rel, `--uninstall${params?.purge === true ? " --purge" : ""}`), purge: params?.purge === true, fingerprint: rel.sha, url: rel.url };
  }

  /** The Add-site form builds a site file; this only turns it into the one-line root command (vault-site validates it again). */
  async function addSiteCommand(params) {
    const site = params?.site;
    if (!isObj(site)) throw new CommandRefused("site must be an object (the site file)");
    validateSiteFile(site);      // same schema as vaultd and vault-site: unknown keys (so any secret field) are refused
    const json = JSON.stringify(site);
    if (Buffer.byteLength(json) > MAX_SITE_JSON_BYTES) throw new CommandRefused("the site file is larger than 24 KiB");
    return { ok: true, siteId: site.id, command: `sudo vault-site add --site-json-b64 ${Buffer.from(json, "utf8").toString("base64")}`, note: "Run this on the host. It asks for the login details on the terminal; nothing secret passes through Paperclip." };
  }

  async function removeSiteCommand(params) {
    const id = params?.siteId;
    if (typeof id !== "string" || !SITE_ID_RE.test(id)) throw new CommandRefused("siteId is not a valid site id");
    return { ok: true, siteId: id, command: `sudo vault-site remove ${id}${params?.keepCreds === true ? " --keep-creds" : ""}` };
  }

  /** Job enrol-tick. */
  async function tick() {
    const rec = await state.enrol();
    if (!rec?.code) return { skipped: "no_code" };
    if (!(Date.parse(rec.expiresAt) > now())) { await state.clearEnrol(); return { skipped: "expired" }; }
    const cfg = await readConfig(ctx, rec.companyId);
    if (!checkExposure(cfg).ok) return { skipped: "exposed" };
    if (!socketExists(cfg.socketPath)) return { skipped: "no_socket" };
    const key = loadKey(cfg.dataDir);
    if (!key) { await state.clearEnrol(); return { skipped: "no_key" }; }
    let res;
    try {
      res = await clientFor(cfg).enrol({ code: rec.code, publicKey: key.publicKeyB64, pluginVersion });
    } catch (e) {
      // Not-yet-ready or refused: keep the code until it expires; the admin sees the last error on the Install tab.
      await state.setEnrol({ ...rec, lastError: { code: e.code ?? "error", message: String(e.message).slice(0, 200), at: new Date(now()).toISOString() } });
      return { skipped: "refused", code: e.code };
    }
    if (typeof res?.installId !== "string" || !INSTALL_ID_RE.test(res.installId)) {
      await state.setEnrol({ ...rec, lastError: { code: "protocol", message: "vaultd answered without a valid install id", at: new Date(now()).toISOString() } });
      return { skipped: "bad_answer" };
    }
    await state.setInstall({ installId: res.installId, vaultdVersion: String(res.vaultdVersion ?? ""), apiVersion: res.apiVersion ?? 1, enrolledAt: new Date(now()).toISOString(), kid: key.kid });
    await state.clearEnrol();
    await activity(rec.companyId, "Vault: enrolled with vaultd", { installId: res.installId, vaultdVersion: res.vaultdVersion });
    return { enrolled: true };
  }

  /** Action vaultStatus: enrolment state plus a live hello. No secrets. */
  async function status(context, actor) {
    const install = await state.install();
    const enrol = await state.enrol();
    const companyId = actor.companyId ?? context?.companyId ?? enrol?.companyId ?? null;
    const cfg = await readConfig(ctx, companyId);
    const exposure = checkExposure(cfg);
    const out = {
      enrolled: Boolean(install), installId: install?.installId ?? null, enrolledAt: install?.enrolledAt ?? null,
      pendingEnrol: enrol?.code ? { expiresAt: enrol.expiresAt, lastError: enrol.lastError ?? null } : null,
      socketPath: cfg.socketPath, socketPresent: socketExists(cfg.socketPath), releaseBuild: Boolean(pins.baseUrl && pins.installVaultSha256),
      codeTtlMinutes: CODE_TTL_MINUTES, yourUserId: actor.userId, vaultd: { reachable: false }, exposure,
      error: exposure.ok ? null : `The plugin refuses to operate: ${exposure.problems.map((p) => p.message).join('; ')}.${exposure.problems.some((p) => p.code !== "not_configured") ? " Move the key directory or the socket out of the agents' reach." : ""}`,
      configure: exposure.problems.filter((p) => p.code === "not_configured").map((p) => p.what),
    };
    if (install && exposure.ok) {
      try {
        const hello = await clientFor(cfg).call("hello", {});
        out.vaultd = { reachable: true, version: hello.vaultdVersion ?? null, helper: hello.helper ?? null, time: hello.time ?? null };
      } catch (e) {
        out.vaultd = { reachable: false, code: e.code ?? "error" };
      }
    }
    return out;
  }

  return { installCommand, uninstallCommand, addSiteCommand, removeSiteCommand, tick, status };
}
