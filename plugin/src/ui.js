// Plain ESM (no build step); `react` and `@paperclipai/plugin-sdk/ui` are host-provided externals, so this file imports
// nothing else.
//
// The Vault page (route `vault`), one tab per job:
//   Install       enrolment status, the one-line install command with its fingerprint and expiry, the uninstall command
//   Sites         the registered sites and their state, the Add-site form (it only BUILDS a `sudo vault-site add ...` command),
//                 and the remove / test / authorize / interactive one-liners per site
//   Ceilings      read-only: agent pins, roles -> classes, never-list, maxima, and the root command that edits them
//   Decision log  what the reviewing model and vaultd decided, newest first, paged
//   Leases        active leases, with Revoke for admins
//   Gatekeeper    provider status, models, judge tests, model selection
//
// Every read and write is a plugin action (the only plugin calls that carry the caller's identity). The page never asks for,
// holds or sends a password, one-time-code seed or other secret: secrets are typed on the host's terminal. The worker checks
// every write again (admin only); the page only hides or disables what the caller may not do and says why.
import React from "react";
import { usePluginAction, copyTextToClipboard, StatusBadge, DataTable } from "@paperclipai/plugin-sdk/ui";
const h = React.createElement;
const { useState, useEffect } = React;

// ------------------------------------------------------------------------------------------------ pure helpers (tested)

export const SITE_TYPES = Object.freeze([
  { value: "password-totp", label: "Website login (username, password, optional one-time code)" },
  { value: "interactive", label: "Website that blocks automatic logins (a person logs in once)" },
  { value: "oauth", label: "OAuth access token" },
]);
export const SITE_KINDS = Object.freeze([
  { value: "test", label: "Test account" },
  { value: "research", label: "Research account" },
  { value: "owner", label: "Owner's own account" },
]);

/** Every key a site file may carry (docs/DESIGN.md section 5, as vaultd's and the helper's schema accept them). buildSiteFile emits nothing else. */
export const SITE_FILE_KEYS = Object.freeze(["schema", "id", "displayName", "type", "kind", "purpose", "loginUrl", "logoutUrl", "allowedHosts", "allowedAgents", "roles", "maxMinutes", "recipe", "oauth"]);
export const RECIPE_KEYS = Object.freeze(["steps", "successCheck", "logout", "timeoutSeconds"]);
export const OAUTH_KEYS = Object.freeze(["flow", "authUrl", "tokenUrl", "deviceUrl", "revokeUrl", "clientId", "scopes", "accessTtlMaxMinutes"]);

const SITE_ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOST_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$/;
const URL_RE = /^https?:\/\/[^\s/]+/;
const MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$/;
const MAX_MINUTES = 480;

/** One entry per non-empty line or comma-separated item. */
export const listItems = (text) => (typeof text === "string" ? text.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean) : Array.isArray(text) ? text.map((x) => String(x).trim()).filter(Boolean) : []);
const scopeItems = (text) => (typeof text === "string" ? text.split(/[\s,]+/).filter(Boolean) : listItems(text));
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const hostOf = (url) => { try { return new URL(url).host.toLowerCase(); } catch { return null; } };
const str = (v) => (typeof v === "string" ? v.trim() : "");

export function emptySiteForm(type = "password-totp") {
  return {
    type, id: "", displayName: "", kind: "test", purpose: "", loginUrl: "", logoutUrl: "", allowedHosts: "", allowedAgents: [], roles: "", maxMinutes: "60",
    usernameSelector: "", nextSelector: "", passwordSelector: "", submitSelector: "", totpSelector: "", totpSubmitSelector: "",
    successUrl: "", successSelector: "", logoutSelector: "",
    flow: "device", authUrl: "", tokenUrl: "", deviceUrl: "", revokeUrl: "", clientId: "", scopes: "", accessTtlMaxMinutes: "",
  };
}

/**
 * The Add-site form -> a site file (docs/DESIGN.md section 5). Pure: no I/O. Only the fields below are ever copied from the form, so no
 * password, one-time-code seed, client secret or token can end up in the result, whatever the form object carries. The
 * terminal command (`vault-site add`) asks for those on the host and validates the file again.
 * @returns {{site: object|null, errors: Record<string, string>}}  site is null while there are errors
 */
export function buildSiteFile(form) {
  const f = form && typeof form === "object" ? form : {};
  const errors = {};
  const need = (field, ok, message) => { if (!ok && !errors[field]) errors[field] = message; };
  const type = SITE_TYPES.some((t) => t.value === f.type) ? f.type : null;
  need("type", type, "Choose what kind of site this is.");
  const id = str(f.id);
  need("id", SITE_ID_RE.test(id), "Use 1 to 41 lowercase letters, digits or hyphens, starting with a letter or digit (for example example-admin).");
  const displayName = str(f.displayName);
  need("displayName", displayName.length >= 1 && displayName.length <= 80, "Give the site a name of at most 80 characters.");
  const kind = SITE_KINDS.some((k) => k.value === f.kind) ? f.kind : null;
  need("kind", kind, "Choose whose account this is.");
  const purpose = str(f.purpose);
  need("purpose", purpose.length >= 1 && purpose.length <= 200, "Say in one line (at most 200 characters) what agents use this site for. The reviewing model reads it.");
  const oauth = type === "oauth";

  const loginUrl = oauth ? null : str(f.loginUrl);
  if (!oauth) need("loginUrl", URL_RE.test(loginUrl ?? ""), "Enter the full login page address, starting with https://");
  const logoutRaw = oauth ? "" : str(f.logoutUrl);
  if (logoutRaw) need("logoutUrl", URL_RE.test(logoutRaw), "Enter the full address, starting with https://, or leave it empty.");

  let hosts = listItems(f.allowedHosts).map((x) => x.toLowerCase());
  if (!hosts.length) {
    const urls = oauth ? [f.authUrl, f.tokenUrl, f.deviceUrl, f.revokeUrl] : [f.loginUrl];
    hosts = [...new Set(urls.map((u) => hostOf(str(u))).filter(Boolean))];
  }
  need("allowedHosts", hosts.length > 0 && hosts.length <= 20 && hosts.every((x) => HOST_RE.test(x)), "List the website host names the login may visit, lowercase (for example app.example.org).");

  const allowedAgents = [...new Set(listItems(f.allowedAgents))];
  need("allowedAgents", allowedAgents.every((a) => UUID_RE.test(a)), "Agents are chosen from the list; ids must be UUIDs.");
  const roles = listItems(f.roles);
  need("roles", roles.length <= 10 && roles.every((r) => r.length <= 30), "At most 10 roles of at most 30 characters each.");
  const maxText = str(String(f.maxMinutes ?? ""));
  const maxMinutes = maxText === "" ? 60 : Number(maxText);
  need("maxMinutes", Number.isInteger(maxMinutes) && maxMinutes >= 1 && maxMinutes <= MAX_MINUTES, `Whole minutes from 1 to ${MAX_MINUTES}.`);

  let recipe = null;
  let oauthBlock = null;
  if (oauth) {
    const flow = f.flow === "redirect" ? "redirect" : f.flow === "device" ? "device" : null;
    need("flow", flow, "Choose device or redirect.");
    const urlField = (field, value, required, label) => {
      const v = str(value);
      if (!v) { need(field, !required, `${label} is needed.`); return null; }
      need(field, URL_RE.test(v), `${label} must be a full address starting with https://`);
      return v;
    };
    const authUrl = urlField("authUrl", f.authUrl, true, "The authorization address");
    const tokenUrl = urlField("tokenUrl", f.tokenUrl, true, "The token address");
    const deviceUrl = urlField("deviceUrl", f.deviceUrl, flow === "device", "The device-code address");
    const revokeUrl = urlField("revokeUrl", f.revokeUrl, false, "The revoke address");
    const clientId = str(f.clientId);
    need("clientId", clientId.length >= 1 && clientId.length <= 300, "The client id is needed (it is not a secret; a client secret, if any, is typed on the host).");
    const scopes = scopeItems(f.scopes);
    need("scopes", scopes.length >= 1 && scopes.length <= 40 && scopes.every((s) => s.length <= 200), "List at least one scope, separated by spaces or commas.");
    const ttlText = str(String(f.accessTtlMaxMinutes ?? ""));
    const ttl = ttlText === "" ? MAX_MINUTES : Number(ttlText);
    need("accessTtlMaxMinutes", Number.isInteger(ttl) && ttl >= 1 && ttl <= MAX_MINUTES, `Whole minutes from 1 to ${MAX_MINUTES}, or leave it empty.`);
    oauthBlock = { flow, authUrl, tokenUrl, deviceUrl, revokeUrl, clientId, scopes, accessTtlMaxMinutes: ttl };
  } else {
    const steps = [];
    const sel = (field, label, required) => {
      const v = str(f[field]);
      need(field, !required || v.length > 0, `${label} is needed.`);
      need(field, v.length <= 500, "At most 500 characters.");
      return v;
    };
    if (type === "password-totp") {
      const user = sel("usernameSelector", "The username field", true);
      const next = sel("nextSelector", "", false);
      const pass = sel("passwordSelector", "The password field", true);
      const submit = sel("submitSelector", "The login button", true);
      const totp = sel("totpSelector", "", false);
      const totpSubmit = sel("totpSubmitSelector", "", false);
      steps.push({ fill: user, from: "username" });
      if (next) steps.push({ click: next });
      steps.push({ fill: pass, from: "password" }, { click: submit });
      if (totp) steps.push({ fill: totp, from: "totp", optional: true });
      if (totpSubmit) steps.push({ click: totpSubmit, optional: true });
    }
    const successUrl = str(f.successUrl);
    const successSelector = sel("successSelector", "", false);
    need("successUrl", successUrl || successSelector, "Say how to tell that the login worked: the address of the page shown afterwards or an element on it.");
    if (successUrl) need("successUrl", URL_RE.test(successUrl), "Enter the full address, starting with https://");
    const successCheck = {};
    if (successUrl) successCheck.urlMatches = `^${escapeRegExp(successUrl)}`;
    if (successSelector) successCheck.selector = successSelector;
    recipe = { steps, successCheck };
    const logoutSelector = sel("logoutSelector", "", false);
    if (logoutSelector) recipe.logout = { steps: [{ click: logoutSelector }] };
    recipe.timeoutSeconds = 45;
  }
  if (Object.keys(errors).length) return { site: null, errors };
  return {
    errors,
    site: {
      schema: 1, id, displayName, type, kind, purpose,
      loginUrl: oauth ? null : loginUrl, logoutUrl: oauth ? null : logoutRaw || null,
      allowedHosts: hosts, allowedAgents, roles, maxMinutes,
      recipe, oauth: oauthBlock,
    },
  };
}

/** One-line commands for a site, built here because they carry nothing but the (validated) site id. */
export function siteCommands(site) {
  const id = site?.id;
  if (typeof id !== "string" || !SITE_ID_RE.test(id)) return [];
  const out = [{ key: "test", label: "Test the login", description: "Logs in once and reports whether it worked.", command: `sudo vault-site test ${id}` }];
  if (site.type === "oauth") out.push({
    key: "authorize", label: "Authorize", description: "Connects the account. Follow the instructions the command prints (a code to approve on your own device, or an ssh tunnel for the redirect flow).",
    command: `sudo vault-site authorize ${id}`,
  });
  if (site.type === "interactive") out.push({
    key: "interactive", label: "Log in by hand", description: "Opens the site in a browser you reach through an ssh tunnel (the command prints how); you log in yourself, second factor included.",
    command: `sudo vault-site interactive ${id}`,
  });
  return out;
}

/** The root command that edits the ceilings; vaultd reads the policy at start. */
export const POLICY_EDIT_COMMAND = "sudoedit /etc/vault/policy.json && sudo systemctl restart vaultd";
export const unlockCommand = (agentId) => (UUID_RE.test(String(agentId)) ? `sudo vaultctl unlock ${agentId}` : null);

/** "60 minutes" / "1 minute" from the lifetime the worker reports (enrol.js CODE_TTL_MS); never hard-coded here. */
export const minutesText = (n) => (Number.isFinite(n) && n > 0 ? `${n} minute${n === 1 ? "" : "s"}` : "a limited time");

/** "2026-10-19T08:15:30.123Z" -> "2026-10-19 08:15:30 UTC" (the same text for everyone). */
export const formatTime = (iso) => (typeof iso === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/.test(iso) ? `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC` : "-");

export function minutesLeft(expiresAt, nowMs = Date.now()) {
  const t = Date.parse(expiresAt ?? "");
  return Number.isFinite(t) ? Math.max(0, Math.ceil((t - nowMs) / 60_000)) : null;
}

export const shortId = (id) => (typeof id === "string" && id.length > 8 ? id.slice(0, 8) : id ?? "-");

const SITE_STATES = {
  ready: { label: "ready", tone: "ok", hint: "" },
  needs_authorize: { label: "needs authorizing", tone: "warning", hint: "Run the Authorize command for this site." },
  needs_interactive: { label: "needs a manual login", tone: "warning", hint: "Run the Log in by hand command for this site." },
  missing_credential: { label: "login details missing", tone: "error", hint: "Run the Add command again for this site, or remove it and add it again." },
};
export const siteState = (state) => SITE_STATES[state] ?? { label: String(state ?? "unknown"), tone: "info", hint: "" };

const DECISIONS = { approve: { label: "approved", tone: "ok" }, deny: { label: "denied", tone: "warning" }, failed: { label: "failed", tone: "error" } };
const CODE_TEXT = {
  judge_deny: "the reviewing model said no", judge_lock: "the reviewing model locked the agent", agent_locked: "agent is locked", agent_unpinned: "agent is not pinned in the ceilings",
  company_not_allowed: "company not allowed", bad_target: "no such site or item", never_list: "on the never-list", role_class: "the role may not use this kind of access",
  site_agent_not_allowed: "the site does not list this agent", minutes_over_max: "more minutes than the maximum", minutes_missing: "no minutes given", minutes_zero: "the reviewer left no minutes",
  site_not_ready: "the site is not ready", no_verdict: "no verdict in time", model_not_cleared: "the model has not passed the judge tests", prompt_mismatch: "the review prompt did not match",
  aggregate_mismatch: "the verdict did not add up", bad_verdict: "the verdict was malformed", provider_error: "the model provider failed", rate_limited: "too many requests",
  helper_error: "the login helper failed", login_failed: "the login failed", delivery_failed: "the file could not be delivered", revoked: "revoked by an admin",
};
export const codeText = (code) => (code ? CODE_TEXT[code] ?? code : "");

/** A decision-log entry from vaultd (log.read) -> the cells shown. */
export function logRow(e) {
  const d = DECISIONS[e?.decision] ?? { label: String(e?.decision ?? "?"), tone: "info" };
  const raw = Array.isArray(e?.raw) ? e.raw : [];
  return {
    id: e?.hash ?? `seq-${e?.seq}`, seq: e?.seq ?? null, time: formatTime(e?.time),
    agent: `${e?.role ?? "agent"} ${shortId(e?.agentId)}`, agentId: e?.agentId ?? null, target: e?.target ?? "-",
    minutes: Number.isInteger(e?.minutes) ? `${e.minutes}${Number.isInteger(e?.requestedMinutes) ? ` of ${e.requestedMinutes}` : ""}` : Number.isInteger(e?.requestedMinutes) ? `0 of ${e.requestedMinutes}` : "-",
    decision: d, code: e?.code ?? "", model: e?.model || "-", provider: e?.provider || "-",
    raw: raw.map((r) => ({ decision: String(r?.decision ?? "?"), reason: typeof r?.reason === "string" ? r.reason : "", parseFailed: Boolean(r?.parseFailed) })),
    hash: typeof e?.hash === "string" ? e.hash : "",
  };
}

const GATE_TEXT = {
  no_model: "No model is selected yet. Run the judge tests for a model, then select it. Until then every request is denied.",
  provider_not_configured: "The provider is not set up. Open this plugin's settings and fill in the Gatekeeper base URL (and API key). Until then every request is denied.",
  provider_changed: "The provider changed since the model was selected. Select a model again.",
  no_record: "The selected model has no judge-test result. Run the judge tests again.",
  not_clean: "The selected model did not pass the judge tests. Select another model.",
  stale_hashes: "The review prompt, the test scenarios or the number of samples (k) changed since the last judge tests. Run them again.",
  vaultd_unreachable: "vaultd could not be reached, so the gate cannot be checked.",
};
export const gateText = (reason) => GATE_TEXT[reason] ?? `Not cleared (${reason ?? "unknown"}).`;

/**
 * Models shown on the Gatekeeper tab: the provider's list (filtered), every model with a test record, and a typed-in id.
 * `select` is allowed only for a model with a clean record that matches the current prompt, scenarios and k.
 */
export function modelRows({ models = [], records = [], selected = null, filter = "", limit = 50 } = {}) {
  const byModel = new Map();
  for (const r of records) { const prev = byModel.get(r.model); if (!prev || (r.current && !prev.current) || (r.current === prev.current && String(r.at) > String(prev.at))) byModel.set(r.model, r); }
  const ids = new Set();
  const q = str(filter).toLowerCase();
  const listed = models.map((m) => (typeof m === "string" ? m : m?.id)).filter((x) => typeof x === "string");
  for (const id of listed) if (!q || id.toLowerCase().includes(q)) ids.add(id);
  for (const id of byModel.keys()) ids.add(id);
  if (selected?.model) ids.add(selected.model);
  if (q && MODEL_ID_RE.test(str(filter))) ids.add(str(filter));
  const rows = [...ids].map((id) => {
    const rec = byModel.get(id) ?? null;
    const result = !rec ? { label: "not tested", tone: "info" } : !rec.clean ? { label: "did not pass", tone: "error" } : !rec.current ? { label: "passed, but outdated", tone: "warning" } : { label: "passed", tone: "ok" };
    const canSelect = Boolean(rec?.clean && rec.current);
    return { id, record: rec, result, canSelect, isSelected: selected?.model === id,
      whyNot: canSelect ? "" : !rec ? "Run the judge tests for this model first." : !rec.clean ? "This model did not pass the judge tests." : "The prompt, scenarios or k changed since this model passed. Run the judge tests again." };
  });
  rows.sort((a, b) => Number(b.isSelected) - Number(a.isSelected) || Number(Boolean(b.record)) - Number(Boolean(a.record)) || a.id.localeCompare(b.id));
  return { rows: rows.slice(0, limit), total: rows.length };
}

export function metricsText(m, thresholds) {
  if (!m) return "";
  const t = thresholds ?? {};
  const ok = (good) => (good ? "ok" : "FAILS");
  return [
    `injection requests granted: ${m.injection_granted} (must be ${t.injection_granted ?? 0}) ${ok(m.injection_granted <= (t.injection_granted ?? 0))}`,
    `over-grants: ${m.over_grants} (must be ${t.over_grants ?? 0}) ${ok(m.over_grants <= (t.over_grants ?? 0))}`,
    `stability: ${m.stability} (at least ${t.stability ?? 0.95}) ${ok(m.stability >= (t.stability ?? 0.95))}`,
    `unparseable answers: ${m.parse_failures_pct}% (at most ${t.parse_failures_pct ?? 1}%) ${ok(m.parse_failures_pct <= (t.parse_failures_pct ?? 1))}`,
  ];
}

const errText = (e) => (e && e.message) || String(e);

// ------------------------------------------------------------------------------------------------ small components

const box = { border: "1px solid rgba(127,127,127,0.3)", borderRadius: 8, padding: 12 };
const muted = { opacity: 0.7, fontSize: "0.9em" };
const row = { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" };
const grid = { display: "grid", gap: 10 };
const mono = { fontFamily: "monospace" };

function Notice({ tone = "info", children }) {
  return h(StatusBadge, { label: typeof children === "string" ? children : String(children), status: tone });
}

/** A read action loaded on mount and whenever its params change; polls while `pollWhen(data)` is true. */
function useRead(key, params, { pollWhen = null, everyMs = 3000 } = {}) {
  const call = usePluginAction(key);
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const p = JSON.stringify(params ?? {});
  const run = () => call(JSON.parse(p)).then(
    (data) => setState({ loading: false, data, error: null }),
    (error) => setState((prev) => ({ ...prev, loading: false, error })));
  const polling = Boolean(pollWhen && state.data && pollWhen(state.data));
  useEffect(() => {
    run();
    return undefined;
  }, [p]);
  useEffect(() => {
    if (!polling) return undefined;
    const t = setInterval(run, everyMs);
    return () => clearInterval(t);
  }, [p, polling]);
  return { ...state, refresh: run };
}

/** A write (or any action) with a busy flag and a plain error message. */
function useDo() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run = async (fn) => {
    setBusy(true); setError("");
    try { return await fn(); } catch (e) { setError(errText(e)); return undefined; } finally { setBusy(false); }
  };
  return { busy, error, run, clear: () => setError("") };
}

function CommandBox({ command, label, note }) {
  const [copied, setCopied] = useState("");
  const copy = async () => {
    try { await copyTextToClipboard(command); setCopied("Copied."); } catch { setCopied("Could not copy: select the text and copy it by hand."); }
  };
  return h("div", { style: { display: "grid", gap: 4 } },
    label ? h("strong", null, label) : null,
    h("pre", { style: { ...mono, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, padding: 8, border: "1px solid rgba(127,127,127,0.3)", borderRadius: 6, maxHeight: 220, overflow: "auto" } }, command),
    h("div", { style: row }, h("button", { type: "button", onClick: copy }, "Copy"), copied ? h("span", { style: muted }, copied) : null),
    note ? h("span", { style: muted }, note) : null);
}

function Field({ label, hint, error, children }) {
  return h("label", { style: { display: "grid", gap: 2 } },
    h("span", null, h("b", null, label)),
    hint ? h("span", { style: muted }, hint) : null,
    children,
    error ? h("span", { role: "alert", style: { color: "var(--destructive, #c0392b)" } }, error) : null);
}

function Section({ title, children }) {
  return h("section", { style: { ...box, ...grid } }, h("h3", { style: { margin: 0 } }, title), children);
}

const Loading = ({ what }) => h("p", null, `Loading ${what}...`);
const ReadError = ({ error, retry }) => h("div", { style: row }, h(Notice, { tone: "error" }, errText(error)), retry ? h("button", { type: "button", onClick: retry }, "Try again") : null);

// ------------------------------------------------------------------------------------------------ Install

function InstallTab({ companyId, status, canEdit, reason }) {
  const install = usePluginAction("installCommand");
  const uninstall = usePluginAction("uninstallCommand");
  const mk = useDo();
  const rm = useDo();
  const [created, setCreated] = useState(null);
  const [removal, setRemoval] = useState(null);
  const [purge, setPurge] = useState(false);
  const s = status.data;

  let badge;
  if (s.error) badge = h(Notice, { tone: "error" }, s.error);
  else if (s.enrolled && s.vaultd?.reachable) badge = h(Notice, { tone: "ok" }, `Connected to vaultd${s.vaultd.version ? ` ${s.vaultd.version}` : ""}; the login helper is ${s.vaultd.helper ?? "unknown"}.`);
  else if (s.enrolled) badge = h(Notice, { tone: "error" }, `Installed, but vaultd does not answer (${s.vaultd?.code ?? "no answer"}). Check that the vaultd service is running on the host.`);
  else if (s.pendingEnrol) badge = h(Notice, { tone: "pending" }, `Waiting for the install command to be run on the host (code valid until ${formatTime(s.pendingEnrol.expiresAt)}).`);
  else badge = h(Notice, { tone: "info" }, "Not installed on the host yet. Create the install command below and run it there.");

  const create = () => mk.run(async () => { setCreated(await install({ companyId })); status.refresh(); });
  const showRemoval = () => rm.run(async () => { setRemoval(await uninstall({ companyId, purge })); });
  const made = created?.ok ? created : null;      // the worker returns command, fingerprint, url, ttlMinutes, expiresAt, version
  const gone = removal?.ok ? removal : null;

  return h("div", { style: grid },
    h("div", { style: row }, badge),
    s.configure?.length ? h("p", null, `To finish: open this plugin's settings and set ${s.configure.map((x) => (x === "workspaceRoots" ? "Workspace roots (the folder(s) that hold your agents' workspaces)" : x)).join(", ")}.`) : null,
    s.pendingEnrol?.lastError ? h(Notice, { tone: "warning" }, `The last enrolment attempt failed: ${s.pendingEnrol.lastError.message} (${formatTime(s.pendingEnrol.lastError.at)}).`) : null,
    h(Section, { title: s.enrolled ? "Reconnect or reinstall" : "Install on the host" },
      !s.releaseBuild ? h(Notice, { tone: "warning" }, "This build of the plugin has no official download address and fingerprint, so it cannot show an install command. Install a released version of the plugin.") : null,
      h("p", { style: { margin: 0 } }, `The command downloads the installer, checks it against the fingerprint shown here, then runs it with sudo. Run it on the Paperclip host as an admin. The one-time code in it works once and for ${minutesText(s.codeTtlMinutes)}.`),
      h("div", { style: row }, h("button", { type: "button", disabled: !canEdit || !s.releaseBuild || mk.busy || Boolean(s.error), title: canEdit ? "" : reason, onClick: create }, s.enrolled ? "Create a new install command" : "Create install command"),
        !canEdit ? h("span", { style: muted }, reason) : null),
      mk.error ? h(Notice, { tone: "error" }, mk.error) : null,
      made ? h("div", { style: grid },
        h(CommandBox, { command: made.command, label: "Run this on the host" }),
        h("div", { style: { ...muted, display: "grid", gap: 2 } },
          h("span", null, `Installer fingerprint (sha256): ${made.fingerprint ?? "unknown"}`),
          made.url ? h("span", null, `Downloaded from: ${made.url}`) : null,
          h("span", null, `Valid until ${formatTime(made.expiresAt)} (${minutesText(made.ttlMinutes)}, single use). Plugin version ${made.version ?? "?"}. The page updates by itself when the host has connected.`))) : null),
    h(Section, { title: "Uninstall from the host" },
      h("p", { style: { margin: 0 } }, "Removes the vault services from the host. Stored logins and the audit log stay unless you also delete them."),
      h("label", { style: row }, h("input", { type: "checkbox", checked: purge, disabled: !canEdit, onChange: (e) => { setPurge(e.target.checked); setRemoval(null); } }), "Also delete stored logins and the audit log (cannot be undone)"),
      h("div", { style: row }, h("button", { type: "button", disabled: !canEdit || !s.releaseBuild || rm.busy, title: canEdit ? "" : reason, onClick: showRemoval }, "Show uninstall command")),
      rm.error ? h(Notice, { tone: "error" }, rm.error) : null,
      gone ? h(CommandBox, { command: gone.command, label: "Run this on the host", note: `Fingerprint (sha256): ${gone.fingerprint ?? "unknown"}. The plugin can then be removed in Paperclip.` }) : null),
    h("p", { style: muted }, `Socket: ${s.socketPath}${s.socketPresent ? "" : " (not found)"}. Your user id: ${s.yourUserId ?? "unknown"}.`));
}

// ------------------------------------------------------------------------------------------------ Sites

function SiteForm({ companyId, ceilings, onDone }) {
  const build = usePluginAction("addSiteCommand");
  const act = useDo();
  const [f, setF] = useState(() => emptySiteForm());
  const [errors, setErrors] = useState({});
  const [result, setResult] = useState(null);
  const set = (k) => (e) => { setF({ ...f, [k]: e.target.value }); setResult(null); };
  const agents = Object.entries(ceilings?.agents ?? {});
  const input = (k, label, hint, props = {}) => h(Field, { label, hint, error: errors[k] }, h("input", { type: "text", value: f[k], onChange: set(k), "aria-label": label, style: props.mono ? mono : undefined, placeholder: props.placeholder }));
  const select = (k, label, options, hint) => h(Field, { label, hint, error: errors[k] }, h("select", { value: f[k], onChange: set(k), "aria-label": label }, options.map((o) => h("option", { key: o.value, value: o.value }, o.label))));
  const oauth = f.type === "oauth";
  const selectors = f.type === "password-totp";

  const submit = () => act.run(async () => {
    const built = buildSiteFile(f);
    setErrors(built.errors);
    if (!built.site) { setResult(null); return; }
    setResult(await build({ companyId, site: built.site }));
  });
  const toggleAgent = (id, on) => { setF({ ...f, allowedAgents: on ? [...f.allowedAgents, id] : f.allowedAgents.filter((x) => x !== id) }); setResult(null); };

  return h("div", { style: grid },
    h("p", { style: { margin: 0 } }, "Describe the site here. This page never asks for a password, one-time-code seed or any other secret: the command below asks for them on the host's terminal."),
    select("type", "Kind of site", SITE_TYPES, undefined),
    input("id", "Short name (id)", "Lowercase letters, digits and hyphens. Agents use it to ask for the site.", { mono: true, placeholder: "example-admin" }),
    input("displayName", "Display name", "", { placeholder: "Example admin" }),
    select("kind", "Whose account", SITE_KINDS, undefined),
    input("purpose", "What agents use it for", "One line. The reviewing model reads it as trusted text."),
    oauth ? null : input("loginUrl", "Login page address", "Starts with https://", { mono: true, placeholder: "https://app.example.org/login" }),
    oauth ? null : input("logoutUrl", "Log-out address (optional)", "", { mono: true }),
    h(Field, { label: "Hosts the login may visit", hint: "One per line. Empty: the host of the address above.", error: errors.allowedHosts }, h("textarea", { rows: 2, value: f.allowedHosts, onChange: set("allowedHosts"), "aria-label": "Hosts the login may visit", style: mono })),
    h(Field, { label: "Agents that may use it", hint: agents.length ? "Only checked agents can ask for this site." : "No agents are pinned yet. Pin agents in the ceilings (Ceilings tab); until then nobody can use the site.", error: errors.allowedAgents },
      agents.length ? h("div", { style: grid }, agents.map(([id, role]) => h("label", { key: id, style: row }, h("input", { type: "checkbox", checked: f.allowedAgents.includes(id), onChange: (e) => toggleAgent(id, e.target.checked) }), `${role} (${shortId(id)})`))) : null),
    input("roles", "Roles that use it (shown to the reviewer)", "Comma separated, for example QA, UI Tester."),
    input("maxMinutes", "Longest session in minutes", `1 to ${MAX_MINUTES}. Default 60.`),
    selectors ? h("div", { style: grid },
      h("strong", null, "Login steps (CSS selectors of the page elements)"),
      input("usernameSelector", "Username field", "", { mono: true, placeholder: "#email" }),
      input("nextSelector", "Button between username and password (optional)", "For logins in two steps.", { mono: true }),
      input("passwordSelector", "Password field", "", { mono: true, placeholder: "#password" }),
      input("submitSelector", "Login button", "", { mono: true, placeholder: "#login" }),
      input("totpSelector", "One-time-code field (optional)", "Leave empty if the site has no one-time code.", { mono: true }),
      input("totpSubmitSelector", "One-time-code button (optional)", "", { mono: true })) : null,
    oauth ? h("div", { style: grid },
      h("strong", null, "OAuth settings"),
      select("flow", "Flow", [{ value: "device", label: "Device code (approve on your own device)" }, { value: "redirect", label: "Redirect (through an ssh tunnel)" }], undefined),
      input("authUrl", "Authorization address", "", { mono: true }),
      input("tokenUrl", "Token address", "", { mono: true }),
      f.flow === "device" ? input("deviceUrl", "Device-code address", "", { mono: true }) : null,
      input("revokeUrl", "Revoke address (optional)", "", { mono: true }),
      input("clientId", "Client id", "Not a secret. A client secret, if the provider has one, is typed on the host.", { mono: true }),
      input("scopes", "Scopes", "Separated by spaces or commas."),
      input("accessTtlMaxMinutes", "Longest token life in minutes (optional)", "")) : h("div", { style: grid },
      h("strong", null, "How to tell the login worked"),
      input("successUrl", "Page shown after login (address starts with)", "", { mono: true, placeholder: "https://app.example.org/dashboard" }),
      input("successSelector", "Or an element on that page (optional)", "", { mono: true, placeholder: "#avatar" }),
      input("logoutSelector", "Log-out button (optional)", "Clicked to end the session when the time is up.", { mono: true })),
    h("div", { style: row }, h("button", { type: "button", disabled: act.busy, onClick: submit }, "Build the command"), onDone ? h("button", { type: "button", onClick: onDone }, "Close") : null),
    act.error ? h(Notice, { tone: "error" }, act.error) : null,
    Object.keys(errors).length ? h(Notice, { tone: "warning" }, "Some fields need a look; they are marked above.") : null,
    result?.ok ? h("div", { style: grid },
      h(CommandBox, { command: result.command, label: `Run this on the host to add ${result.siteId}`, note: result.note }),
      h("span", { style: muted }, "If the site has no one-time code, add --no-totp at the end of the command. When it finishes, this page shows the site.")) : null);
}

function SiteRow({ site, canEdit, reason, companyId }) {
  const remove = usePluginAction("removeSiteCommand");
  const act = useDo();
  const [removal, setRemoval] = useState(null);
  const [keep, setKeep] = useState(false);
  const cmds = siteCommands(site);
  return h("div", { style: { display: "grid", gap: 8, paddingTop: 8 } },
    h("p", { style: { margin: 0 } }, site.purpose),
    siteState(site.state).hint ? h(Notice, { tone: siteState(site.state).tone }, siteState(site.state).hint) : null,
    !canEdit ? h("span", { style: muted }, reason) : null,
    canEdit ? cmds.map((c) => h("div", { key: c.key }, h(CommandBox, { command: c.command, label: c.label, note: c.description }))) : null,
    canEdit ? h("div", { style: grid },
      h("label", { style: row }, h("input", { type: "checkbox", checked: keep, onChange: (e) => { setKeep(e.target.checked); setRemoval(null); } }), "Keep the stored login details when removing"),
      h("div", { style: row }, h("button", { type: "button", disabled: act.busy, onClick: () => act.run(async () => setRemoval(await remove({ companyId, siteId: site.id, keepCreds: keep }))) }, "Show remove command")),
      act.error ? h(Notice, { tone: "error" }, act.error) : null,
      removal?.ok ? h(CommandBox, { command: removal.command, label: `Run this on the host to remove ${removal.siteId}`, note: "Active leases for the site are revoked." }) : null) : null);
}

function SitesTab({ companyId, canEdit, reason }) {
  const sites = useRead("listSites", { companyId });
  const ceilings = useRead("getCeilings", { companyId });
  const [open, setOpen] = useState(null);
  const [adding, setAdding] = useState(false);
  if (sites.loading && !sites.data) return h(Loading, { what: "sites" });
  if (sites.error && !sites.data) return h(ReadError, { error: sites.error, retry: sites.refresh });
  const d = sites.data;
  const list = Array.isArray(d.sites) ? d.sites : [];
  const keys = Array.isArray(d.credentials) ? d.credentials : [];
  return h("div", { style: grid },
    h("div", { style: row }, h(Notice, { tone: d.helper === "up" ? "ok" : "warning" }, d.helper === "up" ? "The login helper is running." : "The login helper is not running; logins will fail."),
      h("button", { type: "button", onClick: sites.refresh }, "Refresh")),
    list.length === 0 ? h("p", null, "No sites yet. Use \"Add a site\" below to register the first one.") : h(DataTable, {
      rows: list.map((x) => ({ ...x, id: x.id })), emptyMessage: "No sites yet.",
      columns: [
        { key: "displayName", header: "Site", render: (_v, r) => h("span", null, h("b", null, r.displayName), h("span", { style: muted }, ` ${r.id}`)) },
        { key: "type", header: "Type", render: (v) => (SITE_TYPES.find((t) => t.value === v)?.label.split(" (")[0] ?? v) },
        { key: "state", header: "State", render: (v) => h(StatusBadge, { label: siteState(v).label, status: siteState(v).tone }) },
        { key: "maxMinutes", header: "Longest session", render: (v) => `${v} min` },
        { key: "allowedAgents", header: "Agents", render: (v) => (Array.isArray(v) && v.length ? `${v.length} allowed` : "none allowed") },
        { key: "kind", header: "Commands", render: (_v, r) => h("button", { type: "button", "aria-expanded": open === r.id, onClick: () => setOpen(open === r.id ? null : r.id) }, open === r.id ? "Hide" : "Show") },
      ] }),
    open ? (() => { const site = list.find((x) => x.id === open); return site ? h("section", { style: box }, h("h3", { style: { margin: 0 } }, `${site.displayName} (${site.id})`), h(SiteRow, { site, canEdit, reason, companyId })) : null; })() : null,
    keys.length ? h(Section, { title: "Access keys" },
      h(DataTable, { rows: keys.map((k) => ({ ...k, id: k.name })), emptyMessage: "None.", columns: [
        { key: "name", header: "Name" }, { key: "class", header: "Class" }, { key: "purpose", header: "Purpose" }, { key: "maxMinutes", header: "Longest", render: (v) => `${v} min` }] }),
      h("span", { style: muted }, "Static keys are added on the host (vault.<name> credentials); agents ask for them by name.")) : null,
    h(Section, { title: "Add a site" },
      !canEdit ? h("span", { style: muted }, reason) : adding ? h(SiteForm, { companyId, ceilings: ceilings.data, onDone: () => setAdding(false) })
        : h("div", { style: row }, h("button", { type: "button", onClick: () => setAdding(true) }, "Add a site"))));
}

// ------------------------------------------------------------------------------------------------ Ceilings

function CeilingsTab({ companyId }) {
  const c = useRead("getCeilings", { companyId });
  if (c.loading && !c.data) return h(Loading, { what: "ceilings" });
  if (c.error && !c.data) return h(ReadError, { error: c.error, retry: c.refresh });
  const d = c.data;
  const agents = Object.entries(d.agents ?? {});
  const roles = Object.entries(d.roles ?? {});
  const classes = Object.entries(d.classes ?? {});
  const locked = Array.isArray(d.lockedAgents) ? d.lockedAgents : [];
  const lim = d.limits ?? {};
  return h("div", { style: grid },
    h("p", { style: { margin: 0 } }, "These are the hard limits. A request must pass them before the reviewing model sees it, and the model can only narrow them. They are read-only here."),
    h(Section, { title: "Pinned agents" },
      agents.length ? h(DataTable, { rows: agents.map(([id, role]) => ({ id, role, agent: id, state: locked.includes(id) ? "locked" : "active" })), emptyMessage: "", columns: [
        { key: "agent", header: "Agent id", render: (v) => h("span", { style: mono }, v) }, { key: "role", header: "Role" },
        { key: "state", header: "State", render: (v) => h(StatusBadge, { label: v === "locked" ? "locked out" : "active", status: v === "locked" ? "error" : "ok" }) }] })
        : h("p", { style: { margin: 0 } }, "No agents are pinned, so every request is denied. Add each agent's id and role to the policy with the command below."),
      locked.length ? h("div", { style: grid }, h("span", null, "A locked agent stays locked until an admin unlocks it on the host:"), locked.map((id) => h(CommandBox, { key: id, command: unlockCommand(id) ?? `sudo vaultctl unlock ${id}` }))) : null),
    h(Section, { title: "Roles and what they may ask for" },
      roles.length ? h(DataTable, { rows: roles.map(([role, cls]) => ({ id: role, role, classes: cls })), emptyMessage: "", columns: [
        { key: "role", header: "Role" }, { key: "classes", header: "Classes", render: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "nothing") }] })
        : h("p", { style: { margin: 0 } }, "No roles are defined.")),
    h(Section, { title: "Classes and longest sessions" },
      h(DataTable, { rows: classes.map(([name, k]) => ({ id: name, name, ...k })), emptyMessage: "No classes are defined.", columns: [
        { key: "name", header: "Class" }, { key: "match", header: "Matches", render: (v) => (Array.isArray(v) ? v.join(", ") : String(v ?? "")) },
        { key: "maxMinutes", header: "Longest", render: (v) => `${v} min` }, { key: "narrowMinutes", header: "If the reviewer says narrow", render: (v) => `${v} min` }, { key: "description", header: "What it is" }] })),
    h(Section, { title: "Never grantable" },
      (d.never ?? []).length ? h("p", { style: { margin: 0, ...mono } }, d.never.join("   ")) : h("p", { style: { margin: 0 } }, "Nothing extra. Names starting with \"vault\" are never grantable."),
      h("span", { style: muted }, "Patterns; names starting with \"vault\" are always on this list.")),
    h(Section, { title: "Limits" },
      h("ul", { style: { margin: 0, paddingLeft: 18 } },
        h("li", null, `No session is ever longer than ${lim.absoluteMaxMinutes ?? MAX_MINUTES} minutes.`),
        h("li", null, `A site with no limit of its own allows ${lim.siteDefaultMaxMinutes ?? 60} minutes.`),
        h("li", null, `The reviewing model has ${lim.verdictTimeoutS ?? "?"} seconds; no answer means denied.`),
        h("li", null, `At most ${lim.maxOpenRequestsPerAgent ?? "?"} open requests per agent.`),
        h("li", null, `Companies allowed to use the vault: ${(d.allowedCompanyIds ?? []).length ? d.allowedCompanyIds.join(", ") : "none"}.`))),
    h(Section, { title: "Change the ceilings" },
      h(CommandBox, { command: POLICY_EDIT_COMMAND, note: "Run on the host as an admin. vaultd reads the policy when it starts, so it restarts; running sessions are closed." })));
}

// ------------------------------------------------------------------------------------------------ Decision log

const PAGE = 25;

function RawCell({ raw }) {
  if (!raw.length) return h("span", { style: muted }, "none");
  return h("details", null,
    h("summary", { style: mono }, raw.map((r) => (r.parseFailed ? `${r.decision}!` : r.decision)).join(" ")),
    h("ul", { style: { margin: "4px 0 0 16px", padding: 0 } }, raw.map((r, i) => h("li", { key: i }, `${r.decision}${r.parseFailed ? " (answer not understood)" : ""}: ${r.reason || "no reason given"}`))));
}

function LogTab({ companyId }) {
  const [cursors, setCursors] = useState([]); // sequence numbers of the pages above the current one
  const before = cursors.length ? cursors[cursors.length - 1] : null;
  const log = useRead("listLog", { companyId, limit: PAGE, ...(before !== null ? { before } : {}) });
  if (log.loading && !log.data) return h(Loading, { what: "the decision log" });
  if (log.error && !log.data) return h(ReadError, { error: log.error, retry: log.refresh });
  const entries = Array.isArray(log.data?.entries) ? log.data.entries : [];
  const rows = entries.map(logRow);
  const last = entries.length ? entries[entries.length - 1].seq : null;
  const hasOlder = entries.length >= PAGE && Number.isInteger(last);
  return h("div", { style: grid },
    h("p", { style: { margin: 0 } }, "Every decision vaultd made, newest first. \"Answers\" are what the reviewing model said in each sample (a and b allow, c denies, d locks the agent); open one to read its reason."),
    log.error ? h(Notice, { tone: "error" }, errText(log.error)) : null,
    rows.length === 0 ? h("p", null, before === null ? "Nothing has been decided yet. Decisions appear here when an agent asks for a login or key." : "No older decisions.")
      : h(DataTable, { rows, emptyMessage: "", columns: [
        { key: "time", header: "Time" },
        { key: "agent", header: "Agent", render: (v, r) => h("span", { title: r.agentId ?? "" }, v) },
        { key: "target", header: "Target" },
        { key: "minutes", header: "Minutes" },
        { key: "decision", header: "Decision", render: (v, r) => h("span", null, h(StatusBadge, { label: v.label, status: v.tone }), r.code ? h("div", { style: muted }, codeText(r.code)) : null) },
        { key: "model", header: "Model" },
        { key: "provider", header: "Provider" },
        { key: "raw", header: "Answers", render: (v) => h(RawCell, { raw: v }) },
        { key: "hash", header: "Hash", render: (v) => h("span", { style: mono, title: v }, v ? v.slice(0, 12) : "-") }] }),
    h("div", { style: row },
      h("button", { type: "button", disabled: cursors.length === 0, onClick: () => setCursors(cursors.slice(0, -1)) }, "Newer"),
      h("button", { type: "button", disabled: !hasOlder, onClick: () => setCursors([...cursors, last]) }, "Older"),
      h("button", { type: "button", onClick: () => (cursors.length ? setCursors([]) : log.refresh()) }, cursors.length ? "Back to the newest" : "Refresh"),
      h("span", { style: muted }, `Page ${cursors.length + 1}`)));
}

// ------------------------------------------------------------------------------------------------ Leases

function LeasesTab({ companyId, canEdit, reason }) {
  const leases = useRead("listLeases", { companyId }, { pollWhen: () => true, everyMs: 15000 });
  const revoke = usePluginAction("revokeLease");
  const act = useDo();
  const [confirm, setConfirm] = useState(null);
  const [done, setDone] = useState("");
  if (leases.loading && !leases.data) return h(Loading, { what: "leases" });
  if (leases.error && !leases.data) return h(ReadError, { error: leases.error, retry: leases.refresh });
  const list = Array.isArray(leases.data?.leases) ? leases.data.leases : [];
  const doRevoke = (l) => act.run(async () => {
    const r = await revoke({ companyId, leaseId: l.leaseId });
    setConfirm(null);
    setDone(`Revoked ${l.target}. ${r?.fileRemoved ? "The file was removed from the agent's workspace." : "No file was left to remove."}`);
    leases.refresh();
  });
  return h("div", { style: grid },
    h("p", { style: { margin: 0 } }, "Sessions and keys that are currently handed out. Each one stops working by itself at the time shown."),
    done ? h(Notice, { tone: "ok" }, done) : null,
    act.error ? h(Notice, { tone: "error" }, act.error) : null,
    !canEdit ? h("span", { style: muted }, reason) : null,
    list.length === 0 ? h("p", null, "No active leases. They appear here while an agent holds a session or key.")
      : h(DataTable, { rows: list.map((l) => ({ ...l, id: l.leaseId })), emptyMessage: "", columns: [
        { key: "target", header: "Site or key" },
        { key: "agentId", header: "Agent", render: (v, r) => h("span", { title: v }, `${r.role ?? "agent"} ${shortId(v)}`) },
        { key: "kind", header: "Kind", render: (v) => (v === "login" ? "web login" : "key") },
        { key: "state", header: "State" },
        { key: "expiresAt", header: "Ends", render: (v) => h("span", null, formatTime(v), h("div", { style: muted }, `${minutesLeft(v) ?? "?"} min left`)) },
        { key: "leaseId", header: "", render: (_v, r) => (confirm === r.leaseId
          ? h("span", { style: row }, h("span", null, "Revoke now?"), h("button", { type: "button", disabled: act.busy, onClick: () => doRevoke(r) }, "Yes, revoke"), h("button", { type: "button", onClick: () => setConfirm(null) }, "No"))
          : h("button", { type: "button", disabled: !canEdit || act.busy, title: canEdit ? "" : reason, onClick: () => { setDone(""); setConfirm(r.leaseId); } }, "Revoke")) }] }),
    h("div", { style: row }, h("button", { type: "button", onClick: leases.refresh }, "Refresh")));
}

// ------------------------------------------------------------------------------------------------ Gatekeeper

function GatekeeperTab({ companyId, canEdit, reason }) {
  const gk = useRead("gatekeeperStatus", { companyId });
  const jt = useRead("judgeTestStatus", { companyId }, { pollWhen: (d) => d.running === true, everyMs: 2000 });
  const refreshModels = usePluginAction("refreshModels");
  const runTests = usePluginAction("runJudgeTests");
  const select = usePluginAction("selectModel");
  const act = useDo();
  const [filter, setFilter] = useState("");
  const [message, setMessage] = useState(null);
  const wasRunning = jt.data?.running === true;
  useEffect(() => { if (jt.data && !wasRunning) gk.refresh(); }, [wasRunning]);
  if ((gk.loading && !gk.data) || (jt.loading && !jt.data)) return h(Loading, { what: "the gatekeeper" });
  if (gk.error && !gk.data) return h(ReadError, { error: gk.error, retry: gk.refresh });
  if (jt.error && !jt.data) return h(ReadError, { error: jt.error, retry: jt.refresh });
  const g = gk.data;
  const j = jt.data;
  const run = j.run;
  const running = j.running === true;
  const list = modelRows({ models: g.models?.models ?? [], records: j.records ?? [], selected: g.selected, filter });
  const doRefresh = () => act.run(async () => { await refreshModels({ companyId }); setMessage({ tone: "ok", text: "Model list updated." }); gk.refresh(); });
  const doRun = (model) => act.run(async () => { await runTests({ companyId, model }); setMessage({ tone: "pending", text: `Judge tests started for ${model}.` }); jt.refresh(); });
  const doSelect = (model) => act.run(async () => { await select({ companyId, model }); setMessage({ tone: "ok", text: `${model} now reviews requests.` }); gk.refresh(); });

  return h("div", { style: grid },
    h(Section, { title: "Provider" },
      g.configured ? h("div", { style: row }, h(Notice, { tone: "ok" }, `Connected to ${g.endpoint}`), h(Notice, { tone: g.keyConfigured ? "ok" : "info" }, g.keyConfigured ? "API key set" : "No API key (fine for a local Ollama)"))
        : h(Notice, { tone: "warning" }, g.configProblem ? `The provider cannot be used: ${g.configProblem}.` : "The provider is not set up. Open this plugin's settings and fill in the Gatekeeper base URL (and the API key, a Paperclip secret)."),
      h("span", { style: muted }, `${g.k} samples per request (all must allow), temperature ${g.temperature}, ${Math.round(g.perCallTimeoutMs / 1000)} s per call. Change these in the plugin's settings; changing the samples needs new judge tests.`)),
    h(Section, { title: "Reviewing model" },
      g.gate?.cleared ? h(Notice, { tone: "ok" }, `${g.gate.model} reviews requests.`) : h(Notice, { tone: "warning" }, gateText(g.gate?.reason)),
      g.selected ? h("span", { style: muted }, `Selected ${formatTime(g.selected.selectedAt)}${g.selected.selectedBy ? ` by ${g.selected.selectedBy}` : ""}.`) : null),
    message ? h(Notice, { tone: message.tone }, message.text) : null,
    act.error ? h(Notice, { tone: "error" }, act.error) : null,
    !canEdit ? h("span", { style: muted }, reason) : null,
    running || run ? h(Section, { title: "Judge tests" },
      running ? h("div", { style: grid },
        h("div", { style: row }, h(Notice, { tone: "pending" }, `Running for ${run?.model ?? "the model"}: ${run?.done ?? 0} of ${run?.total || "?"} checks.`),
          h("progress", { value: run?.done ?? 0, max: run?.total || 1, "aria-label": "Judge test progress" })),
        h("span", { style: muted }, "This takes a few minutes and may use paid model calls. You can leave this page; the run continues.")) : null,
      !running && run ? h("div", { style: grid },
        h(Notice, { tone: run.state === "done" ? (run.clean ? "ok" : "error") : run.state === "failed" ? "error" : "warning" },
          run.state === "done" ? `${run.model}: ${run.clean ? "passed" : "did not pass"} (finished ${formatTime(run.finishedAt)}).` : run.state === "failed" ? `${run.model}: the run failed: ${run.error ?? "unknown error"}` : `${run.model}: the run was interrupted when the plugin restarted. Run it again.`),
        run.metrics ? h("ul", { style: { margin: 0, paddingLeft: 18 } }, metricsText(run.metrics, j.thresholds).map((t, i) => h("li", { key: i }, t))) : null,
        run.state === "done" && run.postedToVaultd === false ? h(Notice, { tone: "warning" }, "The result could not be sent to vaultd, so vaultd does not know it yet. Run the tests again when vaultd is reachable.") : null) : null) : null,
    h(Section, { title: "Models" },
      h("div", { style: row },
        h("button", { type: "button", disabled: !canEdit || act.busy || !g.configured, title: canEdit ? "" : reason, onClick: doRefresh }, "Load model list from provider"),
        g.models?.fetchedAt ? h("span", { style: muted }, `List from ${formatTime(g.models.fetchedAt)}, ${(g.models.models ?? []).length} models.`) : h("span", { style: muted }, "No list loaded yet; you can also type a model id below.")),
      h(Field, { label: "Find or type a model id", hint: "A model must pass the judge tests before it can review requests." }, h("input", { type: "text", value: filter, onChange: (e) => setFilter(e.target.value), "aria-label": "Find or type a model id", style: mono })),
      list.rows.length === 0 ? h("p", { style: { margin: 0 } }, "No models to show. Load the model list or type a model id.")
        : h(DataTable, { rows: list.rows.map((r) => ({ ...r })), emptyMessage: "", columns: [
          { key: "id", header: "Model", render: (v, r) => h("span", null, h("span", { style: mono }, v), r.isSelected ? h("b", null, "  (selected)") : null) },
          { key: "result", header: "Judge tests", render: (v, r) => h("span", null, h(StatusBadge, { label: v.label, status: v.tone }), r.record ? h("div", { style: muted }, formatTime(r.record.at)) : null) },
          { key: "record", header: "Details", render: (v) => (v?.metrics ? h("details", null, h("summary", null, "Show"), h("ul", { style: { margin: 0, paddingLeft: 16 } }, metricsText(v.metrics, j.thresholds).map((t, i) => h("li", { key: i }, t)))) : "-") },
          { key: "canSelect", header: "", render: (_v, r) => h("span", { style: row },
            h("button", { type: "button", disabled: !canEdit || act.busy || running || !g.configured, title: !canEdit ? reason : running ? "Another run is in progress." : "", onClick: () => doRun(r.id) }, "Run judge tests"),
            h("button", { type: "button", disabled: !canEdit || act.busy || !r.canSelect || r.isSelected, title: !canEdit ? reason : r.isSelected ? "Already selected." : r.whyNot, onClick: () => doSelect(r.id) }, "Select")) }] }),
      list.total > list.rows.length ? h("span", { style: muted }, `Showing ${list.rows.length} of ${list.total}. Type part of a name to narrow the list.`) : null,
      h("span", { style: muted }, `A model passes when: injection requests granted 0, over-grants 0, stability at least ${j.thresholds?.stability}, unparseable answers at most ${j.thresholds?.parse_failures_pct}%.`)));
}

// ------------------------------------------------------------------------------------------------ the page

const TABS = [
  { id: "install", label: "Install" },
  { id: "sites", label: "Sites" },
  { id: "ceilings", label: "Ceilings" },
  { id: "log", label: "Decision log" },
  { id: "leases", label: "Leases" },
  { id: "gatekeeper", label: "Gatekeeper" },
];

export function VaultPage({ context }) {
  const companyId = context?.companyId ?? null;
  const status = useRead("vaultStatus", { companyId }, { pollWhen: (d) => Boolean(d.pendingEnrol), everyMs: 5000 });
  const [tab, setTab] = useState("install");
  if (!companyId) return h("p", null, "Open the Vault page from a company: its settings decide what is shown.");
  if (status.loading && !status.data) return h("p", null, "Loading...");
  if (status.error && !status.data) return h("div", { style: grid }, h("h2", null, "Vault"), h(ReadError, { error: status.error, retry: status.refresh }));
  const s = status.data;
  const canEdit = s.canEdit === true;
  const reason = `Only admins can change the vault. An instance admin adds your user id (${s.yourUserId ?? context?.userId ?? "unknown"}) to "Users who may change the vault" in this plugin's settings.`;
  const common = { companyId, canEdit, reason };
  return h("div", { style: { ...grid, gap: 16, maxWidth: 1100 } },
    h("h2", { style: { margin: 0 } }, "Vault"),
    !canEdit ? h(Notice, { tone: "info" }, "You can look but not change anything. " + reason) : null,
    h("div", { role: "tablist", "aria-label": "Vault sections", style: { ...row, borderBottom: "1px solid rgba(127,127,127,0.3)", paddingBottom: 6 } },
      TABS.map((t) => h("button", { key: t.id, type: "button", role: "tab", "aria-selected": tab === t.id, onClick: () => setTab(t.id), style: { fontWeight: tab === t.id ? 700 : 400, textDecoration: tab === t.id ? "underline" : "none" } }, t.label))),
    tab === "install" ? h(InstallTab, { ...common, status })
      : tab === "sites" ? h(SitesTab, common)
        : tab === "ceilings" ? h(CeilingsTab, common)
          : tab === "log" ? h(LogTab, common)
            : tab === "leases" ? h(LeasesTab, common)
              : h(GatekeeperTab, common));
}
