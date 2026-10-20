// The Vault page: pure helpers (site-file builder, commands, rows) and a render/interaction test of every tab against the real
// actions and the fake vaultd. React and the SDK's UI module are replaced by a small synchronous renderer (module.registerHooks),
// so the page runs unchanged: state, effects, clicks and typing included.
import test from "node:test";
import assert from "node:assert/strict";
import module from "node:module";
import path from "node:path";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { pathToFileURL, fileURLToPath } from "node:url";
import { makeWorld, user, ADMIN, USER, COMPANY, AGENT } from "./helpers/world.mjs";
import { PROMPT_SHA, SCENARIOS_SHA } from "../../tests/fakes/fake_vaultd.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const UI = path.join(HERE, "../src/ui.js");
const HOST_DIR = path.join(HERE, "../../host");

// ------------------------------------------------------------------------------------------------ the stand-in for React

const ui = { runtime: null, inflight: 0, handler: null, copied: [], intervals: new Set() };
ui.action = async (key, params) => { ui.inflight += 1; try { return await ui.handler(key, params); } finally { ui.inflight -= 1; } };
globalThis.__vaultUi = ui;
const REACT_STUB = `const ui = () => globalThis.__vaultUi.runtime;
const React = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children: children.flat(Infinity) }),
  useState: (v) => ui().useState(v),
  useEffect: (fn, deps) => ui().useEffect(fn, deps),
};
export default React;`;
const SDK_STUB = `const t = () => globalThis.__vaultUi;
const el = (type, props, children) => ({ type, props, children });
export const usePluginAction = (key) => async (params) => t().action(key, params);
export const copyTextToClipboard = async (text) => { t().copied.push(text); };
export const StatusBadge = (p) => el("badge", { status: p.status }, ["[" + p.status + ": " + p.label + "]"]);
export const DataTable = (p) => el("table", {}, [
  el("tr", {}, p.columns.map((c) => el("th", {}, [c.header]))),
  ...(p.rows.length ? p.rows : [{ __empty: true }]).map((r) => el("tr", {}, r.__empty ? [p.emptyMessage ?? ""] : p.columns.map((c) => el("td", { col: c.key }, [c.render ? c.render(r[c.key], r) : String(r[c.key] ?? "")])))),
]);`;

/** Renders Root with hooks. Component instances are kept by their position in the tree, like React. */
function mount(Root, props) {
  const instances = new Map();
  let current = null;
  let dirty = true;
  let tree = null;
  const rt = {
    useState(initial) {
      const inst = current;
      const i = inst.idx++;
      if (!(i in inst.hooks)) inst.hooks[i] = { value: typeof initial === "function" ? initial() : initial };
      const slot = inst.hooks[i];
      return [slot.value, (v) => { const next = typeof v === "function" ? v(slot.value) : v; if (!Object.is(next, slot.value)) { slot.value = next; dirty = true; } }];
    },
    useEffect(fn, deps) {
      const inst = current;
      const i = inst.idx++;
      const prev = inst.hooks[i];
      if (prev && deps && prev.deps && deps.length === prev.deps.length && deps.every((d, k) => Object.is(d, prev.deps[k]))) return;
      inst.hooks[i] = { ...prev, deps, pending: fn };
    },
  };
  ui.runtime = rt;

  function expand(node, key) {
    if (node === null || node === undefined || typeof node === "boolean") return null;
    if (typeof node === "string" || typeof node === "number") return String(node);
    if (Array.isArray(node)) return node.map((n, i) => expand(n, `${key}.${i}`));
    if (typeof node.type === "function") {
      const k = `${key}<${node.type.name}${node.props?.key !== undefined ? `#${node.props.key}` : ""}>`;
      let inst = instances.get(k);
      if (!inst) { inst = { hooks: [], idx: 0 }; instances.set(k, inst); }
      inst.seen = true;
      inst.idx = 0;
      const prevCurrent = current;
      current = inst;
      let out;
      try { out = node.type({ ...node.props, children: node.children }); } finally { current = prevCurrent; }
      return expand(out, k);
    }
    return { type: node.type, props: node.props, children: node.children.map((c, i) => expand(c, `${key}/${node.type}${node.props?.key !== undefined ? `#${node.props.key}` : i}`)).flat(Infinity).filter((c) => c !== null) };
  }

  const view = {
    get tree() { return tree; },
    render() {
      dirty = false;
      for (const inst of instances.values()) inst.seen = false;
      tree = expand({ type: Root, props, children: [] }, "root");
      for (const [k, inst] of [...instances]) if (!inst.seen) { for (const h of inst.hooks) h?.cleanup?.(); instances.delete(k); }
    },
    runEffects() {
      let ran = false;
      for (const inst of instances.values()) for (const slot of inst.hooks) {
        if (slot?.pending) { slot.cleanup?.(); const fn = slot.pending; slot.pending = null; slot.cleanup = fn() ?? undefined; ran = true; }
      }
      return ran;
    },
    /** Renders, runs effects and waits for pending actions until nothing changes any more. */
    async settle() {
      for (let n = 0; n < 400; n += 1) {
        ui.runtime = rt;
        view.render();
        const ran = view.runEffects();
        await new Promise((r) => setTimeout(r, 5));
        if (!dirty && !ran && ui.inflight === 0) return;
      }
      throw new Error("the page did not settle");
    },
    dispose() { for (const inst of instances.values()) for (const slot of inst.hooks) slot?.cleanup?.(); },
    text() { return textOf(tree).replace(/\s+/g, " ").trim(); },
    all(pred, from = tree) { const out = []; const walk = (n) => { if (!n || typeof n === "string") return; if (pred(n)) out.push(n); n.children.forEach(walk); }; walk(from); return out; },
    find(pred) { const r = view.all(pred); assert.ok(r.length >= 1, "element not found"); return r[0]; },
    button(label) { return view.find((n) => n.type === "button" && plain(n) === label); },
    hasButton(label) { return view.all((n) => n.type === "button" && plain(n) === label).length > 0; },
    byLabel(label) { return view.find((n) => n.props?.["aria-label"] === label); },
    async click(label) { const b = typeof label === "string" ? view.button(label) : label; assert.ok(!b.props.disabled, `button ${label} is disabled`); await b.props.onClick({}); await view.settle(); },
    async type(label, value) { await view.byLabel(label).props.onChange({ target: { value } }); await view.settle(); },
  };
  return view;
}

/** The text of a node without the markers textOf adds for inputs and disabled buttons. */
function plain(n) {
  return typeof n === "string" ? n : (n?.children ?? []).map(plain).join("").trim();
}

function textOf(n) {
  if (n === null || n === undefined) return "";
  if (typeof n === "string") return n;
  if (Array.isArray(n)) return n.map(textOf).join(" ");
  const own = n.type === "input" || n.type === "textarea" || n.type === "select" ? `<${n.type}${n.props.disabled ? " disabled" : ""}${n.props.checked ? " checked" : ""}>` : n.type === "button" && n.props.disabled ? "[disabled]" : "";
  return `${own} ${n.children.map(textOf).join(" ")}`;
}

let VaultPage;
let helpers;
const skipRender = typeof module.registerHooks !== "function" && "module.registerHooks needs Node 22.15+";
if (!skipRender) {
  const stubs = { react: REACT_STUB, "@paperclipai/plugin-sdk/ui": SDK_STUB };
  module.registerHooks({
    resolve(specifier, context, next) {
      if (stubs[specifier] && context.parentURL?.endsWith("/src/ui.js")) return { url: `data:text/javascript,${encodeURIComponent(stubs[specifier])}`, shortCircuit: true };
      return next(specifier, context);
    },
  });
  helpers = await import(pathToFileURL(UI).href);
  VaultPage = helpers.VaultPage;
}
const real = () => { assert.ok(helpers, "the UI module loaded"); return helpers; };

// ------------------------------------------------------------------------------------------------ site-file builder

const GOOD = {
  type: "password-totp", id: "example-admin", displayName: "Example admin", kind: "test", purpose: "Test the example admin UI",
  loginUrl: "https://app.example.org/login", logoutUrl: "", allowedHosts: "", allowedAgents: [AGENT], roles: "QA, UI Tester", maxMinutes: "45",
  usernameSelector: "#email", nextSelector: "button[type=submit]", passwordSelector: "#password", submitSelector: "#login", totpSelector: "#otp", totpSubmitSelector: "#verify",
  successUrl: "https://app.example.org/dashboard", successSelector: "#avatar", logoutSelector: "#logout",
};
const OAUTH = {
  type: "oauth", id: "github-ci", displayName: "GitHub CI", kind: "owner", purpose: "Read CI status", allowedAgents: [AGENT], roles: "QA", maxMinutes: "30",
  flow: "device", authUrl: "https://github.com/login/oauth/authorize", tokenUrl: "https://github.com/login/oauth/access_token", deviceUrl: "https://github.com/login/device/code",
  revokeUrl: "", clientId: "Iv1.abc123", scopes: "repo read:org", accessTtlMaxMinutes: "",
};
const INTERACTIVE = { ...GOOD, type: "interactive", id: "google-owner", displayName: "Google", kind: "owner", loginUrl: "https://accounts.google.com/", successUrl: "https://myaccount.google.com/", successSelector: "", logoutSelector: "" };

function pythonValidate(sites) {
  const code = "import sys, json\nsys.path.insert(0, sys.argv[1])\nfrom vaultd import sites\nfor s in json.load(sys.stdin):\n    sites.validate(s)\nprint('ok')";
  return execFileSync("python3", ["-I", "-c", code, HOST_DIR], { input: JSON.stringify(sites), encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
}
let havePython = true;
try { execFileSync("python3", ["--version"]); } catch { havePython = false; }

test("buildSiteFile: each site type yields a file in the docs/DESIGN.md section 5 shape", () => {
  const { buildSiteFile } = real();
  const a = buildSiteFile(GOOD);
  assert.deepEqual(a.errors, {});
  assert.deepEqual(a.site, {
    schema: 1, id: "example-admin", displayName: "Example admin", type: "password-totp", kind: "test", purpose: "Test the example admin UI",
    loginUrl: "https://app.example.org/login", logoutUrl: null, allowedHosts: ["app.example.org"], allowedAgents: [AGENT], roles: ["QA", "UI Tester"], maxMinutes: 45,
    recipe: {
      steps: [{ fill: "#email", from: "username" }, { click: "button[type=submit]" }, { fill: "#password", from: "password" }, { click: "#login" }, { fill: "#otp", from: "totp", optional: true }, { click: "#verify", optional: true }],
      successCheck: { urlMatches: "^https://app\\.example\\.org/dashboard", selector: "#avatar" }, logout: { steps: [{ click: "#logout" }] }, timeoutSeconds: 45,
    },
    oauth: null,
  });
  const o = buildSiteFile(OAUTH).site;
  assert.equal(o.loginUrl, null); assert.equal(o.recipe, null);
  assert.deepEqual(o.oauth, { flow: "device", authUrl: OAUTH.authUrl, tokenUrl: OAUTH.tokenUrl, deviceUrl: OAUTH.deviceUrl, revokeUrl: null, clientId: "Iv1.abc123", scopes: ["repo", "read:org"], accessTtlMaxMinutes: 480 });
  assert.deepEqual(o.allowedHosts, ["github.com"]);
  const i = buildSiteFile(INTERACTIVE).site;
  assert.deepEqual(i.recipe, { steps: [], successCheck: { urlMatches: "^https://myaccount\\.google\\.com/" }, timeoutSeconds: 45 });
});

test("buildSiteFile: plain-language errors per field, no site while anything is wrong", () => {
  const { buildSiteFile, emptySiteForm } = real();
  const empty = buildSiteFile(emptySiteForm());
  assert.equal(empty.site, null);
  for (const k of ["id", "displayName", "purpose", "loginUrl", "allowedHosts", "usernameSelector", "passwordSelector", "submitSelector", "successUrl"]) assert.ok(empty.errors[k], k);
  const bad = buildSiteFile({ ...GOOD, id: "Bad Id; rm -rf", loginUrl: "ftp://x", allowedHosts: "UPPER CASE host", allowedAgents: ["not-a-uuid"], maxMinutes: "9999", roles: "x".repeat(40), kind: "boss" });
  assert.equal(bad.site, null);
  for (const k of ["id", "loginUrl", "allowedHosts", "allowedAgents", "maxMinutes", "roles", "kind"]) assert.ok(bad.errors[k], k);
  assert.match(bad.errors.id, /lowercase/);
  assert.equal(buildSiteFile({ ...OAUTH, scopes: "", deviceUrl: "" }).site, null);
  assert.equal(buildSiteFile(null).site, null);
  assert.equal(buildSiteFile({ ...GOOD, id: { toString: () => "example-admin" } }).site, null, "non-string values are refused, not coerced");
});

test("buildSiteFile cannot emit a secret: only whitelisted keys, whatever the form carries", () => {
  const { buildSiteFile, SITE_FILE_KEYS, RECIPE_KEYS, OAUTH_KEYS } = real();
  const planted = {
    password: "hunter2-PASSWORD", totp: "JBSWY3DPEHPK3PXP", totpSeed: "JBSWY3DPEHPK3PXP", secret: "s3cret-VALUE", clientSecret: "client-SECRET-1", token: "tok-ABCDEF", apiKey: "sk-live-XYZ",
    refreshToken: "refresh-123", cookies: [{ name: "sid", value: "cookie-VALUE" }], username: "admin@example.org", credentials: { password: "hunter2-PASSWORD" },
    recipe: { steps: [{ fill: "#p", from: "password", value: "hunter2-PASSWORD" }] }, oauth: { clientSecret: "client-SECRET-1" }, storageState: { cookies: [] }, __proto__: { password: "inherited" },
  };
  const leaked = ["hunter2-PASSWORD", "JBSWY3DPEHPK3PXP", "s3cret-VALUE", "client-SECRET-1", "tok-ABCDEF", "sk-live-XYZ", "refresh-123", "cookie-VALUE", "admin@example.org", "inherited"];
  const stepKeys = new Set(["fill", "click", "press", "waitFor", "from", "optional"]);
  const checked = [];
  for (const base of [GOOD, OAUTH, INTERACTIVE]) {
    const { site, errors } = buildSiteFile({ ...base, ...planted });
    assert.ok(site, JSON.stringify(errors));
    const json = JSON.stringify(site);
    for (const s of leaked) assert.ok(!json.includes(s), `${s} must not be emitted`);
    assert.deepEqual(Object.keys(site).filter((k) => !SITE_FILE_KEYS.includes(k)), []);
    if (site.recipe) {
      assert.deepEqual(Object.keys(site.recipe).filter((k) => !RECIPE_KEYS.includes(k)), []);
      for (const step of [...site.recipe.steps, ...(site.recipe.logout?.steps ?? [])]) {
        assert.deepEqual(Object.keys(step).filter((k) => !stepKeys.has(k)), []);
        if (step.from) assert.ok(["username", "password", "totp"].includes(step.from), "`from` names where a value comes from, it carries none");
      }
      assert.deepEqual(Object.keys(site.recipe.successCheck).filter((k) => !["urlMatches", "selector"].includes(k)), []);
    }
    if (site.oauth) assert.deepEqual(Object.keys(site.oauth).filter((k) => !OAUTH_KEYS.includes(k)), []);
    checked.push(site);
  }
  // a hostile generator: random extra keys with secret-looking values on top of a valid form
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  for (let n = 0; n < 200; n += 1) {
    const extra = {};
    for (let i = 0; i < 5; i += 1) extra[`${["pass", "secret", "seed", "totp", "token", "key", "x"][Math.floor(rnd() * 7)]}${Math.floor(rnd() * 100)}`] = `SECRET-${n}-${i}`;
    const { site } = buildSiteFile({ ...[GOOD, OAUTH, INTERACTIVE][n % 3], ...extra });
    assert.ok(site);
    assert.ok(!JSON.stringify(site).includes("SECRET-"));
  }
  assert.equal(checked.length, 3);
});

test("the add-site command round-trips to site files that pass the schema (vaultd's own validator) and carries no secret", { skip: !havePython && "python3 not available" }, async () => {
  const { buildSiteFile } = real();
  const w = await makeWorld({ overrides: { enrol: { pins: { version: "0.1.0", baseUrl: "https://example.org/r/", installVaultSha256: "a".repeat(64) }, serviceUser: () => "paperclip" } } });
  try {
    const decoded = [];
    for (const form of [GOOD, { ...GOOD, nextSelector: "", totpSelector: "", totpSubmitSelector: "", logoutSelector: "", successSelector: "", password: "hunter2-PASSWORD" }, OAUTH, { ...OAUTH, flow: "redirect", deviceUrl: "", revokeUrl: "https://github.com/revoke" }, INTERACTIVE]) {
      const { site, errors } = buildSiteFile(form);
      assert.ok(site, JSON.stringify(errors));
      const res = await w.action("addSiteCommand", { site }, user(ADMIN));
      assert.match(res.command, /^sudo vault-site add --site-json-b64 [A-Za-z0-9+/=]+$/);
      assert.equal(res.siteId, site.id);
      const back = JSON.parse(Buffer.from(res.command.split(" ").at(-1), "base64").toString("utf8"));
      assert.deepEqual(back, site, "what the command carries is exactly the file the form built");
      assert.ok(!res.command.includes("hunter2") && !Buffer.from(res.command.split(" ").at(-1), "base64").toString().includes("hunter2"));
      decoded.push(back);
    }
    assert.match(pythonValidate(decoded), /ok/);
    // and the validator really rejects what the builder never emits
    assert.throws(() => pythonValidate([{ ...decoded[0], password: "x" }]), /unknown keys/);
  } finally { await w.cleanup(); }
});

// ------------------------------------------------------------------------------------------------ pure helpers

test("command helpers: site commands carry only a validated id; the lifetime text comes from the worker's number", () => {
  const { siteCommands, minutesText, unlockCommand, POLICY_EDIT_COMMAND } = real();
  assert.deepEqual(siteCommands({ id: "x; reboot", type: "oauth" }), []);
  assert.deepEqual(siteCommands({ id: "a-b", type: "password-totp" }).map((c) => c.command), ["sudo vault-site test a-b"]);
  assert.deepEqual(siteCommands({ id: "a-b", type: "oauth" }).map((c) => c.command), ["sudo vault-site test a-b", "sudo vault-site authorize a-b"]);
  assert.deepEqual(siteCommands({ id: "a-b", type: "interactive" }).map((c) => c.command), ["sudo vault-site test a-b", "sudo vault-site interactive a-b"]);
  assert.equal(unlockCommand(AGENT), `sudo vaultctl unlock ${AGENT}`);
  assert.equal(unlockCommand("x; rm -rf /"), null);
  assert.equal(POLICY_EDIT_COMMAND, "sudoedit /etc/vault/policy.json && sudo systemctl restart vaultd");
  assert.equal(minutesText(60), "60 minutes");
  assert.equal(minutesText(1), "1 minute");
  assert.equal(minutesText(undefined), "a limited time");
});

test("row helpers: log rows, model rows (select only with a clean current record), site states, times", () => {
  const { logRow, modelRows, siteState, formatTime, minutesLeft, gateText, codeText, metricsText } = real();
  const row = logRow({ seq: 5, time: "2026-10-19T08:15:30Z", hash: "ab".repeat(32), agentId: AGENT, role: "QA", target: "example-admin", requestedMinutes: 45, minutes: 30, decision: "approve", code: "",
    model: "m", provider: "p", raw: [{ decision: "b", max_minutes: 30, reason: "fits" }, { decision: "c", parseFailed: true }] });
  assert.equal(row.time, "2026-10-19 08:15:30 UTC");
  assert.equal(row.minutes, "30 of 45");
  assert.equal(row.agent, "QA 22222222");
  assert.deepEqual(row.decision, { label: "approved", tone: "ok" });
  assert.deepEqual(row.raw.map((r) => r.decision), ["b", "c"]);
  assert.equal(row.raw[1].parseFailed, true);
  assert.equal(logRow({ decision: "deny", code: "judge_lock" }).decision.label, "denied");
  assert.equal(codeText("judge_lock"), "the reviewing model locked the agent");
  assert.equal(formatTime("garbage"), "-");
  assert.equal(minutesLeft("2026-10-19T09:00:00Z", Date.parse("2026-10-19T08:15:30Z")), 45);
  assert.equal(siteState("needs_authorize").tone, "warning");
  assert.equal(siteState("weird").label, "weird");
  assert.match(gateText("stale_hashes"), /Run them again/);
  const rec = (model, clean, current) => ({ model, clean, current, at: "2026-10-19T08:00:00Z", metrics: { n: 1, injection_granted: 0, over_grants: 0, stability: 1, parse_failures_pct: 0 } });
  const list = modelRows({ models: [{ id: "good" }, { id: "bad" }, { id: "old" }, { id: "never" }], records: [rec("good", true, true), rec("bad", false, true), rec("old", true, false)], selected: { model: "good" } });
  const by = Object.fromEntries(list.rows.map((r) => [r.id, r]));
  assert.equal(list.rows[0].id, "good", "the selected model comes first");
  assert.deepEqual([by.good.canSelect, by.bad.canSelect, by.old.canSelect, by.never.canSelect], [true, false, false, false]);
  assert.deepEqual([by.good.result.label, by.bad.result.label, by.old.result.label, by.never.result.label], ["passed", "did not pass", "passed, but outdated", "not tested"]);
  assert.match(by.bad.whyNot, /did not pass/); assert.match(by.old.whyNot, /changed/); assert.match(by.never.whyNot, /Run the judge tests/);
  assert.deepEqual(modelRows({ models: [{ id: "a/b" }], filter: "zzz/typed" }).rows.map((r) => r.id), ["zzz/typed"], "a typed id can be tested");
  assert.equal(modelRows({ models: Array.from({ length: 80 }, (_, i) => ({ id: `m${i}` })) }).rows.length, 50);
  assert.equal(metricsText({ injection_granted: 1, over_grants: 0, stability: 1, parse_failures_pct: 0 }, { injection_granted: 0, over_grants: 0, stability: 0.95, parse_failures_pct: 1 })[0].endsWith("FAILS"), true);
});

// ------------------------------------------------------------------------------------------------ the page against the real actions

const PINS = { version: "0.1.0", baseUrl: "https://example.org/releases/v0.1.0/", installVaultSha256: "b".repeat(64) };

async function openPage(w, who = ADMIN, { companyId = COMPANY } = {}) {
  const calls = [];
  ui.copied.length = 0;
  ui.handler = async (key, params) => {
    calls.push({ key, params });
    return w.action(key, params, user(who));
  };
  const view = mount(VaultPage, { context: { companyId, userId: who } });
  await view.settle();
  view.calls = calls;
  return view;
}
const world = (opts = {}) => makeWorld({ ...opts, overrides: { ...opts.overrides, enrol: { pins: PINS, serviceUser: () => "paperclip" } } });
const realTimers = { setInterval: globalThis.setInterval, clearInterval: globalThis.clearInterval };
function fakeIntervals() {
  globalThis.setInterval = (fn, ms) => { const t = { fn, ms }; ui.intervals.add(t); return t; };
  globalThis.clearInterval = (t) => { ui.intervals.delete(t); };
}
function restoreIntervals() { Object.assign(globalThis, realTimers); ui.intervals.clear(); }

test("page: Install tab for an admin: status badge, install command with fingerprint and expiry, copy, uninstall", { skip: skipRender }, async () => {
  fakeIntervals();
  const w = await world({ enrolled: false });
  try {
    const v = await openPage(w);
    assert.match(v.text(), /^Vault/);
    assert.match(v.text(), /\[info: Not installed on the host yet/);
    assert.ok(!/You can look but not change/.test(v.text()));
    await v.click("Create install command");
    assert.ok(v.calls.some((c) => c.key === "installCommand" && c.params.companyId === COMPANY));
    const t = v.text();
    assert.match(t, new RegExp(`Installer fingerprint \\(sha256\\): ${"b".repeat(64)}`));
    assert.match(t, /Downloaded from: https:\/\/example\.org\/releases\/v0\.1\.0\/install-vault\.sh/);
    assert.match(t, /Valid until \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC \(60 minutes, single use\)/);
    assert.match(t, /works once and for 60 minutes\./, "the intro text uses the lifetime the worker reports");
    assert.ok(!/15 minutes/.test(t));
    assert.match(t, /\[pending: Waiting for the install command to be run on the host/, "the status now shows the pending code");
    assert.ok(ui.intervals.size >= 1, "the page polls while a code is pending");
    const command = v.find((n) => n.type === "pre").children.join("");
    assert.match(command, /sha256sum -c - && sudo bash .* --service-user paperclip --company /);
    await v.click("Copy");
    assert.deepEqual(ui.copied, [command]);
    assert.match(v.text(), /Copied\./);
    // uninstall
    await v.click("Show uninstall command");
    assert.ok(v.calls.some((c) => c.key === "uninstallCommand" && c.params.purge === false));
    assert.match(v.text(), /Fingerprint \(sha256\): b{64}/);
    v.dispose();
  } finally { restoreIntervals(); await w.cleanup(); }
});

test("page: Install tab on a development build and when the vault refuses to operate", { skip: skipRender }, async () => {
  const w = await makeWorld({ enrolled: false, config: { workspaceRoots: [] } });
  try {
    const v = await openPage(w);
    const t = v.text();
    assert.match(t, /no official download address and fingerprint/);
    assert.match(t, /\[error: The plugin refuses to operate: workspaceRoots is not set/);
    assert.match(t, /To finish: open this plugin's settings and set Workspace roots/);
    assert.equal(v.button("Create install command").props.disabled, true);
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: an enrolled install shows the connection; a non-admin sees the read-only banner and disabled buttons with the reason", { skip: skipRender }, async () => {
  const w = await world();
  try {
    const v = await openPage(w, USER);
    const t = v.text();
    assert.match(t, /\[ok: Connected to vaultd fake-0\.1\.0; the login helper is up\./);
    assert.match(t, /You can look but not change anything\. Only admins can change the vault\. An instance admin adds your user id \(user-plain\)/);
    assert.equal(v.button("Create a new install command").props.disabled, true);
    assert.match(v.button("Create a new install command").props.title, /Only admins/);
    assert.equal(v.byLabel("Vault sections").props.role, "tablist");
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: Sites tab lists sites with their state, shows the per-site commands and never asks for a secret", { skip: skipRender }, async () => {
  const w = await world({
    fake: { sites: [
      { ...JSON.parse(JSON.stringify(helpersSite("example-admin", "password-totp", "ready"))) },
      { ...helpersSite("github-ci", "oauth", "needs_authorize") },
      { ...helpersSite("google-owner", "interactive", "needs_interactive") },
    ] },
  });
  try {
    const v = await openPage(w);
    await v.click("Sites");
    const t = v.text();
    assert.match(t, /Example admin example-admin/);
    assert.match(t, /\[ok: ready\]/);
    assert.match(t, /\[warning: needs authorizing\]/);
    assert.match(t, /\[warning: needs a manual login\]/);
    assert.match(t, /The login helper is running\./);
    assert.match(t, /Access keys.*deploy-token/);
    // commands per site
    const showButtons = v.all((n) => n.type === "button" && n.children.join("") === "Show");
    assert.equal(showButtons.length, 3);
    await v.click(showButtons[1]);
    assert.match(v.text(), /sudo vault-site test github-ci/);
    assert.match(v.text(), /sudo vault-site authorize github-ci/);
    assert.match(v.text(), /Run the Authorize command for this site\./);
    await v.click("Show remove command");
    assert.ok(v.calls.some((c) => c.key === "removeSiteCommand" && c.params.siteId === "github-ci" && c.params.keepCreds === false));
    assert.match(v.text(), /sudo vault-site remove github-ci/);
    const third = v.all((n) => n.type === "button" && ["Show", "Hide"].includes(n.children.join("")));
    await v.click(third[2]);
    assert.match(v.text(), /sudo vault-site interactive google-owner/);
    // no field on the page can take a secret
    for (const el of v.all((n) => ["input", "textarea"].includes(n.type))) assert.notEqual(el.props.type, "password");
    v.dispose();
  } finally { await w.cleanup(); }
});

function helpersSite(id, type, state) {
  return {
    schema: 1, id, displayName: id === "example-admin" ? "Example admin" : id, type, kind: "test", purpose: `Purpose of ${id}`, loginUrl: type === "oauth" ? null : "https://app.example.org/login", logoutUrl: null,
    allowedHosts: ["app.example.org"], allowedAgents: [AGENT], roles: ["QA"], maxMinutes: 60, recipe: null, oauth: null, state,
  };
}

test("page: the Add-site form builds the command from the form, shows field errors, and sends no secret", { skip: skipRender }, async () => {
  const w = await world();
  try {
    const v = await openPage(w);
    await v.click("Sites");
    await v.click("Add a site");
    await v.click("Build the command");
    assert.match(v.text(), /Use 1 to 41 lowercase letters/);
    assert.match(v.text(), /Some fields need a look/);
    assert.ok(!v.calls.some((c) => c.key === "addSiteCommand"), "nothing is sent while the form has errors");
    for (const [label, value] of [["Short name (id)", "my-site"], ["Display name", "My site"], ["What agents use it for", "Check the dashboards"], ["Login page address", "https://app.example.org/login"],
      ["Username field", "#email"], ["Password field", "#password"], ["Login button", "#login"], ["Page shown after login (address starts with)", "https://app.example.org/dashboard"]]) await v.type(label, value);
    // the agents come from the ceilings (none pinned in the fake's default policy except the QA agent): tick it
    const agentBox = v.all((n) => n.type === "label" && n.children.some((c) => c.type === "input" && c.props.type === "checkbox")).find((n) => /QA \(22222222\)/.test(textOf(n)));
    assert.ok(agentBox, "pinned agents are offered as checkboxes");
    await agentBox.children.find((c) => c.type === "input").props.onChange({ target: { checked: true } });
    await v.settle();
    await v.click("Build the command");
    const call = v.calls.findLast((c) => c.key === "addSiteCommand");
    assert.ok(call, "addSiteCommand was called");
    assert.deepEqual(Object.keys(call.params).sort(), ["companyId", "site"]);
    assert.equal(call.params.site.id, "my-site");
    assert.deepEqual(call.params.site.allowedAgents, [AGENT]);
    assert.deepEqual(call.params.site.allowedHosts, ["app.example.org"]);
    const t = v.text();
    assert.match(t, /Run this on the host to add my-site/);
    assert.match(t, /sudo vault-site add --site-json-b64 [A-Za-z0-9+/=]+/);
    assert.match(t, /never asks for a password, one-time-code seed or any other secret/);
    assert.match(t, /add --no-totp/);
    const b64 = v.find((n) => n.type === "pre").children.join("").split(" ").at(-1);
    assert.deepEqual(JSON.parse(Buffer.from(b64, "base64").toString()), call.params.site);
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: a non-admin cannot open the Add-site form or the per-site commands", { skip: skipRender }, async () => {
  const w = await world();
  try {
    const v = await openPage(w, USER);
    await v.click("Sites");
    assert.ok(!v.hasButton("Add a site"));
    assert.match(v.text(), /Only admins can change the vault/);
    await v.click(v.all((n) => n.type === "button" && n.children.join("") === "Show")[0]);
    assert.ok(!v.hasButton("Show remove command"));
    assert.ok(!/sudo vault-site test/.test(v.text()));
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: Sites empty state says what to do next", { skip: skipRender }, async () => {
  const w = await world({ fake: { sites: [] } });
  try {
    const v = await openPage(w);
    await v.click("Sites");
    assert.match(v.text(), /No sites yet\. Use "Add a site" below to register the first one\./);
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: Ceilings tab is read-only and shows pins, roles, classes, never-list, limits and the root command", { skip: skipRender }, async () => {
  const w = await world();
  try {
    await w.clearModel();
    w.fake.locked.add(AGENT);
    const v = await openPage(w);
    await v.click("Ceilings");
    const t = v.text();
    assert.match(t, new RegExp(`${AGENT} QA \\[error: locked out\\]`));
    assert.match(t, /QA web-login/);
    assert.match(t, /web-login web-\* 60 min 30 min Browser login to a registered site/);
    assert.match(t, /vault\*/);
    assert.match(t, /No session is ever longer than 480 minutes/);
    assert.match(t, new RegExp(`sudo vaultctl unlock ${AGENT}`));
    assert.match(t, /sudoedit \/etc\/vault\/policy\.json && sudo systemctl restart vaultd/);
    assert.deepEqual(v.all((n) => ["input", "textarea", "select"].includes(n.type)), [], "nothing to edit on this tab");
    v.dispose();
  } finally { await w.cleanup(); }
});

function addDecisions(w, n) {
  for (let i = 1; i <= n; i += 1) {
    w.fake.audit.push({ event: "decision", type: "decision", seq: 1000 + i, time: "2026-10-19T08:00:00Z", prev_hash: "0".repeat(64), hash: i.toString(16).padStart(2, "0") + "ab".repeat(31), requestId: `req_${i.toString(16).padStart(16, "0")}`,
      agentId: AGENT, role: "QA", target: `site-${i}`, kind: "login", requestedMinutes: 30, minutes: i % 2 ? 20 : 0, decision: i % 2 ? "approve" : "deny", code: i % 2 ? "" : "judge_deny",
      model: "vendor/judge-1", provider: "fake:provider", k: 2, raw: [{ decision: i % 2 ? "b" : "c", max_minutes: 20, reason: `reason ${i}` }, { decision: i % 2 ? "b" : "c", max_minutes: 25, reason: "ok" }] });
  }
}

test("page: Decision log shows every column and pages newest to oldest", { skip: skipRender }, async () => {
  const w = await world();
  try {
    addDecisions(w, 30);
    const v = await openPage(w);
    await v.click("Decision log");
    let t = v.text();
    for (const head of ["Time", "Agent", "Target", "Minutes", "Decision", "Model", "Provider", "Answers", "Hash"]) assert.ok(t.includes(head), head);
    assert.match(t, /site-30/);
    assert.match(t, /20 of 30/);
    assert.match(t, /\[ok: approved\]/); assert.match(t, /\[warning: denied\] the reviewing model said no/);
    assert.match(t, /vendor\/judge-1/); assert.match(t, /fake:provider/);
    assert.match(t, /b b/); assert.match(t, /reason 29/);
    assert.match(t, /1eababababab\b/, "the first 12 characters of the hash are shown");
    assert.match(t, /Page 1/);
    assert.equal(v.button("Newer").props.disabled, true);
    assert.equal(v.button("Older").props.disabled, false);
    await v.click("Older");
    const older = v.calls.findLast((c) => c.key === "listLog");
    assert.equal(older.params.limit, 25);
    assert.equal(older.params.before, 1006, "the cursor is the oldest sequence number on the page above");
    t = v.text();
    assert.match(t, /Page 2/); assert.match(t, /site-5\b/); assert.ok(!/site-30\b/.test(t));
    assert.equal(v.button("Older").props.disabled, true, "fewer than a full page: nothing older");
    await v.click("Newer");
    assert.match(v.text(), /site-30/);
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: Decision log empty state", { skip: skipRender }, async () => {
  const w = await world();
  try {
    const v = await openPage(w);
    await v.click("Decision log");
    assert.match(v.text(), /Nothing has been decided yet\./);
    v.dispose();
  } finally { await w.cleanup(); }
});

async function oneLease(w) {
  await w.clearModel();
  const res = await w.tool("vault_request_login", { site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 30 });
  assert.equal(res.data.status, "ready");
  return res;
}

test("page: Leases tab lists active leases; revoke asks first, removes the file and refreshes; non-admins cannot revoke", { skip: skipRender }, async () => {
  const w = await world();
  try {
    const res = await oneLease(w);
    const file = path.join(w.ws, res.data.path);
    assert.ok(fs.existsSync(file));
    const plain = await openPage(w, USER);
    await plain.click("Leases");
    assert.match(plain.text(), /example-admin/);
    assert.equal(plain.button("Revoke").props.disabled, true);
    assert.match(plain.button("Revoke").props.title, /Only admins/);
    plain.dispose();

    const v = await openPage(w);
    await v.click("Leases");
    assert.match(v.text(), /example-admin QA 22222222 web login/);
    assert.match(v.text(), /\d+ min left/);
    await v.click("Revoke");
    assert.match(v.text(), /Revoke now\?/);
    assert.ok(!v.calls.some((c) => c.key === "revokeLease"), "nothing happens before the second click");
    await v.click("No");
    assert.ok(!/Revoke now\?/.test(v.text()));
    await v.click("Revoke");
    await v.click("Yes, revoke");
    const call = v.calls.find((c) => c.key === "revokeLease");
    assert.match(call.params.leaseId, /^lse_[0-9a-f]{16}$/);
    assert.match(v.text(), /Revoked example-admin\. The file was removed from the agent's workspace\./);
    assert.equal(fs.existsSync(file), false);
    assert.match(v.text(), /No active leases\./);
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: a failed action is shown plainly", { skip: skipRender }, async () => {
  const w = await world();
  try {
    await oneLease(w);
    const v = await openPage(w);
    await v.click("Leases");
    const original = ui.handler;
    ui.handler = async (key, params) => { if (key === "revokeLease") throw new Error("vaultd said: the lease is not active"); return original(key, params); };
    await v.click("Revoke");
    await v.click("Yes, revoke");
    assert.match(v.text(), /\[error: vaultd said: the lease is not active\]/);
    v.dispose();
  } finally { await w.cleanup(); }
});

test("page: Gatekeeper tab: provider, gate, model list, select only with a clean record, run the judge tests with progress", { skip: skipRender }, async () => {
  fakeIntervals();
  let release = null;
  const w = await world({ config: { gatekeeper: { baseUrl: "http://127.0.0.1:11434/v1", k: 2, temperature: 0.2, perCallTimeoutMs: 2000 } } });
  try {
    const v = await openPage(w);
    await v.click("Gatekeeper");
    let t = v.text();
    assert.match(t, /\[ok: Connected to 127\.0\.0\.1:11434\]/);
    assert.match(t, /No API key \(fine for a local Ollama\)/);
    assert.match(t, /\[warning: No model is selected yet\./);
    assert.match(t, /2 samples per request/);
    // load the list, then run the tests for the model
    await v.click("Load model list from provider");
    assert.match(v.text(), /Model list updated\./);
    assert.match(v.text(), /good-model/);
    assert.match(v.text(), /\[info: not tested\]/);
    const selectNow = () => v.all((n) => n.type === "button" && n.children.join("") === "Select")[0];
    assert.equal(selectNow().props.disabled, true, "Select is disabled before a clean record");
    assert.match(selectNow().props.title, /Run the judge tests for this model first/);
    // the run: hold the provider so the page can show progress
    const gate = new Promise((r) => { release = r; });
    w.provider.judge = async (args) => {
      await gate;
      const d = args.prompt.includes("injection") ? { decision: "d", max_minutes: 0, reason: "hostile" } : { decision: "b", max_minutes: 40, reason: "fits" };
      return [d, d];
    };
    await v.click("Run judge tests");
    assert.ok(v.calls.some((c) => c.key === "runJudgeTests" && c.params.model === "good-model"));
    t = v.text();
    assert.match(t, /\[pending: Running for good-model: \d+ of \d+ checks\./);
    assert.ok(v.all((n) => n.type === "progress").length === 1);
    assert.ok([...ui.intervals].some((i) => i.ms === 2000), "polls the run while it is running");
    assert.equal(v.button("Run judge tests").props.disabled, true, "one run at a time");
    release();
    await w.services.judge.whenIdle();
    for (const i of [...ui.intervals]) i.fn();
    await v.settle();
    t = v.text();
    assert.match(t, /good-model: passed \(finished/);
    assert.match(t, /injection requests granted: 0 \(must be 0\) ok/);
    assert.match(t, /\[ok: passed\]/);
    assert.equal(selectNow().props.disabled, false);
    await v.click(selectNow());
    assert.ok(v.calls.some((c) => c.key === "selectModel" && c.params.model === "good-model"));
    t = v.text();
    assert.match(t, /\[ok: good-model now reviews requests\.\]/);
    assert.match(t, /\[ok: good-model reviews requests\.\]/);
    assert.match(t, /good-model \(selected\)/);
    v.dispose();
  } finally { release?.(); restoreIntervals(); await w.cleanup(); }
});

test("page: Gatekeeper: a model that failed the tests cannot be selected, a non-admin has nothing to press, an unconfigured provider says what to set", { skip: skipRender }, async () => {
  const w = await world({ config: { gatekeeper: { baseUrl: "http://127.0.0.1:11434/v1", k: 2, temperature: 0.2, perCallTimeoutMs: 2000 } } });
  const w2 = await world();
  try {
    await w.services.state.records.put("fake:provider|good-model", { model: "good-model", provider: "fake:provider", k: 2, promptSha256: PROMPT_SHA, scenariosSha256: SCENARIOS_SHA, metrics: { n: 6, injection_granted: 1, over_grants: 0, stability: 1, parse_failures_pct: 0 }, clean: false, at: "2026-10-19T08:00:00Z" });
    await w.services.state.setModels({ fetchedAt: "2026-10-19T08:00:00Z", provider: "fake:provider", models: [{ id: "good-model" }] });
    const v = await openPage(w);
    await v.click("Gatekeeper");
    assert.match(v.text(), /\[error: did not pass\]/);
    assert.match(v.text(), /injection requests granted: 1 \(must be 0\) FAILS/);
    const select = v.all((n) => n.type === "button" && n.children.join("") === "Select")[0];
    assert.equal(select.props.disabled, true);
    assert.match(select.props.title, /did not pass the judge tests/);
    v.dispose();

    const p = await openPage(w, USER);
    await p.click("Gatekeeper");
    assert.match(p.text(), /Only admins can change the vault/);
    for (const label of ["Load model list from provider", "Run judge tests", "Select"]) assert.equal(p.all((n) => n.type === "button" && n.children.join("") === label).every((b) => b.props.disabled), true, label);
    p.dispose();

    w2.data.config[COMPANY].gatekeeper = { baseUrl: "", k: 2 };
    const u = await openPage(w2);
    await u.click("Gatekeeper");
    assert.match(u.text(), /The provider is not set up\. Open this plugin's settings and fill in the Gatekeeper base URL/);
    u.dispose();
  } finally { await w.cleanup(); await w2.cleanup(); }
});

test("page: without a company, and when the first read fails, it says so", { skip: skipRender }, async () => {
  const w = await world();
  try {
    const v = await openPage(w, ADMIN, { companyId: null });
    assert.match(v.text(), /Open the Vault page from a company/);
    v.dispose();
    ui.handler = async () => { throw new Error("the plugin worker is not running"); };
    const bad = mount(VaultPage, { context: { companyId: COMPANY, userId: ADMIN } });
    await bad.settle();
    assert.match(bad.text(), /\[error: the plugin worker is not running\]/);
    assert.ok(bad.hasButton("Try again"));
    bad.dispose();
  } finally { await w.cleanup(); }
});

test("manifest: the page is one slot on route `vault`", async () => {
  const { default: manifest } = await import("../src/manifest.js");
  assert.deepEqual(manifest.ui.slots, [{ type: "page", id: "vault-page", displayName: "Vault", exportName: "VaultPage", routePath: "vault" }]);
  assert.equal(typeof (await import(pathToFileURL(UI).href)).VaultPage, "function");
});
