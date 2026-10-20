import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { makeWorld, user, USER, ADMIN, COMPANY } from "./helpers/world.mjs";
import { checkExposure, realpathLoose } from "../src/exposure.js";
import { readConfig } from "../src/config.js";

const base = (over = {}) => ({ workspaceRoots: ["/srv/work"], agentHomeRoot: null, instanceRoot: null, sandboxExtraPaths: [], dataDir: "/srv/vault-data", socketPath: "/pcv-run/vault/plugin.sock", ...over });
const mk = () => fs.mkdtempSync("/tmp/pcv-");

test("a key directory and socket outside every sandbox-visible root are fine", () => {
  assert.deepEqual(checkExposure(base({ workspaceRoots: ["/srv/work"], agentHomeRoot: "/srv/homes", instanceRoot: "/srv/paperclip", sandboxExtraPaths: ["/opt/tools"] })), { ok: true, problems: [] });
});

test("refusal: dataDir inside each kind of root", () => {
  const cases = [
    ["workspaceRoots", { workspaceRoots: ["/srv/other", "/srv"] }],
    ["agentHomeRoot", { agentHomeRoot: "/srv" }],
    ["instanceRoot", { instanceRoot: "/srv" }],
    ["sandboxExtraPaths", { sandboxExtraPaths: ["/opt", "/srv/vault-data"] }],
  ];
  for (const [code, over] of cases) {
    const r = checkExposure(base(over));
    assert.equal(r.ok, false, code);
    assert.ok(r.problems.some((p) => p.what === "dataDir" && p.code === code), code);
    assert.ok(r.problems.every((p) => p.what === "dataDir"), "the socket is fine in this case");
    assert.match(r.problems[0].message, /dataDir .* lies inside/);
  }
});

test("refusal: socketPath inside each kind of root", () => {
  const cases = [
    ["workspaceRoots", { workspaceRoots: ["/pcv-run"] }],
    ["agentHomeRoot", { agentHomeRoot: "/pcv-run/vault" }],
    ["instanceRoot", { instanceRoot: "/pcv-run" }],
    ["sandboxExtraPaths", { sandboxExtraPaths: ["/pcv-run/vault"] }],
  ];
  for (const [code, over] of cases) {
    const r = checkExposure(base(over));
    assert.equal(r.ok, false, code);
    assert.ok(r.problems.some((p) => p.what === "socketPath" && p.code === code), code);
  }
});

test("a root that merely shares a name prefix does not contain the path", () => {
  assert.equal(checkExposure(base({ workspaceRoots: ["/srv/vault"] })).ok, true);
});

test("symlinks are resolved: a data directory that links into a workspace root is refused, also through a missing tail", () => {
  const dir = mk();
  try {
    const roots = path.join(dir, "roots");
    const elsewhere = path.join(dir, "elsewhere");
    fs.mkdirSync(roots); fs.mkdirSync(elsewhere);
    fs.symlinkSync(roots, path.join(elsewhere, "link"));
    const cfg = base({ workspaceRoots: [roots], dataDir: path.join(elsewhere, "link", "data"), socketPath: path.join(dir, "s.sock") });
    const r = checkExposure(cfg);
    assert.equal(r.ok, false);
    assert.equal(r.problems[0].path, path.join(fs.realpathSync(roots), "data"));
    // and a root that is itself a symlink to the data directory's parent
    const rootLink = path.join(dir, "root-link");
    fs.symlinkSync(elsewhere, rootLink);
    assert.equal(checkExposure(base({ workspaceRoots: [rootLink], dataDir: path.join(elsewhere, "d"), socketPath: path.join(dir, "s.sock") })).ok, false);
    assert.equal(realpathLoose(path.join(dir, "a", "b", "c")), path.join(fs.realpathSync(dir), "a", "b", "c"));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("config: instanceRoot and sandboxExtraPaths are read, normalised and must be absolute", async () => {
  const w = await makeWorld({ config: { instanceRoot: "/srv/paperclip/", sandboxExtraPaths: ["/opt/tools", "relative/x", 5, ""] } });
  try {
    const cfg = await readConfig(w.c.ctx, COMPANY);
    assert.equal(cfg.instanceRoot, "/srv/paperclip");
    assert.deepEqual(cfg.sandboxExtraPaths, ["/opt/tools"]);
    assert.equal((await readConfig(w.c.ctx, "none")).instanceRoot, null);
  } finally { await w.cleanup(); }
});

// ----------------------------------------------------------- behaviour: no signed call, status error
const exposures = {
  "dataDir in a workspace root": (w) => ({ dataDir: path.join(w.roots, "keys") }),
  "dataDir in the agent home root": (w) => ({ dataDir: path.join(w.config.agentHomeRoot, "keys") }),
  "dataDir in the instance root": (w) => ({ instanceRoot: w.root }),
  "dataDir in a sandbox extra path": (w) => ({ sandboxExtraPaths: [w.dataDir] }),
  "socket in a workspace root": (w) => ({ socketPath: path.join(w.roots, "s.sock") }),
  "socket in the agent home root": (w) => ({ socketPath: path.join(w.config.agentHomeRoot, "s.sock") }),
  "socket in the instance root": (w) => ({ instanceRoot: path.dirname(w.socketPath), dataDir: path.join(w.root, "..", "data-elsewhere") }),
  "socket in a sandbox extra path": (w) => ({ sandboxExtraPaths: [path.dirname(w.socketPath)], dataDir: path.join(w.root, "..", "data-elsewhere") }),
};

for (const [name, patch] of Object.entries(exposures)) {
  test(`refusal (${name}): no signed call is made, tools fail closed, vaultStatus names the problem`, async () => {
    const w = await makeWorld();
    try {
      await w.clearModel();
      const calls = w.fake.calls.length;
      Object.assign(w.data.config[COMPANY], patch(w));
      const res = await w.tool("vault_request_login", { site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 20 });
      assert.equal(res.data.status, "failed");
      assert.equal(res.data.code, "exposed");
      assert.equal((await w.tool("vault_list_sites", {})).data.code, "exposed");
      assert.equal((await w.tool("vault_request_status", { requestId: "req_0000000000000000" })).data.status !== "ready", true);
      await assert.rejects(w.action("listLeases", {}, user(USER)), /refusing to use the vault/);
      await w.c.jobs["lease-sweep"]({});
      await w.c.jobs["enrol-tick"]({});
      assert.equal(w.fake.calls.length, calls, "vaultd saw nothing");
      assert.equal(w.fake.rejected.length, 0);
      const st = await w.action("vaultStatus", {}, user(USER));
      assert.equal(st.exposure.ok, false);
      assert.match(st.error, /refuses to operate/);
      assert.equal(st.vaultd.reachable, false);
      assert.ok(st.exposure.problems.length >= 1);
    } finally { await w.cleanup(); }
  });
}

test("refusal: installCommand makes no key and no code; enrol-tick makes no enrolment call; start-up logs an error", async () => {
  const w = await makeWorld({ enrolled: false, overrides: { enrol: { pins: { version: "0.1.0", baseUrl: "https://example.org/r/", installVaultSha256: "a".repeat(64) }, serviceUser: () => "paperclip" } } });
  try {
    await w.services.state.setEnrol({ code: "ABCD-EFGH-JKMN-PQRS", expiresAt: new Date(Date.now() + 60_000).toISOString(), createdBy: ADMIN, companyId: COMPANY });
    const newDir = path.join(w.roots, "fresh-keys");
    Object.assign(w.data.config[COMPANY], { dataDir: newDir });
    await assert.rejects(w.action("installCommand", {}, user(ADMIN)), /refusing to create the key or a code/);
    assert.equal(fs.existsSync(newDir), false, "no key directory was created inside the exposed root");
    await w.c.jobs["enrol-tick"]({});
    assert.equal(w.fake.calls.length, 0);
    await w.services.checkExposureAtStart();
    const err = w.c.logs.find((l) => l.level === "error" && /reachable from agent sandboxes/.test(l.message));
    assert.ok(err);
    assert.match(err.meta.problems[0], /dataDir/);
  } finally { await w.cleanup(); }
});

test("a correct setup is not refused", async () => {
  const w = await makeWorld();
  try {
    await w.clearModel();
    const res = await w.tool("vault_request_login", { site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 20 });
    assert.equal(res.data.status, "ready");
    await w.services.checkExposureAtStart();
    assert.equal(w.c.logs.filter((l) => l.level === "error").length, 0);
  } finally { await w.cleanup(); }
});

test("an unreadable parent directory cannot be resolved and is refused (fail closed)", () => {
  const dir = mk();
  try {
    fs.mkdirSync(path.join(dir, "locked"));
    fs.chmodSync(path.join(dir, "locked"), 0o000);
    const r = checkExposure(base({ socketPath: path.join(dir, "locked", "s.sock") }));
    assert.equal(r.ok, false);
    assert.deepEqual(r.problems.map((p) => [p.what, p.code]), [["socketPath", "unresolvable"]]);
  } finally { fs.chmodSync(path.join(dir, "locked"), 0o700); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("fail closed: with no workspaceRoots the check fails, whatever else is set", () => {
  for (const over of [{ workspaceRoots: [] }, { workspaceRoots: [], agentHomeRoot: "/srv/homes", instanceRoot: "/srv/paperclip", sandboxExtraPaths: ["/opt/tools"] }]) {
    const r = checkExposure(base(over));
    assert.equal(r.ok, false);
    assert.deepEqual(r.problems.map((p) => [p.what, p.code]), [["workspaceRoots", "not_configured"]]);
    assert.match(r.problems[0].message, /workspaceRoots is not set/);
  }
});

test("no workspaceRoots: no signed call, tools fail closed, vaultStatus says what to configure", async () => {
  const w = await makeWorld({ config: { workspaceRoots: [] } });
  try {
    await w.clearModel();
    const calls = w.fake.calls.length;
    const res = await w.tool("vault_request_login", { site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 20 });
    assert.equal(res.data.code, "exposed");
    await assert.rejects(w.action("listLeases", {}, user(USER)), /workspaceRoots is not set/);
    await w.c.jobs["lease-sweep"]({});
    await w.c.jobs["enrol-tick"]({});
    assert.equal(w.fake.calls.length, calls, "vaultd saw nothing");
    const st = await w.action("vaultStatus", {}, user(USER));
    assert.deepEqual(st.configure, ["workspaceRoots"]);
    assert.match(st.error, /workspaceRoots is not set/);
    assert.doesNotMatch(st.error, /Move the key directory/);
  } finally { await w.cleanup(); }
});
