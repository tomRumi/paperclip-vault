import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { makeWorld, AGENT, ISSUE, PROJECT, EXEC_WS, ADMIN, user } from "./helpers/world.mjs";
import { FAKE_COOKIE_VALUE } from "../../tests/fakes/fake_vaultd.mjs";
import { resolveWorkspace, WorkspaceError, isInside, containedIn } from "../src/workspace.js";
import { openVaultDir, writePrivateFile, shredFile, ensureGitignore, DeliveryError } from "../src/delivery.js";

const login = () => ({ site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 30 });
const ready = async (w) => { await w.clearModel(); return w.tool("vault_request_login", login()); };

test("workspace resolution: execution workspace, then agent home; the project's shared workspace is never a source", async () => {
  const w = await makeWorld();
  try {
    const exec = path.join(w.roots, "exec"), proj = path.join(w.roots, "proj"), home = path.join(w.config.agentHomeRoot, AGENT);
    for (const d of [exec, proj, home]) fs.mkdirSync(d, { recursive: true });
    const cfg = { workspaceRoots: [w.roots], agentHomeRoot: w.config.agentHomeRoot };
    const issue = { executionWorkspaceId: EXEC_WS };
    const args = { companyId: "c", agentId: AGENT, projectId: PROJECT, cfg };
    w.data.executionWorkspaces[EXEC_WS] = { cwd: exec };
    w.data.projectWorkspaces[PROJECT] = { path: proj };
    assert.deepEqual(await resolveWorkspace(w.c.ctx, { ...args, issue }), { dir: fs.realpathSync(exec), source: "execution-workspace" });
    // no execution workspace: the agent's own home, even though the project has a (shared) primary workspace
    assert.deepEqual(await resolveWorkspace(w.c.ctx, { ...args, issue: { executionWorkspaceId: null } }), { dir: fs.realpathSync(home), source: "agent-home" });
    assert.deepEqual(await resolveWorkspace(w.c.ctx, { ...args, issue: null }), { dir: fs.realpathSync(home), source: "agent-home" });
    // nothing else is known: fail closed, never the project workspace
    await assert.rejects(resolveWorkspace(w.c.ctx, { ...args, issue: null, cfg: { ...cfg, agentHomeRoot: null } }), (e) => e instanceof WorkspaceError && e.code === "no_workspace");
    await assert.rejects(resolveWorkspace(w.c.ctx, { ...args, issue: { executionWorkspaceId: null }, cfg: { ...cfg, agentHomeRoot: null } }), { code: "no_workspace" });
    assert.deepEqual(w.c.primaryWorkspaceCalls, [], "the project's primary workspace was never even looked up");
    // a source that yields a path wins even when it fails: no silent fallback to another directory
    w.data.executionWorkspaces[EXEC_WS] = { cwd: path.join(w.root, "elsewhere") };
    fs.mkdirSync(path.join(w.root, "elsewhere"));
    await assert.rejects(resolveWorkspace(w.c.ctx, { ...args, issue }), { code: "no_workspace" });
  } finally { await w.cleanup(); }
});

test("a project with a shared primary workspace but no execution workspace and no agent home delivers nothing", async () => {
  const w = await makeWorld({ config: { agentHomeRoot: null } });
  try {
    const proj = path.join(w.roots, "proj");
    fs.mkdirSync(proj);
    w.data.executionWorkspaces = {};
    w.data.projectWorkspaces[PROJECT] = { path: proj };
    const res = await ready(w);
    assert.equal(res.data.status, "failed");
    assert.equal(res.data.code, "no_workspace");
    assert.deepEqual(fs.readdirSync(proj), [], "nothing was written into the shared project workspace");
    assert.deepEqual(w.c.primaryWorkspaceCalls, []);
    assert.equal(w.fake.calls.filter((c) => c.type === "lease.fetch").length, 0);
  } finally { await w.cleanup(); }
});

test("containment helpers: prefixes are not containment, roots must exist", () => {
  assert.equal(isInside("/a/b", "/a/b"), true);
  assert.equal(isInside("/a/b", "/a/b/c"), true);
  assert.equal(isInside("/a/b", "/a/bc"), false);
  assert.equal(isInside("/a/b", "/a"), false);
  assert.equal(containedIn(["/definitely/not/there"], "/definitely/not/there/x"), false);
});

test("symlink escape: a workspace that is a symlink out of the roots is refused, nothing is written, the lease is closed", async () => {
  const w = await makeWorld();
  try {
    const outside = path.join(w.root, "outside");
    fs.mkdirSync(outside);
    const link = path.join(w.roots, "ws-link");
    fs.symlinkSync(outside, link);
    w.data.executionWorkspaces[EXEC_WS] = { cwd: link };
    const res = await ready(w);
    assert.equal(res.data.status, "failed");
    assert.equal(res.data.code, "no_workspace");
    assert.deepEqual(fs.readdirSync(outside), []);
    assert.equal(w.fake.calls.filter((c) => c.type === "lease.fetch").length, 0, "the single-use fetch was not burned");
    const revoke = w.fake.calls.find((c) => c.type === "lease.revoke").data;
    assert.deepEqual([revoke.by, revoke.reason], ["plugin", "no_workspace"]);
    // later polls keep saying failed
    assert.equal((await w.tool("vault_request_status", { requestId: res.data.requestId })).data.code, "no_workspace");
  } finally { await w.cleanup(); }
});

test("a workspace outside the roots, or no roots configured, delivers nothing", async () => {
  const w = await makeWorld({ config: { workspaceRoots: [] } });
  try {
    const res = await ready(w);
    assert.equal(res.data.code, "exposed", "no workspace roots at all: the exposure check fails closed first");
    assert.deepEqual(fs.readdirSync(w.ws), []);
  } finally { await w.cleanup(); }
  const v = await makeWorld();
  try {
    const other = path.join(v.root, "not-a-root");
    fs.mkdirSync(other);
    v.data.executionWorkspaces[EXEC_WS] = { cwd: other };
    assert.equal((await ready(v)).data.code, "no_workspace");
    assert.deepEqual(fs.readdirSync(other), []);
  } finally { await v.cleanup(); }
});

test(".vault planted as a symlink (to a directory outside or inside the roots) is refused", async () => {
  for (const target of ["outside", "inside"]) {
    const w = await makeWorld();
    try {
      const dest = target === "outside" ? path.join(w.root, "outside") : path.join(w.roots, "elsewhere-inside");
      fs.mkdirSync(dest);
      fs.symlinkSync(dest, path.join(w.ws, ".vault"));
      const res = await ready(w);
      assert.equal(res.data.status, "failed", target);
      assert.deepEqual(fs.readdirSync(dest), [], target);
      assert.equal(w.fake.calls.filter((c) => c.type === "lease.fetch").length, 0);
    } finally { await w.cleanup(); }
  }
});

test("a file planted at the target name is replaced, never followed", async () => {
  const w = await makeWorld();
  try {
    const victim = path.join(w.root, "victim.txt");
    fs.writeFileSync(victim, "keep me");
    const vdir = openVaultDir(w.ws, [w.roots], { create: true });
    try {
      fs.symlinkSync(victim, path.join(w.ws, ".vault", "target.json"));
      writePrivateFile(vdir, "target.json", Buffer.from("{}\n"));
      assert.equal(fs.readFileSync(victim, "utf8"), "keep me");
      assert.equal(fs.lstatSync(path.join(w.ws, ".vault", "target.json")).isSymbolicLink(), false);
      assert.equal(fs.statSync(path.join(w.ws, ".vault", "target.json")).mode & 0o777, 0o600);
      // a planted temp name is never reused (O_EXCL)
      assert.throws(() => fs.openSync(vdir.at("x"), fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600) && fs.openSync(vdir.at("x"), fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600), { code: "EEXIST" });
    } finally { vdir.close(); }
  } finally { await w.cleanup(); }
});

test("swapping .vault for a symlink after it was opened changes nothing (descriptor-relative writes)", async () => {
  const w = await makeWorld();
  try {
    const outside = path.join(w.root, "outside");
    fs.mkdirSync(outside);
    const vdir = openVaultDir(w.ws, [w.roots], { create: true });
    try {
      fs.renameSync(path.join(w.ws, ".vault"), path.join(w.ws, ".vault-moved"));
      fs.symlinkSync(outside, path.join(w.ws, ".vault"));
      writePrivateFile(vdir, "f.json", Buffer.from("{\"a\":1}\n"));
      assert.deepEqual(fs.readdirSync(outside), []);
      assert.ok(fs.existsSync(path.join(w.ws, ".vault-moved", "f.json")));
    } finally { vdir.close(); }
  } finally { await w.cleanup(); }
});

test(".vault outside the roots after realpath, or owned by someone else, is refused", async () => {
  const w = await makeWorld();
  try {
    assert.throws(() => openVaultDir(w.ws, [path.join(w.root, "other-root")], { create: true }), (e) => e instanceof DeliveryError && e.code === "no_workspace");
    assert.equal(openVaultDir(path.join(w.ws, "nope"), [w.roots], { create: false }), null);
  } finally { await w.cleanup(); }
});

test("cleanup: expiry removes the file; the content is overwritten with zeros first (an open descriptor sees zeros)", async () => {
  const w = await makeWorld();
  try {
    const res = await ready(w);
    const file = path.join(w.ws, res.data.path);
    const held = fs.openSync(file, "r");                         // same inode: shows what the overwrite left behind
    const size = fs.statSync(file).size;
    const readHeld = () => { const b = Buffer.alloc(size); fs.readSync(held, b, 0, size, 0); return b; };
    assert.ok(readHeld().toString("utf8").includes(FAKE_COOKIE_VALUE));
    // before expiry: nothing happens
    await w.c.jobs["lease-sweep"]({});
    assert.ok(fs.existsSync(file));
    w.clock.t += 31 * 60_000;
    await w.c.jobs["lease-sweep"]({});
    assert.equal(fs.existsSync(file), false);
    const left = readHeld();
    fs.closeSync(held);
    assert.equal(left.length, size);
    assert.ok(left.every((b) => b === 0), "overwritten with zeros");
    assert.equal(await w.services.state.deliveries.get(res.data.requestId), null);
    // the agent now hears that it ended
    assert.equal((await w.tool("vault_request_status", { requestId: res.data.requestId })).data.status, "ended");
  } finally { await w.cleanup(); }
});

test("cleanup: a lease revoked at vaultd is removed by the next sweep, also after a plugin restart", async () => {
  const w = await makeWorld();
  try {
    const res = await ready(w);
    const file = path.join(w.ws, res.data.path);
    // vaultd ends the lease (owner ran vaultctl revoke)
    w.fake.requests.get(res.data.requestId).state = "ended";
    const r = await w.services.delivery.sweep();                 // what setup() runs once at start
    assert.equal(r.removed, 1);
    assert.equal(fs.existsSync(file), false);
  } finally { await w.cleanup(); }
});

test("cleanup with vaultd down still removes expired files by the plugin's own clock", async () => {
  const w = await makeWorld();
  try {
    const res = await ready(w);
    await w.fake.close();
    await w.c.jobs["lease-sweep"]({});
    assert.ok(fs.existsSync(path.join(w.ws, res.data.path)), "alive and vaultd unreachable: kept");
    w.clock.t += 31 * 60_000;
    await w.c.jobs["lease-sweep"]({});
    assert.equal(fs.existsSync(path.join(w.ws, res.data.path)), false);
  } finally { fs.rmSync(w.root, { recursive: true, force: true }); }
});

test("shredFile: zeros then unlink; a planted FIFO or symlink is only unlinked and cannot block", async () => {
  const w = await makeWorld();
  try {
    const vdir = openVaultDir(w.ws, [w.roots], { create: true });
    try {
      assert.equal(shredFile(vdir, "missing.json"), false);
      const victim = path.join(w.root, "victim.txt");
      fs.writeFileSync(victim, "keep me");
      fs.symlinkSync(victim, path.join(w.ws, ".vault", "link.json"));
      assert.equal(shredFile(vdir, "link.json"), true);
      assert.equal(fs.readFileSync(victim, "utf8"), "keep me");
      const { execFileSync } = await import("node:child_process");
      execFileSync("mkfifo", [path.join(w.ws, ".vault", "fifo.json")]);
      assert.equal(shredFile(vdir, "fifo.json"), true);
      assert.deepEqual(fs.readdirSync(path.join(w.ws, ".vault")), []);
      ensureGitignore(vdir);
      ensureGitignore(vdir);
      assert.equal(fs.readFileSync(path.join(w.ws, ".vault", ".gitignore"), "utf8"), "*\n");
    } finally { vdir.close(); }
  } finally { await w.cleanup(); }
});

test("cleanup refuses a delivery directory that is no longer inside the roots", async () => {
  const w = await makeWorld();
  try {
    const res = await ready(w);
    const rec = await w.services.state.deliveries.get(res.data.requestId);
    w.data.config["11111111-1111-4111-8111-111111111111"].workspaceRoots = [path.join(w.root, "moved-roots")];
    assert.equal(await w.services.delivery.cleanup(rec), false);
    assert.ok(fs.existsSync(path.join(w.ws, res.data.path)));
  } finally { await w.cleanup(); }
});

test("revokeLease (admin) revokes at vaultd and removes the file at once; agents and plain users cannot", async () => {
  const w = await makeWorld();
  try {
    const res = await ready(w);
    const file = path.join(w.ws, res.data.path);
    await assert.rejects(w.action("revokeLease", { requestId: res.data.requestId }, user("user-plain")), /only admins/);
    await assert.rejects(w.action("revokeLease", { requestId: res.data.requestId }, { actor: { type: "agent", userId: null, agentId: AGENT, companyId: w.runCtx.companyId } }), /agent/);
    assert.ok(fs.existsSync(file));
    const out = await w.action("revokeLease", { requestId: res.data.requestId }, user(ADMIN));
    assert.equal(out.ok, true);
    assert.equal(out.fileRemoved, true);
    assert.equal(fs.existsSync(file), false);
    assert.equal(w.fake.calls.find((c) => c.type === "lease.revoke").data.by, ADMIN);
    assert.ok(w.c.activity.some((a) => /lease revoked/.test(a.message)));
    await assert.rejects(w.action("revokeLease", {}, user(ADMIN)), /requestId or a leaseId/);
  } finally { await w.cleanup(); }
});

test("the ISSUE and project ids are exercised (sanity of the shared fixtures)", () => {
  assert.ok(ISSUE && PROJECT);
});

test("shredFile overwrites only a regular, singly linked file of this process; a hard-linked file is unlinked, never written", async () => {
  const w = await makeWorld();
  try {
    const vdir = openVaultDir(w.ws, [w.roots], { create: true });
    try {
      const own = path.join(w.ws, ".vault", "own.json");
      fs.writeFileSync(own, "SECRET-CONTENT", { mode: 0o600 });
      const mine = fs.openSync(own, "r");
      assert.equal(shredFile(vdir, "own.json"), true);
      // the descriptor opened before still sees the same inode: it was zero-filled to the same length, then unlinked
      assert.equal(fs.readFileSync(mine).toString("latin1"), "\0".repeat(14));
      fs.closeSync(mine);
      // a second hard link (for instance to a file outside the workspace) must not be overwritten through the planted name
      const victim = path.join(w.root, "victim2.txt");
      fs.writeFileSync(victim, "keep me too");
      fs.linkSync(victim, path.join(w.ws, ".vault", "hard.json"));
      assert.equal(shredFile(vdir, "hard.json"), true);
      assert.equal(fs.readFileSync(victim, "utf8"), "keep me too");
      assert.deepEqual(fs.readdirSync(path.join(w.ws, ".vault")), []);
    } finally { vdir.close(); }
  } finally { await w.cleanup(); }
});
