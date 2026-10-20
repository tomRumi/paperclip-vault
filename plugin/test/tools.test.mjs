import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { makeWorld, AGENT, OTHER_AGENT, RUN, ISSUE, COMPANY, PROJECT, user, ADMIN } from "./helpers/world.mjs";
import { FAKE_COOKIE_VALUE, FAKE_ACCESS_TOKEN } from "../../tests/fakes/fake_vaultd.mjs";
import { ALL_MESSAGES } from "../src/messages.js";
import manifest from "../src/manifest.js";

const login = (over = {}) => ({ site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 45, ...over });
const SECRETS = [FAKE_COOKIE_VALUE, FAKE_ACCESS_TOKEN];
const noSecrets = (result) => { const t = JSON.stringify(result); for (const s of SECRETS) assert.ok(!t.includes(s), "a secret leaked into a tool result"); };
const modeOf = (p) => fs.statSync(p).mode & 0o777;

test("tools are registered with the manifest declarations and gateway-friendly names", async () => {
  const w = await makeWorld();
  try {
    assert.deepEqual(Object.keys(w.c.tools).sort(), ["vault_list_sites", "vault_request_credential", "vault_request_login", "vault_request_status"]);
    assert.deepEqual(manifest.tools.map((t) => t.name).sort(), Object.keys(w.c.tools).sort());
    // the gateway classes a tool by its name: no write/create/send/delete verbs
    for (const name of Object.keys(w.c.tools)) assert.doesNotMatch(name, /write|create|send|apply|delete|remove|update|set|post|put/);
    assert.equal(w.c.tools.vault_request_login.decl.parametersSchema.properties.minutes.maximum, 480);
  } finally { await w.cleanup(); }
});

test("login request: approved, session file delivered with mode 0600, result carries only path and expiry", async () => {
  const w = await makeWorld();
  try {
    await w.clearModel();
    const res = await w.tool("vault_request_login", login());
    noSecrets(res);
    assert.equal(res.data.status, "ready", JSON.stringify(res));
    assert.match(res.data.requestId, /^req_[0-9a-f]{16}$/);
    assert.match(res.data.path, /^\.vault\/example-admin-[0-9a-f]{8}\.session\.json$/);
    assert.equal(res.data.minutes, 45);
    assert.ok(Date.parse(res.data.expiresAt) > Date.now());
    assert.deepEqual(JSON.parse(res.content), res.data);
    assert.deepEqual(Object.keys(res.data).sort(), ["expiresAt", "message", "minutes", "path", "requestId", "status"]);

    const file = path.join(w.ws, res.data.path);
    assert.equal(modeOf(file), 0o600);
    assert.equal(modeOf(path.join(w.ws, ".vault")), 0o700);
    assert.equal(fs.readFileSync(path.join(w.ws, ".vault", ".gitignore"), "utf8"), "*\n");
    const state = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.equal(state.cookies[0].value, FAKE_COOKIE_VALUE);
    assert.deepEqual(fs.readdirSync(path.join(w.ws, ".vault")).filter((n) => n.startsWith(".tmp-")), [], "no temp file left behind");

    // what vaultd received: ids from the run guard, context from Paperclip, the verdict with raw samples
    const create = w.fake.calls.find((c) => c.type === "request.create").data;
    assert.deepEqual(create.agent, { agentId: AGENT, runId: RUN, companyId: COMPANY, issueId: ISSUE });
    assert.deepEqual(create.context, { issue_title: "[Test] Check the admin UI", issue_project: "example-site", stage: "Test" });
    assert.equal(create.kind, "login");
    const verdict = w.fake.calls.find((c) => c.type === "verdict.submit").data;
    assert.equal(verdict.k, 2);
    assert.equal(verdict.raw.length, 2);
    assert.equal(verdict.decision, "b");
    assert.equal(verdict.minutes, 45);
    assert.equal(verdict.provider, "fake:provider");
    assert.equal(verdict.model, "good-model");
    assert.match(verdict.renderedSha256, /^[0-9a-f]{64}$/);
    const ack = w.fake.calls.find((c) => c.type === "lease.ack").data;
    assert.equal(ack.relPath, res.data.path);
    // a repeat poll answers from the delivery record and does not fetch again
    const again = await w.tool("vault_request_status", { requestId: res.data.requestId });
    assert.equal(again.data.status, "ready");
    assert.equal(again.data.path, res.data.path);
    assert.equal(w.fake.calls.filter((c) => c.type === "lease.fetch").length, 1);
    // the service state holds metadata only
    const dump = JSON.stringify([...w.c.store.values()]);
    for (const s of SECRETS) assert.ok(!dump.includes(s));
    assert.ok(!JSON.stringify(w.c.logs).includes(FAKE_COOKIE_VALUE));
  } finally { await w.cleanup(); }
});

test("credential request writes <name>-<lease>.token.json with the token file shape", async () => {
  const w = await makeWorld();
  try {
    await w.clearModel();
    const res = await w.tool("vault_request_credential", { credential: "deploy-token", reason: "Deploy the fix for ticket 12", minutes: 20 });
    noSecrets(res);
    assert.equal(res.data.status, "ready");
    assert.match(res.data.path, /^\.vault\/deploy-token-[0-9a-f]{8}\.token\.json$/);
    const file = path.join(w.ws, res.data.path);
    assert.equal(modeOf(file), 0o600);
    const body = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.deepEqual(Object.keys(body).sort(), ["accessToken", "expiresAt", "scopes", "tokenType"]);
    assert.equal(body.accessToken, FAKE_ACCESS_TOKEN);
  } finally { await w.cleanup(); }
});

test("pending then ready: the tool answers pending after toolWaitMs; the poll and the sweep deliver", async () => {
  const w = await makeWorld({ fake: { issueDelayMs: 400 }, config: { toolWaitMs: 100 } });
  try {
    await w.clearModel();
    const first = await w.tool("vault_request_login", login());
    assert.ok(["pending", "preparing"].includes(first.data.status), JSON.stringify(first));
    assert.match(first.data.requestId, /^req_/);
    assert.ok(!first.data.path);
    await new Promise((r) => setTimeout(r, 120));
    // vaultd's clock for issuing is the plugin's clock here: move it past the delay
    w.clock.t += 1000;
    const polled = await w.tool("vault_request_status", { requestId: first.data.requestId });
    assert.equal(polled.data.status, "ready", JSON.stringify(polled));
    assert.ok(fs.existsSync(path.join(w.ws, polled.data.path)));

    // second request delivered by the sweep job, never polled by the agent
    w.fake.issueDelayMs = 400;
    w.fake.requests.clear();
    const second = await w.tool("vault_request_credential", { credential: "deploy-token", reason: "Deploy the fix for ticket 12", minutes: 10 });
    assert.notEqual(second.data.status, "ready");
    w.clock.t += 1000;
    await w.c.jobs["lease-sweep"]({});
    const done = await w.services.state.deliveries.get(second.data.requestId);
    assert.ok(done, "the sweep delivered it");
    assert.ok(fs.existsSync(path.join(w.ws, done.relPath)));
    assert.equal(await w.services.state.pending.get(second.data.requestId), null);
  } finally { await w.cleanup(); }
});

test("run guard: every rejection is answered without contacting vaultd", async () => {
  const w = await makeWorld();
  try {
    await w.clearModel();
    const createCalls = () => w.fake.calls.filter((c) => c.type === "request.create").length;
    const expectRefused = async (runCtx) => {
      const res = await w.tool("vault_request_login", login(), runCtx);
      assert.ok(res.error, JSON.stringify(res));
      assert.equal(res.data.code, "run_guard");
      noSecrets(res);
    };
    await expectRefused({ ...w.runCtx, runId: "33333333-3333-4333-8333-000000000000" });          // not a run of this agent
    await expectRefused({ ...w.runCtx, agentId: OTHER_AGENT });                                    // agent is not the run's agent
    await expectRefused({ ...w.runCtx, companyId: "11111111-1111-4111-8111-000000000000" });      // wrong company
    await expectRefused({ ...w.runCtx, runId: "not-a-uuid" });
    w.data.runs[0].status = "succeeded";
    await expectRefused(w.runCtx);                                                                // run no longer running
    w.data.runs[0].status = "running";
    w.data.issues[ISSUE].status = "blocked";
    await expectRefused(w.runCtx);                                                                // issue not in progress
    w.data.issues[ISSUE].status = "in_progress";
    w.data.issues[ISSUE].assigneeAgentId = OTHER_AGENT;
    await expectRefused(w.runCtx);                                                                // issue assigned to someone else
    w.data.issues[ISSUE].assigneeAgentId = AGENT;
    w.data.runs[0].issueId = null;
    await expectRefused(w.runCtx);                                                                // run without an issue
    w.data.runs[0].issueId = ISSUE;
    delete w.data.issues[ISSUE];
    await expectRefused(w.runCtx);                                                                // issue gone
    assert.equal(createCalls(), 0);
    const q = w.c.dbQueries[0];
    assert.match(q.sql, /FROM public\.heartbeat_runs/);
    assert.match(q.sql, /status = 'running'/);
    assert.deepEqual(q.params.slice(0, 3).length, 3);
  } finally { await w.cleanup(); }
});

test("parameter validation happens before the run guard or vaultd", async () => {
  const w = await makeWorld();
  try {
    for (const bad of [{ ...login(), site: "Bad Site!" }, { ...login(), reason: "short" }, { ...login(), reason: "x".repeat(501) }, { ...login(), minutes: "45" }, { ...login(), minutes: 4.5 }, { reason: "long enough reason", minutes: 5 }]) {
      const res = await w.tool("vault_request_login", bad);
      assert.equal(res.data.code, "bad_params");
    }
    assert.equal((await w.tool("vault_request_credential", { credential: "../etc", reason: "long enough reason", minutes: 5 })).data.code, "bad_params");
    assert.equal((await w.tool("vault_request_status", { requestId: "req_zzz" })).data.code, "bad_params");
    assert.equal(w.c.dbQueries.length, 0);
    assert.equal(w.fake.calls.length, 0);
  } finally { await w.cleanup(); }
});

test("ceiling denials come back as fixed messages; over-max carries maxMinutes", async () => {
  const w = await makeWorld();
  try {
    await w.clearModel();
    const over = await w.tool("vault_request_login", login({ minutes: 200 }));
    assert.equal(over.data.status, "denied");
    assert.equal(over.data.code, "minutes_over_max");
    assert.equal(over.data.maxMinutes, 60);
    assert.match(over.data.message, /maximum/);
    assert.equal((await w.tool("vault_request_login", login({ site: "nope" }))).data.code, "bad_target");
    assert.equal((await w.tool("vault_request_login", login({ site: "not-ready" }))).data.code, "site_not_ready");
    assert.equal(w.fake.calls.filter((c) => c.type === "verdict.submit").length, 0, "no verdict for a denied request");
    assert.equal(w.provider.calls.length, 0, "the model is not asked");
  } finally { await w.cleanup(); }
});

test("a model that has not passed the judge tests is not asked; the request is denied", async () => {
  const w = await makeWorld();
  try {
    const res = await w.tool("vault_request_login", login());
    assert.equal(res.data.status, "denied", JSON.stringify(res));
    assert.equal(w.provider.calls.length, 0);
    const v = w.fake.calls.find((c) => c.type === "verdict.submit").data;
    assert.equal(v.decision, "c");
    assert.deepEqual(v.raw, []);
    assert.ok(w.c.logs.some((l) => l.level === "warn" && /has not passed/.test(l.message)));
    assert.equal(fs.existsSync(path.join(w.ws, ".vault")), false);
  } finally { await w.cleanup(); }
});

test("verdicts: disagreement denies, all-d locks the agent, provider failure denies", async () => {
  const sample = (decision, max_minutes) => ({ decision, max_minutes, reason: "r" });
  const cases = [
    { name: "b+c", samples: [sample("b", 60), sample("c", 0)], status: "denied", code: "judge_deny" },
    { name: "a+d", samples: [sample("a", 30), sample("d", 0)], status: "denied", code: "judge_deny" },
    { name: "parse failure", samples: [sample("b", 60), { decision: "c", max_minutes: 0, reason: "", parseFailed: true }], status: "denied", code: "judge_deny" },
    { name: "d+d", samples: [sample("d", 0), sample("d", 0)], status: "denied", code: "judge_lock" },
  ];
  for (const c of cases) {
    const w = await makeWorld({ provider: { id: "fake:provider", calls: [], listModels: async () => [], judge: async () => c.samples } });
    try {
      await w.clearModel();
      const res = await w.tool("vault_request_login", login());
      assert.equal(res.data.status, c.status, c.name);
      assert.equal(res.data.code, c.code, c.name);
      if (c.code === "judge_lock") {
        assert.ok(w.fake.locked.has(AGENT));
        const next = await w.tool("vault_request_credential", { credential: "deploy-token", reason: "Deploy the fix for ticket 12", minutes: 5 });
        assert.equal(next.data.code, "agent_locked");
      }
      assert.equal(fs.existsSync(path.join(w.ws, ".vault")), false);
    } finally { await w.cleanup(); }
  }
  const w = await makeWorld({ provider: { id: "fake:provider", calls: [], listModels: async () => [], judge: async () => { throw new Error("boom"); } } });
  try {
    await w.clearModel();
    const res = await w.tool("vault_request_login", login());
    assert.equal(res.data.status, "denied");
    assert.deepEqual(w.fake.calls.find((c) => c.type === "verdict.submit").data.raw, []);
  } finally { await w.cleanup(); }
});

test("status is only for the requesting agent; unknown and foreign ids look the same", async () => {
  const w = await makeWorld({ fake: { issueDelayMs: 99999 }, config: { toolWaitMs: 50 } });
  try {
    await w.clearModel();
    const res = await w.tool("vault_request_login", login());
    const mine = await w.tool("vault_request_status", { requestId: res.data.requestId });
    assert.ok(["pending", "preparing"].includes(mine.data.status));
    const theirs = await w.tool("vault_request_status", { requestId: res.data.requestId }, { ...w.runCtx, agentId: OTHER_AGENT });
    const unknown = await w.tool("vault_request_status", { requestId: "req_0000000000000000" });
    assert.deepEqual(theirs, unknown);
    assert.ok(theirs.error);
  } finally { await w.cleanup(); }
});

test("vault_list_sites exposes only id, purpose, kind and maxMinutes of what the agent may request", async () => {
  const w = await makeWorld({ fake: { sites: [
    { id: "mine", displayName: "Mine", type: "password-totp", kind: "test", purpose: "Test it", allowedAgents: [AGENT], roles: ["QA"], maxMinutes: 30, state: "ready", loginUrl: "https://secret.example/login" },
    { id: "theirs", displayName: "Theirs", type: "password-totp", kind: "owner", purpose: "Not yours", allowedAgents: [OTHER_AGENT], roles: [], maxMinutes: 30, state: "ready" },
    { id: "unready", displayName: "U", type: "oauth", kind: "test", purpose: "x", allowedAgents: [], roles: [], maxMinutes: 30, state: "needs_authorize" },
  ] } });
  try {
    const res = await w.tool("vault_list_sites", {});
    assert.deepEqual(res.data.sites.filter((s) => s.id !== "deploy-token"), [{ id: "mine", purpose: "Test it", kind: "test", maxMinutes: 30 }]);
    assert.ok(!JSON.stringify(res).includes("secret.example"));
    assert.deepEqual(w.fake.calls.find((c) => c.type === "sites.list").data, { agentId: AGENT, companyId: COMPANY });
  } finally { await w.cleanup(); }
});

test("vaultd unreachable or the plugin not enrolled: fixed failure messages, nothing thrown", async () => {
  const w = await makeWorld();
  try {
    await w.fake.close();
    const res = await w.tool("vault_request_login", login());
    assert.equal(res.data.status, "failed");
    assert.equal(res.data.code, "unreachable");
    assert.equal((await w.tool("vault_list_sites", {})).data.status, "failed");
  } finally { fs.rmSync(w.root, { recursive: true, force: true }); }
  const n = await makeWorld({ enrolled: false });
  try {
    const res = await n.tool("vault_request_login", login());
    assert.equal(res.data.code, "not_enrolled");
    assert.equal(n.fake.calls.length, 0);
  } finally { await n.cleanup(); }
});

test("every agent-facing message passes the gateway's content guards and names no secret", () => {
  // the gateway BLOCKS results matching these patterns (tool-content-guards.js)
  const guards = [/\bignore\b.{0,40}\b(previous|above|earlier)\b.{0,40}\binstructions?\b/i, /\b(reveal|print|dump|show)\b.{0,40}\b(system|developer)\b.{0,20}\b(prompt|message|instructions?)\b/i,
    /\b(new|updated)\b.{0,20}\b(system|developer)\b.{0,20}\b(instructions?|message)\b/i, /\b(exfiltrate|leak|steal|send)\b.{0,40}\b(secret|token|api[-_ ]?key|credential)s?\b/i];
  assert.ok(Object.keys(ALL_MESSAGES).length > 40);
  for (const [k, text] of Object.entries(ALL_MESSAGES)) for (const g of guards) assert.doesNotMatch(text, g, k);
  // and no result key is one the gateway redacts
  const redacted = /^[A-Za-z0-9_-]*(?:api[-_]?key|access[-_]?token|auth|token|authorization|bearer|secrets?|passwd|passwords?|credentials?|jwt|private[-_]?key|cookie)/i;
  for (const key of ["status", "requestId", "code", "message", "path", "expiresAt", "minutes", "maxMinutes", "sites", "id", "purpose", "kind"]) assert.doesNotMatch(key, redacted);
});

test("the admin/user context never reaches the tools: a tool needs an agent run context", async () => {
  const w = await makeWorld();
  try {
    // a board actor replaying a run context still faces the run guard's issue and status checks
    const res = await w.tool("vault_request_login", login(), { ...w.runCtx, runId: RUN.replace("3333", "4444") });
    assert.equal(res.data.code, "run_guard");
    assert.ok(user(ADMIN) && PROJECT);
  } finally { await w.cleanup(); }
});
