// Test world: a mocked plugin context (no live Paperclip), scratch directories, the fake vaultd and the plugin services wired
// to them. Sockets live in short /tmp paths; everything is removed by world.cleanup().
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { register } from "../../src/worker.js";
import { loadOrCreateKey } from "../../src/keys.js";
import { recordKey } from "../../src/state.js";
import { startFakeVaultd, PROMPT_SHA, SCENARIOS_SHA } from "../../../tests/fakes/fake_vaultd.mjs";

export const COMPANY = "11111111-1111-4111-8111-111111111111";
export const AGENT = "22222222-2222-4222-8222-222222222222";
export const OTHER_AGENT = "22222222-2222-4222-8222-999999999999";
export const RUN = "33333333-3333-4333-8333-333333333333";
export const ISSUE = "44444444-4444-4444-8444-444444444444";
export const PROJECT = "55555555-5555-4555-8555-555555555555";
export const EXEC_WS = "66666666-6666-4666-8666-666666666666";
export const ADMIN = "user-admin";
export const USER = "user-plain";

export const user = (userId, companyId = COMPANY) => ({ actor: { type: "user", userId, agentId: null, runId: null, companyId }, companyId });
export const agentActor = () => ({ actor: { type: "agent", userId: null, agentId: AGENT, runId: RUN, companyId: COMPANY }, companyId: COMPANY });
export const systemActor = () => ({ actor: { type: "system", userId: null, agentId: null, runId: null, companyId: COMPANY }, companyId: COMPANY });

/** A mocked PluginContext. `data` holds what the host would answer. */
export function makeCtx(data) {
  const store = new Map();
  const k = (i) => JSON.stringify([i.scopeKind, i.scopeId ?? null, i.namespace ?? "default", i.stateKey]);
  const out = { tools: {}, actions: {}, jobs: {}, logs: [], activity: [], dbQueries: [], secretCalls: [], primaryWorkspaceCalls: [], store };
  const log = (level) => (message, meta) => out.logs.push({ level, message, meta });
  out.ctx = {
    logger: { info: log("info"), warn: log("warn"), error: log("error"), debug: log("debug") },
    config: { get: async (companyId) => structuredClone(data.config[companyId] ?? {}) },
    state: {
      get: async (i) => (store.has(k(i)) ? structuredClone(store.get(k(i))) : null),
      set: async (i, v) => { store.set(k(i), structuredClone(v)); },
      delete: async (i) => { store.delete(k(i)); },
    },
    activity: { log: async (e) => { out.activity.push(e); } },
    tools: { register: (name, decl, fn) => { out.tools[name] = { decl, fn }; } },
    actions: { register: (key, fn) => { out.actions[key] = fn; } },
    jobs: { register: (key, fn) => { out.jobs[key] = fn; } },
    db: {
      query: async (sql, params) => {
        out.dbQueries.push({ sql, params });
        const [runId, agentId, companyId] = params;
        return data.runs.filter((r) => r.id === runId && r.agentId === agentId && r.companyId === companyId && r.status === "running").map((r) => ({ issue_id: r.issueId }));
      },
    },
    issues: { get: async (id) => data.issues[id] ?? null },
    projects: {
      get: async (id) => data.projects?.[id] ?? null,
      // the project's shared workspace must never be consulted; a call is recorded and asserted against in delivery.test.mjs
      getPrimaryWorkspace: async (id) => { out.primaryWorkspaceCalls.push(id); return data.projectWorkspaces?.[id] ?? null; },
    },
    executionWorkspaces: { get: async (id) => data.executionWorkspaces?.[id] ?? null },
    secrets: { resolve: async (ref, opts) => { out.secretCalls.push({ ref, opts }); return data.secret; } },
  };
  return out;
}

/** Everything wired: scratch dirs, mocked ctx, fake vaultd (enrolled) and the plugin services. */
export async function makeWorld(opts = {}) {
  const clock = { t: Date.now() };
  const now = () => clock.t;
  const root = fs.mkdtempSync("/tmp/pcv-");
  const roots = path.join(root, "roots");
  const ws = path.join(roots, "ws1");
  const dataDir = path.join(root, "data");
  const socketPath = path.join(root, "s.sock");
  fs.mkdirSync(ws, { recursive: true });
  const config = {
    adminUserIds: [ADMIN], workspaceRoots: [roots], agentHomeRoot: path.join(roots, "homes"), dataDir, socketPath, toolWaitMs: 3000,
    judge: { baseUrl: "http://127.0.0.1:9/v1", k: 2, temperature: 0.2, perCallTimeoutMs: 2000 },
    ...opts.config,
  };
  const data = {
    config: { [COMPANY]: config },
    runs: [{ id: RUN, agentId: AGENT, companyId: COMPANY, status: "running", issueId: ISSUE }],
    issues: { [ISSUE]: { id: ISSUE, projectId: PROJECT, title: "[Test] Check the admin UI", status: "in_progress", assigneeAgentId: AGENT, executionWorkspaceId: EXEC_WS } },
    projects: { [PROJECT]: { id: PROJECT, name: "example-site" } },
    executionWorkspaces: { [EXEC_WS]: { id: EXEC_WS, cwd: ws, path: ws } },
    projectWorkspaces: {},
    secret: "sk-test-SECRET-KEY-1234567890",
    ...opts.data,
  };
  const c = makeCtx(data);
  const key = loadOrCreateKey(dataDir);
  const fake = await startFakeVaultd({ socketPath, now, preEnrolled: opts.enrolled !== false, enrolledPublicKeyB64: key.publicKeyB64, ...opts.fake });

  const stubProvider = opts.provider ?? {
    id: "fake:provider",
    calls: [],
    async listModels() { return [{ id: "good-model" }]; },
    async judge(args) { this.calls.push(args); return [{ decision: "b", max_minutes: 60, reason: "ok" }, { decision: "b", max_minutes: 45, reason: "ok" }]; },
  };
  const services = register(c.ctx, { providerFor: () => stubProvider, now, sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 15))), ...opts.overrides });
  if (opts.enrolled !== false) await services.state.setInstall({ installId: fake.installId, vaultdVersion: "fake", enrolledAt: new Date().toISOString(), kid: key.kid });

  const world = {
    clock, root, roots, ws, dataDir, socketPath, config, data, c, fake, key, services, provider: stubProvider,
    runCtx: { agentId: AGENT, runId: RUN, companyId: COMPANY, projectId: PROJECT },
    /** Gives the fake a clean test record for the stub provider and selects the model in the plugin. */
    async clearModel(model = "good-model") {
      fake.records.push({ model, provider: stubProvider.id, k: 2, promptSha256: PROMPT_SHA, scenariosSha256: SCENARIOS_SHA, metrics: {}, clean: true });
      await services.state.records.put(recordKey(stubProvider.id, model), { model, provider: stubProvider.id, k: 2, promptSha256: PROMPT_SHA, scenariosSha256: SCENARIOS_SHA, metrics: {}, clean: true, at: new Date().toISOString() });
      await services.state.setModel({ model, provider: stubProvider.id, k: 2, selectedBy: ADMIN, selectedAt: new Date().toISOString() });
    },
    tool: (name, params, runCtx = world.runCtx) => c.tools[name].fn(params, runCtx),
    action: (key, params, context) => c.actions[key](params, context),
    async cleanup() { await fake.close(); fs.rmSync(root, { recursive: true, force: true }); },
  };
  return world;
}

export const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
export { PROMPT_SHA, SCENARIOS_SHA };
