// The plugin side of the end-to-end test: the plugin's REAL worker logic (src/worker.js register(): tools, actions, jobs,
// signed vaultd client, verdict provider, delivery) over the mocked Paperclip context of the plugin tests
// (plugin/test/helpers/world.mjs makeCtx). Nothing is faked on the vaultd side: the socket is the real vaultd's.
//
// Protocol with tests/e2e/test_e2e.py: one JSON object per line on stdin, one JSON reply per line on stdout.
//   {"id": N, "cmd": "tool",   "name": "vault_request_login", "params": {...}, "agent": "<agent key>"}
//   {"id": N, "cmd": "action", "key": "runJudgeTests", "params": {...}, "as": "admin" | "user" | "agent"}
//   {"id": N, "cmd": "job",    "name": "lease-sweep" | "enrol-tick"}
//   {"id": N, "cmd": "call",   "type": "request.create", "data": {...}}     a signed vaultd call as the enrolled plugin
//   {"id": N, "cmd": "sign",   "type": "hello", "data": {}, "installId": "inst-..." | omitted = enrolled one}
//                                                                       -> {line, nonce}: a signed wire line for raw tests
//   {"id": N, "cmd": "state"}                                            -> install, pending, deliveries, model
//   {"id": N, "cmd": "logs"}                                             -> what the worker logged
// Reply: {"id": N, "ok": true, "result": ...} | {"id": N, "ok": false, "error": {"code", "message"}}
// stdout carries the protocol only. Usage: node plugin_driver.mjs <config.json>
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN = path.resolve(HERE, "../../plugin");
const mod = (rel) => import(pathToFileURL(path.join(PLUGIN, rel)).href);
const { register } = await mod("src/worker.js");
const { createVaultClient, buildRequest } = await mod("src/client.js");
const { loadKey } = await mod("src/keys.js");
const { makeCtx } = await mod("test/helpers/world.mjs");

const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const { companyId, adminUserId, plainUserId, agents } = cfg;

const runCtx = (key) => {
  const a = agents[key];
  if (!a) throw new Error(`unknown agent key ${key}`);
  return { agentId: a.agentId, runId: a.runId, companyId, projectId: cfg.projectId };
};

// What the host would answer: the agents' running heartbeat runs, their in-progress issues and execution workspaces.
const data = {
  config: { [companyId]: cfg.pluginConfig },
  runs: Object.values(agents).map((a) => ({ id: a.runId, agentId: a.agentId, companyId, status: "running", issueId: a.issueId })),
  issues: Object.fromEntries(Object.values(agents).map((a) => [a.issueId, {
    id: a.issueId, projectId: cfg.projectId, title: a.issueTitle, status: "in_progress", assigneeAgentId: a.agentId, executionWorkspaceId: a.execWorkspaceId,
  }])),
  projects: { [cfg.projectId]: { id: cfg.projectId, name: "todo-api" } },
  executionWorkspaces: Object.fromEntries(Object.values(agents).map((a) => [a.execWorkspaceId, { id: a.execWorkspaceId, cwd: a.workspace, path: a.workspace }])),
  projectWorkspaces: {},
  secret: "",
};

const c = makeCtx(data);
// Real provider (HTTP to the fake chat-completions server), real vaultd client, real clock and timers. Only the release pins
// (a dev checkout has none) and the service-user name shown in the install command are given.
const services = register(c.ctx, { enrol: { pins: cfg.pins, serviceUser: () => "vault-svc" } });
const client = createVaultClient({
  socketPath: cfg.pluginConfig.socketPath,
  getKey: () => loadKey(cfg.pluginConfig.dataDir),
  getInstallId: async () => (await services.state.install())?.installId ?? null,
});

const contextFor = (as) => {
  const actor = as === "agent"
    ? { type: "agent", userId: null, agentId: Object.values(agents)[0].agentId, runId: Object.values(agents)[0].runId, companyId }
    : { type: "user", userId: as === "admin" ? adminUserId : plainUserId, agentId: null, runId: null, companyId };
  return { actor, companyId };
};

const commands = {
  async tool({ name, params, agent }) { return c.tools[name].fn(params, runCtx(agent)); },
  async action({ key, params, as }) { return c.actions[key](params ?? {}, contextFor(as ?? "admin")); },
  async job({ name }) { return (await c.jobs[name]()) ?? null; },
  async call({ type, data: d }) { return client.call(type, d ?? {}); },
  async sign({ type, data: d, installId }) {
    const key = loadKey(cfg.pluginConfig.dataDir);
    const id = installId === undefined ? (await services.state.install())?.installId ?? null : installId;
    return buildRequest({ key, installId: id, type, data: d ?? {} });
  },
  async state() {
    return {
      install: await services.state.install(), pending: await services.state.pending.all(), deliveries: await services.state.deliveries.all(),
      model: await services.state.model(), judgeRun: await services.state.judgeRun(),
    };
  },
  async logs() { return c.logs; },
};

const out = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);
const rl = readline.createInterface({ input: process.stdin });
const running = new Set();
rl.on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  const p = (async () => {
    try {
      const fn = commands[msg.cmd];
      if (!fn) throw Object.assign(new Error(`unknown command ${msg.cmd}`), { code: "bad_command" });
      out({ id: msg.id, ok: true, result: (await fn(msg)) ?? null });
    } catch (e) {
      out({ id: msg.id, ok: false, error: { code: e?.code ?? e?.name ?? "error", message: String(e?.message ?? e).slice(0, 500) } });
    }
  })().finally(() => running.delete(p));
  running.add(p);
});
rl.on("close", async () => {
  await Promise.allSettled([...running]);
  await services.judge.whenIdle().catch(() => {});
  process.exit(0);
});
