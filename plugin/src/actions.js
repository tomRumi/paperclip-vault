// Actions behind the Vault page (ctx.actions: the only plugin calls that carry the caller's identity, which is why every UI
// read is an action, not a data key). Everything goes through guarded():
//   reads   listSites, getCeilings, listLog, listLeases, vaultStatus, judgeStatus, judgeTestStatus
//           -> a signed-in user (agents and system calls refused)
//   writes  installCommand, uninstallCommand, addSiteCommand, removeSiteCommand, revokeLease, selectModel, refreshModels,
//           runJudgeTests
//           -> a user listed in the company's adminUserIds (see assert-admin.js)
// vaultStatus also tells the page whether the caller may use the writes (canEdit), so it can show read-only views.
// The decision log and the leases are read live from vaultd (log.read, leases.list): vaultd is the single source of truth.
import { guarded, assertAdmin, NotAllowedError } from "./assert-admin.js";
import { readConfig } from "./config.js";
import { THRESHOLDS } from "./judge.js";
import { normalizeBaseUrl, baseUrlProblem } from "./verdict/provider.js";
import { PLUGIN_ID } from "./manifest.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID_RE = /^req_[0-9a-f]{16}$/;
const LEASE_ID_RE = /^lse_[0-9a-f]{16}$/;

export class BadParams extends Error {
  constructor(message) { super(message); this.name = "BadParams"; this.code = "BAD_PARAMS"; }
}

export const READ_ACTIONS = ["listSites", "getCeilings", "listLog", "listLeases", "vaultStatus", "judgeStatus", "judgeTestStatus"];
export const WRITE_ACTIONS = ["installCommand", "uninstallCommand", "addSiteCommand", "removeSiteCommand", "revokeLease", "selectModel", "refreshModels", "runJudgeTests"];

export function createActions({ ctx, state, clientFor, enrol, delivery, judge }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };

  /** Company whose settings apply: the caller's, else the one named in params (company-less instance-admin calls). */
  const companyOf = (params, context, actor) => {
    const id = actor.companyId ?? context?.companyId ?? params?.companyId;
    if (typeof id !== "string" || !UUID_RE.test(id)) throw new BadParams("a company id is needed: open this page from a company");
    return id;
  };
  const cfgOf = async (params, context, actor) => readConfig(ctx, companyOf(params, context, actor));
  const vault = async (cfg, type, data = {}) => clientFor(cfg).call(type, data);

  async function activity(companyId, message, metadata) {
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  }

  /** Whether this caller may use the write actions: the Vault page shows read-only views to everyone else. */
  async function canEdit(context) {
    try { await assertAdmin(ctx, context); return true; }
    catch (e) { if (e instanceof NotAllowedError) return false; throw e; }
  }

  const reads = {
    listSites: async (p, c, a) => vault(await cfgOf(p, c, a), "sites.list", {}),
    getCeilings: async (p, c, a) => vault(await cfgOf(p, c, a), "ceilings.get", {}),
    listLeases: async (p, c, a) => vault(await cfgOf(p, c, a), "leases.list", {}),
    listLog: async (p, c, a) => {
      const limit = Number.isInteger(p.limit) ? Math.min(Math.max(p.limit, 1), 200) : 50;
      const data = { limit };
      if (p.before !== undefined && p.before !== null) {
        if (!Number.isInteger(p.before) || p.before < 0) throw new BadParams("before must be a log sequence number");
        data.beforeSeq = p.before;
      }
      return vault(await cfgOf(p, c, a), "log.read", data);
    },
    vaultStatus: async (_p, c, a) => ({ ...(await enrol.status(c, a)), canEdit: await canEdit(c) }),
    judgeStatus: async (p, c, a) => {
      const cfg = await cfgOf(p, c, a);
      const g = cfg.judge;
      let endpoint = null;
      try { endpoint = normalizeBaseUrl(g.baseUrl) ? new URL(g.baseUrl).host : null; } catch { endpoint = null; }
      return {
        configured: endpoint !== null, endpoint, configProblem: g.baseUrl ? baseUrlProblem(g.baseUrl) : null, keyConfigured: Boolean(g.apiKey), k: g.k, temperature: g.temperature, perCallTimeoutMs: g.perCallTimeoutMs,
        selected: await state.model(), models: await state.models(), gate: await judge.gate(cfg),
      };
    },
    judgeTestStatus: async (p, c, a) => {
      const cfg = await cfgOf(p, c, a);
      let current = null;
      try { current = await judge.hashes(cfg); } catch { current = null; }
      const records = Object.values(await state.records.all()).map((r) => ({
        model: r.model, provider: r.provider, k: r.k, clean: r.clean, at: r.at, metrics: r.metrics, promptSha256: r.promptSha256, scenariosSha256: r.scenariosSha256,
        current: Boolean(current) && r.promptSha256 === current.promptSha256 && r.scenariosSha256 === current.scenariosSha256 && r.k === cfg.judge.k,
      }));
      return { run: await state.judgeRun(), running: judge.isRunning(), records, thresholds: THRESHOLDS, scenarios: current };
    },
  };

  const writes = {
    installCommand: async (p, c, a) => enrol.installCommand(p, c, a),
    uninstallCommand: async (p) => enrol.uninstallCommand(p),
    addSiteCommand: async (p) => enrol.addSiteCommand(p),
    removeSiteCommand: async (p) => enrol.removeSiteCommand(p),
    revokeLease: async (p, c, a) => {
      const requestId = p.requestId, leaseId = p.leaseId;
      if (!(typeof requestId === "string" && REQUEST_ID_RE.test(requestId)) && !(typeof leaseId === "string" && LEASE_ID_RE.test(leaseId))) throw new BadParams("give a requestId or a leaseId");
      const cfg = await cfgOf(p, c, a);
      const res = await vault(cfg, "lease.revoke", { ...(requestId ? { requestId } : { leaseId }), by: a.userId });
      // Do not wait for the sweep: take the file out of the workspace now.
      const mine = requestId ?? Object.values(await state.deliveries.all()).find((d) => d.leaseId === leaseId)?.requestId;
      const removed = mine ? await delivery.removeDelivered(mine) : false;
      await activity(cfg.companyId, "Vault: lease revoked", { requestId: requestId ?? null, leaseId: leaseId ?? null, userId: a.userId });
      return { ok: true, fileRemoved: removed, ...(res && typeof res === "object" ? { state: res.state ?? null } : {}) };
    },
    selectModel: async (p, c, a) => judge.selectModel(p.model, await cfgOf(p, c, a), a),
    refreshModels: async (p, c, a) => judge.modelList(await cfgOf(p, c, a)),
    runJudgeTests: async (p, c, a) => judge.runJudgeTests(p.model, await cfgOf(p, c, a), a),
  };

  function register() {
    for (const [key, fn] of Object.entries(reads)) ctx.actions.register(key, guarded(ctx, "read", fn));
    for (const [key, fn] of Object.entries(writes)) ctx.actions.register(key, guarded(ctx, "write", fn));
  }

  return { register, reads, writes };
}
