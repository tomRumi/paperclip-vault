import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import manifest from "./manifest.js";
import { createState } from "./state.js";
import { createVaultClient, VaultError } from "./client.js";
import { loadKey } from "./keys.js";
import { checkExposure } from "./exposure.js";
import { providerConfig, readConfig } from "./config.js";
import { createProvider, baseUrlProblem } from "./verdict/provider.js";
import { createEnrol } from "./enrol.js";
import { createDelivery } from "./delivery.js";
import { createJudge } from "./judge.js";
import { createTools } from "./tools.js";
import { createActions } from "./actions.js";

/**
 * Registers tools, actions and jobs on a plugin context. Exported for tests with a fake ctx; `overrides` lets tests inject
 * the vaultd client, the verdict provider, the clock, the sleeper and the release pins.
 */
export function register(ctx, overrides = {}) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  const state = createState(ctx);
  const now = overrides.now ?? (() => Date.now());

  const clientFor = overrides.clientFor ?? ((cfg) => createVaultClient({
    socketPath: cfg.socketPath,
    getKey: () => {
      const key = loadKey(cfg.dataDir);
      if (!key) throw new VaultError("not_enrolled", "the plugin has no signing key yet");
      return key;
    },
    getInstallId: async () => (await state.install())?.installId ?? null,
    preflight: () => {
      const exposure = checkExposure(cfg);
      if (!exposure.ok) throw new VaultError("exposed", `refusing to use the vault: ${exposure.problems.map((p) => p.message).join("; ")}`);
    },
  }));
  const providerFor = overrides.providerFor ?? ((cfg) => createProvider(providerConfig(cfg), ctx, { fetch: overrides.fetch }));

  const enrol = createEnrol({ ctx, state, clientFor, now, pluginVersion: manifest.version, ...overrides.enrol });
  const delivery = createDelivery({ ctx, state, clientFor, now });
  const judge = createJudge({ ctx, state, clientFor, providerFor, now, ...overrides.judge });
  const tools = createTools({ ctx, state, clientFor, delivery, judge, now, sleep: overrides.sleep });
  const actions = createActions({ ctx, state, clientFor, enrol, delivery, judge, providerFor });

  tools.register();
  actions.register();

  // One run of a job at a time: a slow vaultd must not stack up sweeps.
  const once = (name, fn) => {
    let busy = false;
    return async () => {
      if (busy) return;
      busy = true;
      try { await fn(); } catch (e) { log.error(`job ${name} failed`, { code: e?.code ?? "error", message: String(e?.message ?? e).slice(0, 200) }); }
      finally { busy = false; }
    };
  };
  ctx.jobs.register("lease-sweep", once("lease-sweep", () => delivery.sweep()));
  ctx.jobs.register("enrol-tick", once("enrol-tick", () => enrol.tick()));

  /** Logs an error for every company with vault state whose key directory or socket is reachable from agent sandboxes. */
  async function checkExposureAtStart() {
    const ids = new Set();
    for (const rec of [await state.enrol(), ...Object.values(await state.pending.all()), ...Object.values(await state.deliveries.all())]) if (rec?.companyId) ids.add(rec.companyId);
    for (const id of ids) {
      const exposure = checkExposure(await readConfig(ctx, id));
      if (!exposure.ok) log.error("the vault key directory or socket is reachable from agent sandboxes; no signed calls will be made", { companyId: id, problems: exposure.problems.map((p) => p.message) });
    }
  }

  return { state, enrol, delivery, judge, tools, actions, checkExposureAtStart };
}

const plugin = definePlugin({
  async setup(ctx) {
    const s = register(ctx);
    // Not awaited: neither may hold up the worker's start. Files of leases that ended while the plugin was down go now;
    // a judge-test run a previous worker left behind is marked interrupted.
    s.checkExposureAtStart().catch((e) => ctx.logger.error(`start-up exposure check failed: ${e.message}`));
    s.delivery.sweep().catch((e) => ctx.logger.error(`start-up sweep failed: ${e.message}`));
    s.judge.recoverInterrupted().catch((e) => ctx.logger.error(`judge run recovery failed: ${e.message}`));
  },
  async onHealth() { return { status: "ok" }; },
  // Refuses a gatekeeper URL that would send the API key and the prompts over plain http to a non-loopback host.
  async onValidateConfig(config) {
    const baseUrl = config?.gatekeeper?.baseUrl;
    const problem = typeof baseUrl === "string" && baseUrl.trim() ? baseUrlProblem(baseUrl) : null;
    return problem ? { ok: false, errors: [problem] } : { ok: true };
  },
  // Settings are read on demand for the company at hand; nothing to reload.
  async onConfigChanged() {},
});
export default plugin;
runWorker(plugin, import.meta.url);
