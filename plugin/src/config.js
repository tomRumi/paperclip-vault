// The plugin's settings (manifest instanceConfigSchema) with defaults and bounds applied. Paperclip stores the settings per
// company (ctx.config.get(companyId)); everything here is read for the company of the caller, the tool run, the pending
// request or the enrolment at hand. `dataDir` and `socketPath` describe the one vaultd install, so a deployment with several
// companies must use the same values in each.
import os from "node:os";
import path from "node:path";

export const DEFAULT_SOCKET_PATH = "/run/vault/plugin.sock";
export const DEFAULT_TOOL_WAIT_MS = 7000;
export const DEFAULT_K = 2;
export const DEFAULT_TEMPERATURE = 0.2;
export const DEFAULT_CALL_TIMEOUT_MS = 30_000;

/** Where the signing key lives: outside every agent workspace root. */
export const defaultDataDir = () => path.join(os.homedir(), ".local", "share", "paperclip-vault");

const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()) : []);
const absolute = (v) => (typeof v === "string" && path.isAbsolute(v.trim()) ? path.normalize(v.trim()).replace(/(.)\/+$/, "$1") : null);
const int = (v, dflt, min, max) => (Number.isInteger(v) && v >= min && v <= max ? v : dflt);

/** @returns the normalized settings for a company. */
export async function readConfig(ctx, companyId) {
  const raw = (await ctx.config.get(companyId).catch(() => null)) ?? {};
  const g = raw.judge && typeof raw.judge === "object" ? raw.judge : {};
  return {
    companyId: companyId ?? null,
    adminUserIds: strings(raw.adminUserIds),
    workspaceRoots: strings(raw.workspaceRoots).map(absolute).filter(Boolean),
    agentHomeRoot: absolute(raw.agentHomeRoot),
    instanceRoot: absolute(raw.instanceRoot),
    sandboxExtraPaths: strings(raw.sandboxExtraPaths).map(absolute).filter(Boolean),
    dataDir: absolute(raw.dataDir) ?? defaultDataDir(),
    socketPath: absolute(raw.socketPath) ?? DEFAULT_SOCKET_PATH,
    toolWaitMs: int(raw.toolWaitMs, DEFAULT_TOOL_WAIT_MS, 0, 50_000),
    judge: {
      baseUrl: typeof g.baseUrl === "string" ? g.baseUrl.trim() : "",
      apiKey: g.apiKey && typeof g.apiKey === "object" ? g.apiKey : null,
      temperature: typeof g.temperature === "number" && g.temperature >= 0 && g.temperature <= 2 ? g.temperature : DEFAULT_TEMPERATURE,
      k: int(g.k, DEFAULT_K, 2, 9),
      perCallTimeoutMs: int(g.perCallTimeoutMs, DEFAULT_CALL_TIMEOUT_MS, 1000, 120_000),
    },
  };
}

/** The `judge` settings in the shape createProvider() takes. */
export const providerConfig = (cfg) => ({ ...cfg.judge, companyId: cfg.companyId });
