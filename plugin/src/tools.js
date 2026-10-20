// The four agent tools. Names carry no write/send/create verbs so Paperclip's tool gateway classes them "read" (no
// approval prompt); the vault itself decides. Everything an agent gets back is a fixed message plus, when ready, the
// RELATIVE path of a file in its own workspace and the time it stops working; never contents (see messages.js).
//
// A request is asynchronous (docs/DESIGN.md section 3): the tool creates the request at vaultd (ceilings first), starts the verdict in the
// worker, waits up to `toolWaitMs` (default 7 s, under the gateway's 10 s) and otherwise returns "pending" with a request id
// to poll with vault_request_status. Delivery happens from the poll or from the lease-sweep job, whichever sees "ready" first.
import { readConfig } from "./config.js";
import { failure, messageFor, viewFromRemote } from "./messages.js";
import manifest from "./manifest.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SITE_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const CREDENTIAL_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const REQUEST_ID_RE = /^req_[0-9a-f]{16}$/;
const STAGE_RE = /^\s*\[(Plan|Build|Test)\]/i;
const POLL_MS = 500;

/** Guard failures are answered with a fixed message; the code says which check failed (for the log, not the agent). */
export class GuardError extends Error {
  constructor(code) { super(code); this.name = "GuardError"; this.code = code; }
}

const stageOf = (title, status) => { const m = STAGE_RE.exec(title ?? ""); return m ? m[1][0].toUpperCase() + m[1].slice(1).toLowerCase() : String(status ?? ""); };
const oneLine = (v, max) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max) : "");

/** The ToolResult for a view: structured data plus the same as JSON text. Only whitelisted keys leave this function. */
export function toolResult(view, requestId) {
  const out = { status: view.status, ...(requestId ? { requestId } : {}) };
  for (const k of ["code", "message", "path", "expiresAt", "minutes", "maxMinutes"]) if (view[k] !== undefined) out[k] = view[k];
  return { content: JSON.stringify(out), data: out };
}

const declaration = (name) => {
  const t = manifest.tools.find((x) => x.name === name);
  return { displayName: t.displayName, description: t.description, parametersSchema: t.parametersSchema };
};

/**
 * @param {object} o
 * @param {object} o.ctx
 * @param {object} o.state
 * @param {Function} o.clientFor  (cfg) => vault client
 * @param {object} o.delivery     src/delivery.js
 * @param {object} o.judge        src/judge.js
 * @param {Function} [o.sleep]
 * @param {Function} [o.now]
 */
export function createTools({ ctx, state, clientFor, delivery, judge, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => Date.now() }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  const verdicts = new Map();

  /** The run must be the agent's own running run, on an issue that is in progress and assigned to the agent. */
  async function runGuard({ agentId, runId, companyId }) {
    if (![agentId, runId, companyId].every((v) => typeof v === "string" && UUID_RE.test(v))) throw new GuardError("bad_run_context");
    const rows = await ctx.db.query(
      "SELECT context_snapshot->>'issueId' AS issue_id FROM public.heartbeat_runs WHERE id = $1::uuid AND agent_id = $2::uuid AND company_id = $3::uuid AND status = 'running'",
      [runId, agentId, companyId],
    );
    if (!rows?.length) throw new GuardError("run_not_active");
    const issueId = rows[0].issue_id;
    if (typeof issueId !== "string" || !UUID_RE.test(issueId)) throw new GuardError("no_issue");
    const issue = await ctx.issues.get(issueId, companyId);
    if (!issue || issue.status !== "in_progress" || issue.assigneeAgentId !== agentId) throw new GuardError("issue_not_assigned");
    return { issueId, issue };
  }

  async function contextOf(issue, projectId, companyId) {
    const pid = projectId || issue.projectId;
    const project = pid ? await ctx.projects.get(pid, companyId).catch(() => null) : null;
    return { issue_title: oneLine(issue.title, 300), issue_project: oneLine(project?.name, 120), stage: stageOf(issue.title, issue.status) };
  }

  /** vaultd transport / protocol error -> the agent-facing view. */
  const viewFromError = (e) => {
    switch (e.code) {
      case "not_enrolled": return failure("not_enrolled");
      case "busy": return failure("busy");
      case "exposed": return failure("exposed");
      case "denied": return { status: "denied", message: messageFor("denied") };
      case "conflict": return { status: "denied", code: "duplicate", message: messageFor("denied", "duplicate") };
      default: return failure("unreachable");
    }
  };

  /** Polls until the request is no longer in progress or the wait budget is used up. */
  async function waitFor(requestId, budgetMs) {
    // Real elapsed time, not the injectable domain clock: this is a wait, not a timestamp.
    const end = performance.now() + budgetMs;
    let view = { status: "pending", message: messageFor("pending") };
    while (performance.now() < end) {
      view = (await delivery.advance(requestId)) ?? view;
      if (view.status !== "pending" && view.status !== "preparing") return view;
      await sleep(Math.min(POLL_MS, Math.max(1, end - performance.now())));
    }
    return view;
  }

  async function requestAccess(kind, params, runCtx) {
    const target = kind === "login" ? params?.site : params?.credential;
    const reason = typeof params?.reason === "string" ? params.reason.trim() : "";
    if (typeof target !== "string" || !(kind === "login" ? SITE_RE : CREDENTIAL_RE).test(target) || reason.length < 10 || reason.length > 500 || !Number.isInteger(params?.minutes))
      return { error: messageFor("denied", "bad_params"), data: { status: "denied", code: "bad_params" } };
    const cfg = await readConfig(ctx, runCtx.companyId);
    let guard;
    try { guard = await runGuard(runCtx); }
    catch (e) {
      if (!(e instanceof GuardError)) throw e;
      log.warn("request refused by the run guard", { agentId: runCtx.agentId, runId: runCtx.runId, check: e.code });
      return { error: messageFor("denied", "run_guard"), data: { status: "denied", code: "run_guard" } };
    }
    const client = clientFor(cfg);
    let created;
    try {
      created = await client.call("request.create", {
        kind, target, reason, minutes: params.minutes,
        agent: { agentId: runCtx.agentId, runId: runCtx.runId, companyId: runCtx.companyId, issueId: guard.issueId },
        context: await contextOf(guard.issue, runCtx.projectId, runCtx.companyId),
      });
    } catch (e) {
      log.warn("request.create failed", { agentId: runCtx.agentId, code: e.code });
      return toolResult(viewFromError(e));
    }
    if (created.state === "denied") return toolResult(viewFromRemote(created), created.requestId);
    if (!REQUEST_ID_RE.test(String(created.requestId ?? "")) || typeof created.prompt !== "string") return toolResult(failure("unreachable"));
    const requestId = created.requestId;
    await state.pending.put(requestId, {
      requestId, kind, target, agentId: runCtx.agentId, runId: runCtx.runId, companyId: runCtx.companyId, projectId: runCtx.projectId || guard.issue.projectId || null,
      issueId: guard.issueId, minutes: params.minutes, createdAt: new Date(now()).toISOString(), deadline: created.deadline ?? null,
    });
    // The verdict keeps running in the worker after the tool has answered.
    const run = judge.produceVerdict(cfg, created).catch((e) => log.error("verdict flow crashed", { requestId, code: e?.code ?? "error" })).finally(() => verdicts.delete(requestId));
    verdicts.set(requestId, run);
    return toolResult(await waitFor(requestId, cfg.toolWaitMs), requestId);
  }

  async function requestStatus(params, runCtx) {
    const requestId = params?.requestId;
    if (typeof requestId !== "string" || !REQUEST_ID_RE.test(requestId)) return { error: messageFor("denied", "bad_params"), data: { status: "denied", code: "bad_params" } };
    const rec = (await state.pending.get(requestId)) ?? (await state.deliveries.get(requestId));
    // The same answer for "no such request" and "somebody else's request".
    if (!rec || rec.agentId !== runCtx.agentId || rec.companyId !== runCtx.companyId) return { error: "No such request.", data: { status: "failed", code: "unknown_request" } };
    const view = (await delivery.advance(requestId)) ?? failure("delivery_lost");
    return toolResult(view, requestId);
  }

  async function listSites(_params, runCtx) {
    const cfg = await readConfig(ctx, runCtx.companyId);
    let res;
    try { res = await clientFor(cfg).call("sites.list", { agentId: runCtx.agentId, companyId: runCtx.companyId }); }
    catch (e) { return toolResult(viewFromError(e)); }
    const rows = [...(Array.isArray(res.sites) ? res.sites : []), ...(Array.isArray(res.credentials) ? res.credentials : [])];
    const sites = rows
      .filter((s) => s && typeof s === "object" && (s.state === undefined || s.state === "ready")
        && (!Array.isArray(s.allowedAgents) || s.allowedAgents.includes(runCtx.agentId)))
      .map((s) => ({ id: oneLine(s.id ?? s.name, 64), purpose: oneLine(s.purpose, 200), kind: oneLine(s.kind, 20), maxMinutes: Number.isInteger(s.maxMinutes) ? s.maxMinutes : null }))
      .filter((s) => s.id);
    const out = { sites };
    return { content: JSON.stringify(out), data: out };
  }

  /** Wraps a handler: an unexpected error is logged (code only) and answered with a fixed message. */
  const safe = (name, fn) => async (params, runCtx) => {
    try { return await fn(params, runCtx); }
    catch (e) {
      log.error(`tool ${name} failed`, { code: e?.code ?? "error", message: String(e?.message ?? e).slice(0, 200) });
      return { error: "The vault is unavailable right now." };
    }
  };

  function register() {
    ctx.tools.register("vault_request_login", declaration("vault_request_login"), safe("vault_request_login", (p, r) => requestAccess("login", p, r)));
    ctx.tools.register("vault_request_credential", declaration("vault_request_credential"), safe("vault_request_credential", (p, r) => requestAccess("credential", p, r)));
    ctx.tools.register("vault_request_status", declaration("vault_request_status"), safe("vault_request_status", requestStatus));
    ctx.tools.register("vault_list_sites", declaration("vault_list_sites"), safe("vault_list_sites", listSites));
  }

  return { register, runGuard, requestAccess, requestStatus, listSites, whenVerdictsDone: () => Promise.all([...verdicts.values()]) };
}
