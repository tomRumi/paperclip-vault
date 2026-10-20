// Where an agent's workspace is (docs/DESIGN.md section 3, step 6), and the containment rule every file the plugin writes must satisfy.
//
// Resolution order, first source that yields a path wins:
//   (a) the run's issue -> executionWorkspaceId -> ctx.executionWorkspaces.get().cwd
//   (b) <agentHomeRoot>/<agentId>   (setting; the default per-agent home of Paperclip)
// Nothing else. In particular the project's primary workspace is NOT a source: every agent of the project can read it (same
// uid, same mount), so a session leased to one agent would be readable by another. The only shared case left is an issue's
// execution workspace, which any agent working on that issue can see (documented as a known limit).
// The chosen path must exist, be a directory and have a realpath inside one of the configured workspaceRoots (the same list
// as the sandbox hardening roots, i.e. what the agent's box can see). If not, delivery fails closed: there is no fallback to
// another source, because the relative path the agent is told only makes sense inside the workspace it works in.
import fs from "node:fs";
import path from "node:path";

export class WorkspaceError extends Error {
  constructor(code, message) { super(message); this.name = "WorkspaceError"; this.code = code; }
}

/** True when `real` equals `root` or lies below it (both already realpath'd). */
export function isInside(root, real) {
  const rel = path.relative(root, real);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** The realpath of each configured root that exists. */
export function realRoots(roots) {
  const out = [];
  for (const r of roots ?? []) {
    try { out.push(fs.realpathSync(r)); } catch { /* a root that does not exist contains nothing */ }
  }
  return out;
}

/** True when `real` is inside one of the roots. */
export const containedIn = (roots, real) => realRoots(roots).some((r) => isInside(r, real));

/**
 * @returns {{dir: string, source: "execution-workspace"|"agent-home"}}  dir is a realpath inside a root
 * @throws {WorkspaceError} code "no_workspace"
 */
export async function resolveWorkspace(ctx, { companyId, agentId, issue, cfg }) {
  const candidates = [];
  if (issue?.executionWorkspaceId) {
    const ew = await ctx.executionWorkspaces.get(issue.executionWorkspaceId, companyId).catch(() => null);
    candidates.push({ source: "execution-workspace", path: ew?.cwd ?? ew?.path ?? null });
  }
  if (cfg.agentHomeRoot && /^[0-9a-f-]{36}$/i.test(agentId)) candidates.push({ source: "agent-home", path: path.join(cfg.agentHomeRoot, agentId) });

  const chosen = candidates.find((c) => typeof c.path === "string" && path.isAbsolute(c.path));
  if (!chosen) throw new WorkspaceError("no_workspace", "no workspace could be determined for this agent");
  let real;
  try {
    real = fs.realpathSync(chosen.path);
    if (!fs.statSync(real).isDirectory()) throw new Error("not a directory");
  } catch {
    throw new WorkspaceError("no_workspace", "the agent's workspace does not exist on this host");
  }
  if (!containedIn(cfg.workspaceRoots, real)) throw new WorkspaceError("no_workspace", "the agent's workspace is outside the configured workspace roots");
  return { dir: real, source: chosen.source };
}
