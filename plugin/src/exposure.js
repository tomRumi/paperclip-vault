// The plugin's signing key and the vaultd socket must be out of reach of sandboxed agent runs. SO_PEERCRED cannot tell the
// plugin worker from an agent (same uid); what separates them is that a run's sandbox never mounts the key's directory or
// the socket. This module checks that against the settings, before every signed call and at start:
//
// dataDir (holds plugin-key.pem) and socketPath must not lie inside
//   * any workspaceRoots entry,
//   * agentHomeRoot,
//   * instanceRoot (the Paperclip instance root, with workspaces/projects/companies beneath it),
//   * any sandboxExtraPaths entry (the paths agent runs mount: their filesystemExtraPaths).
// Paths are compared by realpath (symlinks resolved; a path that does not exist yet is resolved through its nearest existing
// ancestor). On any hit the plugin makes no signed call and vaultStatus reports the problem.
//
// Fail closed: with no workspaceRoots at all there is nothing to compare against (and delivery has nowhere to write), so
// the check fails with code "not_configured" until at least one workspace root is set.
import fs from "node:fs";
import path from "node:path";
import { isInside } from "./workspace.js";

/** realpath of p; a missing tail is appended to the realpath of the nearest existing ancestor. */
export function realpathLoose(p) {
  const rest = [];
  let cur = path.resolve(p);
  for (;;) {
    try { return path.join(fs.realpathSync(cur), ...rest.reverse()); }
    catch (e) {
      if (e.code !== "ENOENT" && e.code !== "ENOTDIR") throw e;
      const parent = path.dirname(cur);
      if (parent === cur) return path.join(cur, ...rest.reverse());
      rest.push(path.basename(cur));
      cur = parent;
    }
  }
}

/** @returns {{ok: boolean, problems: Array<{what: "dataDir"|"socketPath"|"workspaceRoots", code: string, path: string, root: string, message: string}>}} */
export function checkExposure(cfg) {
  const roots = [
    ...(cfg.workspaceRoots ?? []).map((p) => ["workspaceRoots", p]),
    ...(cfg.agentHomeRoot ? [["agentHomeRoot", cfg.agentHomeRoot]] : []),
    ...(cfg.instanceRoot ? [["instanceRoot", cfg.instanceRoot]] : []),
    ...(cfg.sandboxExtraPaths ?? []).map((p) => ["sandboxExtraPaths", p]),
  ];
  const problems = [];
  if (!(cfg.workspaceRoots ?? []).length)
    problems.push({ what: "workspaceRoots", code: "not_configured", path: "", root: "", message: "workspaceRoots is not set: add the absolute folder(s) that hold your agents' workspaces under \"Workspace roots\" in this plugin's settings" });
  for (const [what, configured] of [["dataDir", cfg.dataDir], ["socketPath", cfg.socketPath]]) {
    let real;
    try { real = realpathLoose(configured); }
    catch { problems.push({ what, code: "unresolvable", path: configured, root: "", message: `${what} ${configured} cannot be resolved` }); continue; }
    for (const [code, root] of roots) {
      let realRoot;
      try { realRoot = realpathLoose(root); } catch { continue; }
      if (isInside(realRoot, real))
        problems.push({ what, code, path: real, root: realRoot, message: `${what} (${real}) lies inside ${code} (${realRoot}), which agent sandboxes can reach` });
    }
  }
  return { ok: problems.length === 0, problems };
}
