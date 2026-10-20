// Putting a session or token into an agent's workspace, and taking it out again.
//
// The agent is an adversary that shares the workspace directory, so the writes are done defensively:
//   * <workspace>/.vault is opened ONCE with O_DIRECTORY|O_NOFOLLOW; from then on every operation goes through the
//     directory descriptor (/proc/self/fd/N/<name>, Linux), so replacing .vault with a symlink after the check changes
//     nothing. The directory's own realpath (readlink of the descriptor) must be inside the configured workspaceRoots.
//   * files are created with O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, as a temp file that is fsynced and renamed into place.
//   * removal overwrites the file with zeros, fsyncs and unlinks (opened O_NONBLOCK so a planted FIFO cannot block us).
// Tool results only ever carry the relative path and the expiry, never the content.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { readConfig } from "./config.js";
import { containedIn, resolveWorkspace, WorkspaceError } from "./workspace.js";
import { failure, messageFor, viewFromRemote } from "./messages.js";
import { PLUGIN_ID } from "./manifest.js";

export const VAULT_DIR = ".vault";
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const LEASE_RE = /^lse_([0-9a-f]{16})$/;
const MAX_PAYLOAD_BYTES = 2 * 1024 * 1024;
const PENDING_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const STALE_DELIVERY_MS = 24 * 60 * 60 * 1000;
const SUFFIX = { login: ".session.json", token: ".token.json" };
const F = fs.constants;

export class DeliveryError extends Error {
  constructor(code, message) { super(message); this.name = "DeliveryError"; this.code = code; }
}

/** An opened <workspace>/.vault whose location has been verified; operate through at(name) only. */
export function openVaultDir(workspaceDir, roots, { create }) {
  const dir = path.join(workspaceDir, VAULT_DIR);
  if (create) {
    try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== "EEXIST") throw new DeliveryError("delivery_failed", `cannot create ${VAULT_DIR}: ${e.code}`); }
  }
  let fd;
  try {
    fd = fs.openSync(dir, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw new DeliveryError("delivery_failed", `${VAULT_DIR} is not a plain directory (${e.code})`);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isDirectory() || st.uid !== process.getuid()) throw new DeliveryError("delivery_failed", `${VAULT_DIR} is not owned by the service user`);
    const real = fs.readlinkSync(`/proc/self/fd/${fd}`);
    if (!containedIn(roots, real)) throw new DeliveryError("no_workspace", `${VAULT_DIR} is outside the configured workspace roots`);
    fs.fchmodSync(fd, 0o700);
    return { fd, real, at: (name) => `/proc/self/fd/${fd}/${name}`, close: () => fs.closeSync(fd) };
  } catch (e) {
    fs.closeSync(fd);
    throw e;
  }
}

/** Creates `name` in the directory with mode 0600 atomically (temp file + rename). Never overwrites through a symlink. */
export function writePrivateFile(vdir, name, content) {
  const tmp = `.tmp-${crypto.randomBytes(6).toString("hex")}`;
  const fd = fs.openSync(vdir.at(tmp), F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
  try {
    fs.fchmodSync(fd, 0o600);
    let off = 0;
    while (off < content.length) off += fs.writeSync(fd, content, off, content.length - off);
    fs.fsyncSync(fd);
  } catch (e) {
    fs.closeSync(fd);
    fs.rmSync(vdir.at(tmp), { force: true });
    throw e;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(vdir.at(tmp), vdir.at(name));
  } catch (e) {
    fs.rmSync(vdir.at(tmp), { force: true });
    throw e;
  }
  fs.fsyncSync(vdir.fd);
}

/** `.gitignore` containing "*" so the directory is never committed. Left alone when it already exists. */
export function ensureGitignore(vdir) {
  try { writePrivateFile(vdir, ".gitignore", Buffer.from("*\n")); } catch { /* an existing .gitignore is fine */ }
}

/** Overwrites the file with zeros, then unlinks it. A missing file is fine. Only a regular file with one link that belongs to
 *  this process is overwritten; anything else (a symlink, FIFO, hard link or foreign file planted there) is only unlinked,
 *  never written to. */
export function shredFile(vdir, name) {
  let fd;
  try {
    fd = fs.openSync(vdir.at(name), F.O_WRONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  } catch (e) {
    if (e.code === "ENOENT") return false;
    if (e.code !== "ELOOP" && e.code !== "ENXIO" && e.code !== "EACCES") throw e; // a symlink, FIFO or foreign file is only unlinked
  }
  if (fd !== undefined) {
    try {
      const st = fs.fstatSync(fd);
      if (st.isFile() && st.nlink === 1 && st.uid === process.getuid()) {
        const zeros = Buffer.alloc(64 * 1024);
        for (let left = st.size; left > 0;) left -= fs.writeSync(fd, zeros, 0, Math.min(zeros.length, left), st.size - left);
        fs.fsyncSync(fd);
      }
    } finally {
      fs.closeSync(fd);
    }
  }
  fs.unlinkSync(vdir.at(name));
  return true;
}

const TERMINAL = new Set(["denied", "expired", "ended", "failed"]);

/**
 * @param {object} o
 * @param {object} o.ctx
 * @param {object} o.state       src/state.js
 * @param {Function} o.clientFor (cfg) => vault client
 * @param {Function} [o.now]
 */
export function createDelivery({ ctx, state, clientFor, now = () => Date.now() }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  const inflight = new Map();

  async function activity(companyId, message, metadata) {
    if (!companyId) return;
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  }

  const deliveredView = (d) => {
    const live = now() < Date.parse(d.expiresAt);
    return live
      ? { status: "ready", message: messageFor("ready"), path: d.relPath, expiresAt: d.expiresAt, minutes: d.minutes }
      : { status: "expired", message: messageFor("expired") };
  };

  /** Closes the lease at vaultd and remembers why, so later polls report the failure. */
  async function abort(rec, cfg, code) {
    try { await clientFor(cfg).call("lease.revoke", { requestId: rec.requestId, by: "plugin", reason: code }); }
    catch (e) { log.warn("could not revoke the lease after a failed delivery", { requestId: rec.requestId, code: e.code }); }
    await state.pending.update(rec.requestId, (r) => ({ ...r, failure: code }));
    await activity(rec.companyId, `Vault: delivery failed (${code})`, { requestId: rec.requestId, agentId: rec.agentId });
    log.warn("delivery failed", { requestId: rec.requestId, code });
    return failure(code);
  }

  async function deliverNow(requestId) {
    const rec = await state.pending.get(requestId);
    if (!rec) {
      const d = await state.deliveries.get(requestId);
      return d ? deliveredView(d) : failure("delivery_lost");
    }
    const cfg = await readConfig(ctx, rec.companyId);
    const issue = rec.issueId ? await ctx.issues.get(rec.issueId, rec.companyId).catch(() => null) : null;

    // Everything that can fail without burning the single-use fetch happens first.
    let vdir;
    let ws;
    try {
      ws = await resolveWorkspace(ctx, { companyId: rec.companyId, agentId: rec.agentId, issue, cfg });
      vdir = openVaultDir(ws.dir, cfg.workspaceRoots, { create: true });
      if (!vdir) throw new DeliveryError("delivery_failed", `${VAULT_DIR} could not be opened`);
    } catch (e) {
      return abort(rec, cfg, e instanceof WorkspaceError || e.code === "no_workspace" ? "no_workspace" : "delivery_failed");
    }
    let name;
    try {
      let fetched;
      try {
        fetched = await clientFor(cfg).call("lease.fetch", { requestId });
      } catch (e) {
        if (e.code === "conflict") {
          const d = await state.deliveries.get(requestId);
          return d ? deliveredView(d) : abort(rec, cfg, "delivery_lost");
        }
        log.warn("lease fetch failed, will retry", { requestId, code: e.code });
        return viewFromRemote({ state: "issuing" });
      }
      const kind = fetched?.kind === "login" ? "login" : fetched?.kind === "token" ? "token" : null;
      const lease = LEASE_RE.exec(String(fetched?.leaseId ?? ""));
      const payload = fetched?.payload;
      const expiresAt = typeof (fetched?.expiresAt ?? payload?.expiresAt) === "string" ? (fetched.expiresAt ?? payload.expiresAt) : null;
      const content = payload && typeof payload === "object" && !Array.isArray(payload) ? Buffer.from(`${JSON.stringify(payload)}\n`, "utf8") : null;
      if (!kind || !lease || !NAME_RE.test(String(fetched?.name ?? "")) || !content || content.length > MAX_PAYLOAD_BYTES || !(Date.parse(expiresAt) > now()))
        return abort(rec, cfg, "delivery_failed");
      name = `${fetched.name}-${lease[1].slice(0, 8)}${SUFFIX[kind]}`;
      try {
        ensureGitignore(vdir);
        writePrivateFile(vdir, name, content);
      } catch (e) {
        log.warn("could not write the delivery file", { requestId, code: e.code });
        return abort(rec, cfg, "delivery_failed");
      }
      const relPath = `${VAULT_DIR}/${name}`;
      const record = { requestId, leaseId: fetched.leaseId, agentId: rec.agentId, companyId: rec.companyId, dir: ws.dir, name, relPath, expiresAt, minutes: Number.isInteger(fetched.minutes) ? fetched.minutes : rec.minutes, kind, deliveredAt: new Date(now()).toISOString() };
      try {
        await state.deliveries.put(requestId, record);
      } catch (e) {
        shredFile(vdir, name);
        return abort(rec, cfg, "delivery_failed");
      }
      await state.pending.drop(requestId);
      try { await clientFor(cfg).call("lease.ack", { requestId, relPath }); }
      catch (e) { log.warn("lease acknowledgement failed (audit only)", { requestId, code: e.code }); }
      return deliveredView(record);
    } finally {
      vdir.close();
    }
  }

  /** Fetches the lease and writes the file; concurrent callers (tool poll, job) share one run. */
  function deliver(requestId) {
    if (!inflight.has(requestId)) inflight.set(requestId, deliverNow(requestId).finally(() => inflight.delete(requestId)));
    return inflight.get(requestId);
  }

  /** Where a request stands right now; delivers the file when vaultd says it is ready. null: unknown to this plugin. */
  async function advance(requestId) {
    const d = await state.deliveries.get(requestId);
    if (d) return deliveredView(d);
    const rec = await state.pending.get(requestId);
    if (!rec) return null;
    if (rec.failure) return failure(rec.failure);
    if (rec.ended) return viewFromRemote({ state: "ended" });
    const cfg = await readConfig(ctx, rec.companyId);
    let remote;
    try {
      remote = await clientFor(cfg).call("request.status", { requestId });
    } catch (e) {
      if (e.code === "not_found") return failure("delivery_lost");
      return { status: "pending", code: "unreachable", message: messageFor("pending", "unreachable") };
    }
    if (remote.state === "ready") return deliver(requestId);
    if (remote.state === "delivered") return failure("delivery_lost");
    return viewFromRemote(remote);
  }

  /** Overwrites and removes a delivered file. Returns false when it could not be done safely. */
  async function cleanup(d) {
    const cfg = await readConfig(ctx, d.companyId);
    let vdir;
    try {
      vdir = openVaultDir(d.dir, cfg.workspaceRoots, { create: false });
    } catch (e) {
      log.warn("not touching a delivery directory that is no longer safe", { requestId: d.requestId, code: e.code });
      return false;
    }
    if (!vdir) return true;
    try { shredFile(vdir, d.name); return true; }
    catch (e) { log.warn("could not remove a delivery file", { requestId: d.requestId, code: e.code }); return false; }
    finally { vdir.close(); }
  }

  /** The file is gone: drop the delivery record and keep a small tombstone so the agent's next poll hears "ended". */
  async function retire(d) {
    await state.pending.put(d.requestId, { requestId: d.requestId, agentId: d.agentId, companyId: d.companyId, createdAt: new Date(now()).toISOString(), ended: true, terminal: "ended" });
    await state.deliveries.drop(d.requestId);
  }

  /** Removes the delivered file of a request now (used when an admin revokes the lease). */
  async function removeDelivered(requestId) {
    const d = await state.deliveries.get(requestId);
    if (!d) return false;
    if (await cleanup(d)) { await retire(d); return true; }
    return false;
  }

  /** Job lease-sweep (every minute, and once at start): deliver ready requests, remove files of ended or expired leases. */
  async function sweep() {
    const result = { delivered: 0, removed: 0, pruned: 0 };
    for (const [id, rec] of Object.entries(await state.pending.all())) {
      if (now() - Date.parse(rec.createdAt) > PENDING_MAX_AGE_MS) { await state.pending.drop(id); result.pruned += 1; continue; }
      if (rec.failure || rec.terminal) continue;
      try {
        const view = await advance(id);
        if (view?.status === "ready") result.delivered += 1;
        else if (view && TERMINAL.has(view.status)) await state.pending.update(id, (r) => ({ ...r, terminal: view.status }));
      } catch (e) {
        log.warn("sweep could not advance a request", { requestId: id, code: e.code });
      }
    }
    for (const [id, d] of Object.entries(await state.deliveries.all())) {
      const expiredAt = Date.parse(d.expiresAt);
      let over = !(now() < expiredAt);
      if (!over) {
        try {
          over = ["ended", "revoked", "expired", "failed", "denied"].includes((await clientFor(await readConfig(ctx, d.companyId)).call("request.status", { requestId: id })).state);
        } catch (e) {
          over = e.code === "not_found";
        }
      }
      if (!over) continue;
      if (await cleanup(d)) { await retire(d); result.removed += 1; }
      else if (now() - expiredAt > STALE_DELIVERY_MS) { log.warn("giving up on a delivery file that could not be removed", { requestId: id }); await state.deliveries.drop(id); }
    }
    return result;
  }

  return { deliver, advance, cleanup, removeDelivered, sweep };
}
