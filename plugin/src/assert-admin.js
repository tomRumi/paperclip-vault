// Who may call a plugin action.
//
// Paperclip's plugin bridge (POST /api/plugins/:id/actions/:key) admits ANY authenticated actor with access to the company
// the call is scoped to, agents included; only a call without a company is limited to instance admins. The worker gets a
// host-built, unforgeable actor ({type, userId, agentId, companyId}) but no "is instance admin" flag, and `data` handlers
// get no actor at all, which is why every UI read in this plugin is an action as well.
//
//   assertUser   reads: a signed-in user (agents and system calls are refused).
//   assertAdmin  writes: a user, and either no company scope (the host already enforced instance admin) or the user id
//                listed in the plugin's `adminUserIds` setting of that company, which only instance admins can edit
//                (POST /api/plugins/:id/config is assertInstanceAdmin). The Install tab shows the id to add.
//
// Same semantics as the hardening plugin's assertAdmin.

export class NotAllowedError extends Error {
  constructor(message) { super(message); this.name = "NotAllowedError"; this.code = "NOT_ALLOWED"; }
}

const plainList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

const callerKind = (actor) => (actor.type === "agent" ? "an agent" : "a non-user caller");

/** A signed-in user; returns the actor. Agents and system calls are refused. */
export function assertUser(context) {
  const actor = context?.actor ?? {};
  if (actor.type !== "user" || !actor.userId)
    throw new NotAllowedError(`only signed-in users can read this (this request came from ${callerKind(actor)})`);
  return actor;
}

/** A user listed in `adminUserIds`, or any user of a company-less call (already instance-admin gated by the host). */
export async function assertAdmin(ctx, context) {
  const actor = context?.actor ?? {};
  if (actor.type !== "user" || !actor.userId)
    throw new NotAllowedError(`only admins can change the vault (this request came from ${callerKind(actor)})`);
  const companyId = actor.companyId ?? null;
  if (companyId === null) return actor;
  const cfg = (await ctx.config.get(companyId).catch(() => null)) ?? {};
  if (plainList(cfg.adminUserIds).includes(actor.userId)) return actor;
  throw new NotAllowedError(`only admins can change the vault. An instance admin must add your user id (${actor.userId}) to "Users who may change the vault" in this plugin's settings first.`);
}

/** Wraps an action handler: level "read" needs a user, level "write" needs an admin. The handler gets (params, context, actor). */
export function guarded(ctx, level, handler) {
  return async (params, context) => {
    const actor = level === "write" ? await assertAdmin(ctx, context) : assertUser(context);
    return handler(params ?? {}, context, actor);
  };
}
