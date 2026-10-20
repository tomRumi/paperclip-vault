// What the agent is told. Every string here is fixed: the tool results go through Paperclip's tool gateway, which redacts
// secret-looking keys and BLOCKS a result whose text looks like an instruction to hand over credentials, so nothing from
// the model's `reason`, from vaultd's free text or from the agent's own input is ever echoed. The model's reasons are shown
// only in the admin UI (decision log). Result keys avoid names the gateway redacts (token, credential, secret, cookie, ...).

export const STATUSES = Object.freeze(["pending", "preparing", "ready", "denied", "expired", "ended", "failed"]);

const BY_STATUS = {
  pending: "The request is being reviewed. Check again with vault_request_status.",
  preparing: "The request was approved and the session is being prepared. Check again shortly with vault_request_status.",
  ready: "Ready. The file is in your workspace at the relative path shown and stops working at the time shown. Do not copy it anywhere else.",
  denied: "The request was not granted.",
  expired: "The request expired before it could be completed. Ask again if you still need access.",
  ended: "The access has ended and the file was removed. Ask again if you still need it.",
  failed: "The session could not be prepared. Ask again later.",
};

const BY_CODE = {
  // ceilings (vaultd)
  agent_unpinned: "This agent is not set up to use the vault.",
  company_not_allowed: "This company is not set up to use the vault.",
  agent_locked: "This agent is locked out of the vault. Ask a board member.",
  rate_limited: "Too many requests. Wait before asking again.",
  bad_target: "That site or item does not exist.",
  never_list: "That item cannot be requested.",
  role_class: "Your role may not request this kind of access.",
  site_agent_not_allowed: "This site is not available to you.",
  minutes_missing: "Say how many minutes you need (a whole number, at least 1).",
  minutes_over_max: "The requested duration is above the maximum for this target. Ask again for at most the number of minutes shown as maxMinutes.",
  site_not_ready: "This site is not ready yet. Ask a board member to finish setting it up.",
  backoff: "You asked for this recently. Wait before asking again.",
  too_many_denies: "Too many recent denials for this target. Wait before asking again.",
  too_many_open: "You already have the maximum number of open requests.",
  duplicate: "You already asked for this in this run.",
  // verdict stage
  no_verdict: "The review did not finish in time. Ask again later.",
  judge_deny: "The request was reviewed and not granted.",
  judge_lock: "This agent is locked out of the vault. Ask a board member.",
  provider_error: "The review is not available right now. Ask a board member.",
  model_not_cleared: "The review is not available right now. Ask a board member.",
  prompt_mismatch: "The review is not available right now. Ask a board member.",
  // session stage (helper)
  login_failed: "The login to the site failed. Ask a board member to check the site setup.",
  totp_failed: "The login to the site failed. Ask a board member to check the site setup.",
  challenge_required: "The site asked for an extra check that needs a person. Ask a board member.",
  needs_interactive: "This site needs a person to log in first. Ask a board member.",
  needs_authorize: "This site needs a person to authorize it first. Ask a board member.",
  helper_error: "The login helper failed. Ask again later.",
  captcha: "The site blocked the automatic login. Ask a board member.",
  site_unreachable: "The site could not be reached. Ask again later.",
  recipe_error: "The login recipe for this site is broken. Ask a board member.",
  helper_down: "The login helper is not running. Ask a board member.",
  timeout: "The login took too long. Ask again later.",
  // plugin-side
  no_workspace: "Your workspace could not be found, so nothing was placed there. Ask a board member.",
  delivery_failed: "The file could not be placed in your workspace. Ask again later.",
  delivery_lost: "The file was not placed in your workspace. Ask again.",
  not_enrolled: "The vault is not connected yet. Ask a board member.",
  exposed: "The vault is not available right now. Ask a board member.",
  unreachable: "The vault is not reachable right now. Ask again later.",
  busy: "The vault is busy. Ask again shortly.",
  run_guard: "This can only be used from a running task that is in progress and assigned to you.",
  bad_params: "The request is not valid.",
};

const CODE_RE = /^[a-z][a-z0-9_]{0,39}$/;

/** A code from vaultd that may be echoed (it is only ever used as a lookup key into the fixed strings). */
export const safeCode = (c) => (typeof c === "string" && CODE_RE.test(c) ? c : undefined);

export const messageFor = (status, code) => (code && BY_CODE[code]) || BY_STATUS[status] || BY_STATUS.denied;

const REMOTE_STATUS = {
  awaiting_verdict: "pending",
  issuing: "preparing",
  ready: "ready",
  delivered: "ready",
  denied: "denied",
  expired: "expired",
  ended: "ended",
  revoked: "ended",
  failed: "failed",
};

/** vaultd request.status / request.create answer -> the agent-facing view (without path and expiry). */
export function viewFromRemote(remote) {
  const status = REMOTE_STATUS[remote?.state] ?? "failed";
  const code = safeCode(remote?.code);
  const view = { status, ...(code ? { code } : {}), message: messageFor(status, code) };
  if (code === "minutes_over_max" && Number.isInteger(remote?.maxMinutes)) view.maxMinutes = remote.maxMinutes;
  return view;
}

/** A plugin-side or transport failure -> the agent-facing view. */
export function failure(code) {
  const c = safeCode(code) && BY_CODE[code] ? code : undefined;
  return { status: "failed", ...(c ? { code: c } : {}), message: messageFor("failed", c) };
}

export const ALL_MESSAGES = Object.freeze({ ...Object.fromEntries(Object.entries(BY_STATUS).map(([k, v]) => [`status:${k}`, v])), ...Object.fromEntries(Object.entries(BY_CODE).map(([k, v]) => [`code:${k}`, v])) });
