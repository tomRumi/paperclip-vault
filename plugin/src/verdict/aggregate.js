// The verdict format: the JSON schema every model answer must follow, how one answer is parsed into a sample, and the
// rule that turns k samples into ONE decision. This file and vaultd/judge.py hold the identical aggregation and are tested
// against the same vectors (tests/vectors/aggregate.json): vaultd recomputes the decision from the raw samples and refuses
// a verdict that does not match.
//
// Options (judge_prompt.md): c = deny, d = lock the agent and deny, a = allow narrow, b = allow standard.
//
// Aggregation (docs/DESIGN.md section 3):
//   * Approve only when ALL k samples are a or b. The safer one wins (a over b) and the minutes are the smallest
//     max_minutes of any sample.
//   * Lock (d) only when ALL k samples are d.
//   * Any other mix of c and d, any mix of approve and deny, a parse failure or an empty sample list gives c (deny, no lock).
//   * The minutes are then cut to min(requested, ceiling maxMinutes, narrowMinutes if the result is a); never raised.
//     Fewer than 1 minute is a deny (c).

export const DECISIONS = Object.freeze(["a", "b", "c", "d"]);
export const MAX_SAMPLE_MINUTES = 480;
export const MAX_REASON_CHARS = 200;
export const DEFAULT_NARROW_MINUTES = 30;

/** The structured-output schema sent to the model (OpenAI json_schema response_format). */
export const VERDICT_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  required: ["decision", "max_minutes", "reason"],
  properties: {
    decision: { enum: ["a", "b", "c", "d"] },
    max_minutes: { type: "integer", minimum: 0, maximum: MAX_SAMPLE_MINUTES },
    reason: { type: "string", maxLength: MAX_REASON_CHARS },
  },
});

const isApprove = (d) => d === "a" || d === "b";
const wholeMinutes = (v) => (Number.isInteger(v) ? v : 0);
// Control characters (keep tab/newline out too: the reason is one line shown in the admin UI).
const cleanReason = (v) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, MAX_REASON_CHARS) : "");

const FAILED = () => ({ decision: "c", max_minutes: 0, reason: "", parseFailed: true });

/** Model answer text -> sample. Anything that is not exactly the schema becomes {decision: "c", parseFailed: true}. */
export function parseSample(text) {
  let o;
  try { o = JSON.parse(text); } catch { return FAILED(); }
  if (!o || typeof o !== "object" || Array.isArray(o)) return FAILED();
  if (!DECISIONS.includes(o.decision)) return FAILED();
  if (!Number.isInteger(o.max_minutes) || o.max_minutes < 0 || o.max_minutes > MAX_SAMPLE_MINUTES) return FAILED();
  if (typeof o.reason !== "string") return FAILED();
  const sample = { decision: o.decision, max_minutes: o.max_minutes, reason: cleanReason(o.reason) };
  // An approval without a duration is not an approval.
  if (isApprove(sample.decision) && sample.max_minutes < 1) sample.decision = "c";
  return sample;
}

/** The sample as the aggregation sees it (applied again to the raw samples vaultd receives). */
export function normalizeSample(s) {
  if (s?.parseFailed) return { decision: "c", max_minutes: 0 }; // an unparseable answer is a deny, whatever it carries
  const decision = DECISIONS.includes(s?.decision) ? s.decision : "c";
  const minutes = s?.max_minutes;
  const valid = Number.isInteger(minutes) && minutes >= 1 && minutes <= MAX_SAMPLE_MINUTES;
  if (isApprove(decision) && !valid) return { decision: "c", max_minutes: 0 };
  return { decision, max_minutes: valid ? minutes : 0 };
}

/**
 * @param {Array<{decision: string, max_minutes: number}>} samples  the k raw samples
 * @param {{requested: number, ceiling: {maxMinutes: number, narrowMinutes?: number}}} limits  from vaultd's request.create answer
 * @returns {{decision: "a"|"b"|"c"|"d", minutes: number, lock: boolean}}
 */
export function aggregate(samples, { requested, ceiling } = {}) {
  const list = (Array.isArray(samples) ? samples : []).map(normalizeSample);
  const deny = { decision: "c", minutes: 0, lock: false };
  if (list.length === 0) return deny;
  if (list.every((s) => s.decision === "d")) return { decision: "d", minutes: 0, lock: true };
  if (!list.every((s) => isApprove(s.decision))) return deny;
  const decision = list.some((s) => s.decision === "a") ? "a" : "b";
  const narrow = Number.isInteger(ceiling?.narrowMinutes) ? ceiling.narrowMinutes : DEFAULT_NARROW_MINUTES;
  let minutes = Math.min(...list.map((s) => s.max_minutes), wholeMinutes(requested), wholeMinutes(ceiling?.maxMinutes));
  if (decision === "a") minutes = Math.min(minutes, narrow);
  if (minutes < 1) return deny;
  return { decision, minutes, lock: false };
}
