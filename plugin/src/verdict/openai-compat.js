// Verdict provider for any OpenAI-compatible chat-completions endpoint (OpenRouter, Ollama's /v1, vLLM, ...).
//
//   POST {baseUrl}/chat/completions   one call per sample, k calls in parallel, structured output (json_schema)
//   GET  {baseUrl}/models             the model picker
//
// The API key is a Paperclip company secret referenced from the plugin config (format "secret-ref"). It is resolved for
// every judge()/listModels() call, held only in local variables for that call and never cached, logged, put in an error
// message or returned. Ollama needs no key: leave the field empty.
//
// Calls use the global fetch, not ctx.http.fetch: the host RPC behind ctx.http.fetch carries no AbortSignal, so a per-call
// timeout could not cancel the request. The `http.outbound` capability is still declared for transparency.
import { VERDICT_SCHEMA, parseSample } from "./aggregate.js";

export const MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,119}$/;
export const API_KEY_CONFIG_PATH = "judge.apiKey";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_MODELS = 2000;

export class ProviderError extends Error {
  constructor(code, message) { super(message); this.name = "ProviderError"; this.code = code; }
}

/** True for localhost, 127.0.0.0/8 and ::1 (the only hosts the judge may be reached at over plain http). */
export function isLoopbackHost(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "::1") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  return Boolean(m) && m.slice(1).every((o) => Number(o) <= 255);
}

/** Why `value` cannot be the judge base URL, as a message for the admin; null when it is usable. Empty is "not set". */
export function baseUrlProblem(value) {
  if (typeof value !== "string" || !value.trim()) return "the judge base URL is not set";
  let u;
  try { u = new URL(value.trim()); } catch { return "the judge base URL is not a valid URL"; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "the judge base URL must start with https:// (or http:// for a loopback host)";
  if (u.username || u.password || u.search || u.hash) return "the judge base URL must not contain credentials, a query or a fragment";
  if (u.protocol === "http:" && !isLoopbackHost(u.hostname)) {
    return "the judge base URL uses plain http to a host that is not loopback (127.0.0.0/8, ::1, localhost); the API key and the prompts would cross the network unencrypted. Use https://";
  }
  return null;
}

/** https URL (http only for loopback hosts) without credentials, query or fragment, no trailing slash; null when unusable. */
export function normalizeBaseUrl(value) {
  if (baseUrlProblem(value) !== null) return null;
  const u = new URL(value.trim());
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}

async function readCapped(res, max = MAX_RESPONSE_BYTES) {
  if (!res.body) return "";
  const chunks = [];
  let size = 0;
  for await (const chunk of res.body) {
    size += chunk.length;
    if (size > max) throw new ProviderError("too_large", "response too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const failedSample = (why) => ({ decision: "c", max_minutes: 0, reason: `provider error: ${why}`, parseFailed: true });

function contentOf(json) {
  const content = json?.choices?.[0]?.message?.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((p) => (typeof p?.text === "string" ? p.text : "")).join("");
  return "";
}

/**
 * @param {object} cfg  {baseUrl, apiKey?, temperature, perCallTimeoutMs, companyId}
 * @param {object} ctx  plugin context (secrets, logger)
 * @param {{fetch?: typeof fetch}} [deps]
 */
export function createOpenAiCompat(cfg, ctx, { fetch: fetchFn = globalThis.fetch } = {}) {
  const baseUrl = normalizeBaseUrl(cfg?.baseUrl);
  if (!baseUrl) throw new ProviderError("not_configured", baseUrlProblem(cfg?.baseUrl));
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  const timeoutMs = Number.isInteger(cfg.perCallTimeoutMs) && cfg.perCallTimeoutMs > 0 ? cfg.perCallTimeoutMs : 30_000;
  const temperature = typeof cfg.temperature === "number" ? cfg.temperature : 0.2;
  const id = `openai-compat:${new URL(baseUrl).host}`;

  async function resolveKey() {
    if (!cfg.apiKey) return null;
    let key;
    try { key = await ctx.secrets.resolve(cfg.apiKey, { companyId: cfg.companyId, configPath: API_KEY_CONFIG_PATH }); }
    catch { throw new ProviderError("secret", "the judge API key could not be read from the Paperclip secrets"); }
    key = typeof key === "string" ? key.trim() : "";
    if (!key) throw new ProviderError("secret", "the judge API key secret is empty");
    return key;
  }

  const headers = (key, json) => ({
    ...(json ? { "content-type": "application/json" } : {}),
    accept: "application/json",
    ...(key ? { authorization: `Bearer ${key}` } : {}),
  });

  const signalFor = (signal) => (signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs));

  async function sampleOnce({ prompt, model, key, signal }) {
    const body = {
      model,
      temperature,
      messages: [{ role: "user", content: prompt }],
      response_format: { type: "json_schema", json_schema: { name: "verdict", strict: true, schema: VERDICT_SCHEMA } },
    };
    let outcome;
    try {
      const res = await fetchFn(`${baseUrl}/chat/completions`, { method: "POST", headers: headers(key, true), body: JSON.stringify(body), signal: signalFor(signal) });
      const text = await readCapped(res);
      if (!res.ok) { outcome = `http_${res.status}`; return failedSample(outcome); }
      return parseSample(contentOf(JSON.parse(text)));
    } catch (e) {
      outcome = e?.name === "TimeoutError" || e?.name === "AbortError" ? "timeout" : e instanceof SyntaxError ? "bad_response" : e?.code === "too_large" ? "too_large" : "network";
      return failedSample(outcome);
    } finally {
      if (outcome) log.warn("judge call failed", { provider: id, model, outcome });
    }
  }

  /** Model ids offered by the endpoint (sorted, deduplicated). */
  async function listModels({ signal } = {}) {
    const key = await resolveKey();
    let res;
    try { res = await fetchFn(`${baseUrl}/models`, { method: "GET", headers: headers(key, false), signal: signalFor(signal) }); }
    catch { throw new ProviderError("network", "the judge endpoint could not be reached"); }
    let json;
    try {
      if (!res.ok) throw new ProviderError("http", `the judge endpoint answered HTTP ${res.status}`);
      json = JSON.parse(await readCapped(res));
    } catch (e) {
      if (e instanceof ProviderError) throw e;
      throw new ProviderError("bad_response", "the model list is not valid JSON");
    }
    const ids = (Array.isArray(json?.data) ? json.data : []).map((m) => m?.id).filter((m) => typeof m === "string" && MODEL_RE.test(m));
    return [...new Set(ids)].sort().slice(0, MAX_MODELS).map((m) => ({ id: m }));
  }

  /** k independent samples for one rendered prompt. Per-call failures are `c` samples with parseFailed; only a setup problem throws. */
  function sampleMany({ prompt, model, k, signal }, key) {
    if (typeof prompt !== "string" || !prompt) throw new ProviderError("bad_request", "empty prompt");
    if (typeof model !== "string" || !MODEL_RE.test(model)) throw new ProviderError("bad_request", "invalid model id");
    if (!Number.isInteger(k) || k < 1 || k > 9) throw new ProviderError("bad_request", "k must be an integer from 1 to 9");
    return Promise.all(Array.from({ length: k }, () => sampleOnce({ prompt, model, key, signal })));
  }

  return {
    id,
    listModels,
    async judge(args) { return sampleMany(args, await resolveKey()); },
    /** Resolves the key once and runs fn with a provider that reuses it, then drops it. For long runs (the judge tests) that
     *  would otherwise hit the host's secret-resolution rate limit (30 per minute and company); the key lives only in this
     *  call's closure. */
    async withKey(fn) {
      const key = await resolveKey();
      return fn({ id, listModels, judge: async (args) => sampleMany(args, key) });
    },
  };
}
