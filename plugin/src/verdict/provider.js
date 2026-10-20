// The verdict provider interface. Everything the plugin needs from "the model that judges a request" is this:
//
//   createProvider(cfg, ctx) -> Provider
//
//   Provider {
//     id: string                                   stable id of the backend, stored with every verdict and judge record
//     listModels(): Promise<{id: string}[]>        what the model picker offers
//     judge({prompt, model, k, signal}): Promise<Sample[]>
//                                                  k independent samples for one rendered prompt, each
//                                                  {decision: "a"|"b"|"c"|"d", max_minutes, reason, parseFailed?}.
//                                                  A failing call is a `c` sample, never a throw; only a setup problem
//                                                  (missing config, unreadable secret) throws ProviderError.
//     withKey(fn): Promise<R>                      optional: run fn(provider) with the API key resolved once (long runs)
//   }
//
// Today the one implementation is verdict/openai-compat.js (the plugin calls the model directly rather than through a
// Paperclip managed agent; docs/DESIGN.md section 7). A provider that runs the verdict some other way can replace it here without touching tools, delivery or the judge gate.
import { createOpenAiCompat, ProviderError, MODEL_RE, normalizeBaseUrl, baseUrlProblem } from "./openai-compat.js";

export { ProviderError, MODEL_RE, normalizeBaseUrl, baseUrlProblem };

/**
 * @param {object} cfg  the `judge` config plus `companyId`: {baseUrl, apiKey?, temperature, perCallTimeoutMs, companyId}
 * @param {object} ctx  plugin context
 * @param {object} [deps]  {fetch} for tests
 */
export function createProvider(cfg, ctx, deps) {
  return createOpenAiCompat(cfg, ctx, deps);
}
