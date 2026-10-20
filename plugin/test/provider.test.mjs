import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createProvider, ProviderError, normalizeBaseUrl, baseUrlProblem } from "../src/verdict/provider.js";
import { aggregate } from "../src/verdict/aggregate.js";

const KEY = "sk-live-SUPER-SECRET-0123456789";

/** A local chat-completions server. `answer(req, n)` returns {status?, body?, delay?} for the n-th POST. */
async function server(answer) {
  const seen = { posts: [], gets: [] };
  const srv = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", async () => {
      const entry = { url: req.url, method: req.method, headers: req.headers, body: raw ? JSON.parse(raw) : null };
      (req.method === "POST" ? seen.posts : seen.gets).push(entry);
      const a = await answer(entry, seen.posts.length);
      if (a.delay) await new Promise((r) => setTimeout(r, a.delay));
      res.writeHead(a.status ?? 200, { "content-type": "application/json" });
      res.end(typeof a.body === "string" ? a.body : JSON.stringify(a.body ?? {}));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { seen, baseUrl: `http://127.0.0.1:${srv.address().port}/v1`, close: () => new Promise((r) => { srv.closeAllConnections(); srv.close(r); }) };
}
const chat = (obj) => ({ body: { choices: [{ message: { role: "assistant", content: typeof obj === "string" ? obj : JSON.stringify(obj) } }] } });
const ctxWith = (logs = [], resolved = []) => ({
  logger: { info: (m, x) => logs.push([m, x]), warn: (m, x) => logs.push([m, x]), error: (m, x) => logs.push([m, x]), debug: (m, x) => logs.push([m, x]) },
  secrets: { resolve: async (ref, opts) => { resolved.push({ ref, opts }); return KEY; } },
});
const cfg = (baseUrl, extra = {}) => ({ baseUrl, apiKey: { type: "secret_ref", secretId: "77777777-7777-4777-8777-777777777777" }, temperature: 0.2, perCallTimeoutMs: 2000, companyId: "c1", ...extra });
const PROMPT = "rendered prompt text";

test("request body: json_schema response_format, user message, model, temperature, bearer key", async () => {
  const s = await server(() => chat({ decision: "b", max_minutes: 45, reason: "fine" }));
  try {
    const p = createProvider(cfg(s.baseUrl, { temperature: 0.4 }), ctxWith());
    const samples = await p.judge({ prompt: PROMPT, model: "vendor/model-1", k: 2 });
    assert.deepEqual(samples, [{ decision: "b", max_minutes: 45, reason: "fine" }, { decision: "b", max_minutes: 45, reason: "fine" }]);
    assert.equal(s.seen.posts.length, 2);
    const { body, headers, url } = s.seen.posts[0];
    assert.equal(url, "/v1/chat/completions");
    assert.equal(headers.authorization, `Bearer ${KEY}`);
    assert.equal(body.model, "vendor/model-1");
    assert.equal(body.temperature, 0.4);
    assert.deepEqual(body.messages, [{ role: "user", content: PROMPT }]);
    assert.equal(body.response_format.type, "json_schema");
    assert.equal(body.response_format.json_schema.name, "verdict");
    assert.equal(body.response_format.json_schema.strict, true);
    assert.deepEqual(body.response_format.json_schema.schema.required, ["decision", "max_minutes", "reason"]);
    assert.equal(body.response_format.json_schema.schema.additionalProperties, false);
    assert.deepEqual(body.response_format.json_schema.schema.properties.decision.enum, ["a", "b", "c", "d"]);
    assert.match(p.id, /^openai-compat:127\.0\.0\.1:\d+$/);
  } finally { await s.close(); }
});

test("no key configured (Ollama): no authorization header and no secret lookup", async () => {
  const s = await server(() => chat({ decision: "a", max_minutes: 20, reason: "" }));
  const resolved = [];
  try {
    const p = createProvider({ ...cfg(s.baseUrl), apiKey: null }, ctxWith([], resolved));
    await p.judge({ prompt: PROMPT, model: "llama3:8b", k: 1 });
    assert.equal(s.seen.posts[0].headers.authorization, undefined);
    assert.equal(resolved.length, 0);
  } finally { await s.close(); }
});

test("the secret is resolved for every call, with company and config path, and never logged or returned", async () => {
  const s = await server(() => ({ status: 500, body: `upstream said: your key ${KEY} is invalid` }));
  const logs = [], resolved = [];
  try {
    const p = createProvider(cfg(s.baseUrl), ctxWith(logs, resolved));
    const r1 = await p.judge({ prompt: PROMPT, model: "m", k: 2 });
    await p.judge({ prompt: PROMPT, model: "m", k: 2 });
    assert.equal(resolved.length, 2, "one resolve per judge call, never cached");
    assert.deepEqual(resolved[0].opts, { companyId: "c1", configPath: "judge.apiKey" });
    assert.deepEqual(resolved[0].ref, cfg(s.baseUrl).apiKey);
    assert.ok(logs.length >= 2);
    const everything = JSON.stringify([logs, r1]);
    assert.ok(!everything.includes(KEY), "key never appears in logs or samples");
    assert.ok(!everything.includes("upstream said"), "upstream error bodies are not echoed");
    // errors from resolution carry no key either
    const bad = createProvider(cfg(s.baseUrl), { ...ctxWith(logs), secrets: { resolve: async () => { throw new Error(`cannot read ${KEY}`); } } });
    await assert.rejects(bad.judge({ prompt: PROMPT, model: "m", k: 2 }), (e) => e instanceof ProviderError && e.code === "secret" && !e.message.includes(KEY));
    const empty = createProvider(cfg(s.baseUrl), { ...ctxWith(), secrets: { resolve: async () => "  " } });
    await assert.rejects(empty.judge({ prompt: PROMPT, model: "m", k: 2 }), { code: "secret" });
  } finally { await s.close(); }
});

test("withKey: one resolve for a whole run (host rate limit), key only in the closure", async () => {
  const s = await server(() => chat({ decision: "c", max_minutes: 0, reason: "" }));
  const resolved = [];
  try {
    const p = createProvider(cfg(s.baseUrl), ctxWith([], resolved));
    await p.withKey(async (bound) => { for (let i = 0; i < 5; i += 1) await bound.judge({ prompt: PROMPT, model: "m", k: 2 }); });
    assert.equal(resolved.length, 1);
    assert.equal(s.seen.posts.length, 10);
  } finally { await s.close(); }
});

test("parse failures: bad JSON, wrong shape, empty content, HTTP errors and garbage bodies all become c + parseFailed", async () => {
  const answers = [chat("not json at all"), chat({ decision: "z", max_minutes: 5, reason: "" }), chat({ decision: "b" }), { body: { choices: [] } }, { status: 429, body: {} }, { body: "<html>" }];
  const s = await server((_req, n) => answers[n - 1]);
  const logs = [];
  try {
    const p = createProvider(cfg(s.baseUrl), ctxWith(logs));
    const samples = await p.judge({ prompt: PROMPT, model: "m", k: 6 });
    assert.equal(samples.length, 6);
    for (const smp of samples) { assert.equal(smp.decision, "c"); assert.equal(smp.parseFailed, true); assert.equal(smp.max_minutes, 0); }
    assert.equal(aggregate(samples, { requested: 60, ceiling: { maxMinutes: 60, narrowMinutes: 30 } }).decision, "c");
  } finally { await s.close(); }
});

test("timeout: a slow model is a c sample after perCallTimeoutMs, not a hang", async () => {
  const s = await server(() => ({ delay: 1500, ...chat({ decision: "b", max_minutes: 60, reason: "" }) }));
  try {
    const p = createProvider(cfg(s.baseUrl, { perCallTimeoutMs: 100 }), ctxWith());
    const t = Date.now();
    const samples = await p.judge({ prompt: PROMPT, model: "m", k: 2 });
    assert.ok(Date.now() - t < 1200);
    assert.deepEqual(samples.map((x) => [x.decision, x.parseFailed]), [["c", true], ["c", true]]);
    assert.match(samples[0].reason, /timeout/);
  } finally { await s.close(); }
});

test("an unreachable endpoint and an aborted signal are c samples too", async () => {
  const p = createProvider(cfg("http://127.0.0.1:1/v1"), ctxWith());
  const samples = await p.judge({ prompt: PROMPT, model: "m", k: 2 });
  assert.deepEqual(samples.map((x) => x.decision), ["c", "c"]);
  const ac = new AbortController(); ac.abort();
  const s = await server(() => chat({ decision: "b", max_minutes: 60, reason: "" }));
  try {
    const q = createProvider(cfg(s.baseUrl), ctxWith());
    assert.deepEqual((await q.judge({ prompt: PROMPT, model: "m", k: 2, signal: ac.signal })).map((x) => x.decision), ["c", "c"]);
  } finally { await s.close(); }
});

test("k disagreement follows the aggregation rule: b+a approve narrow, b+c deny, c+d deny without lock, d+d lock", async () => {
  const run = async (answers) => {
    const s = await server((_r, n) => chat(answers[(n - 1) % answers.length]));
    try {
      const p = createProvider(cfg(s.baseUrl), ctxWith());
      const samples = await p.judge({ prompt: PROMPT, model: "m", k: answers.length });
      return aggregate(samples, { requested: 60, ceiling: { maxMinutes: 60, narrowMinutes: 30 } });
    } finally { await s.close(); }
  };
  const smp = (decision, max_minutes) => ({ decision, max_minutes, reason: "" });
  // the server hands out answers in arrival order; with two parallel calls the pair is what matters
  assert.deepEqual(await run([smp("b", 60), smp("a", 20)]), { decision: "a", minutes: 20, lock: false });
  assert.deepEqual(await run([smp("b", 60), smp("c", 0)]), { decision: "c", minutes: 0, lock: false });
  assert.deepEqual(await run([smp("c", 0), smp("d", 0)]), { decision: "c", minutes: 0, lock: false });
  assert.deepEqual(await run([smp("d", 0), smp("d", 0)]), { decision: "d", minutes: 0, lock: true });
});

test("listModels: GET /models with the key, only valid ids, sorted, deduplicated", async () => {
  const s = await server(() => ({ body: { data: [{ id: "z/model" }, { id: "a/model" }, { id: "a/model" }, { id: "bad id with spaces" }, { id: 5 }, {}] } }));
  const resolved = [];
  try {
    const p = createProvider(cfg(s.baseUrl), ctxWith([], resolved));
    assert.deepEqual(await p.listModels(), [{ id: "a/model" }, { id: "z/model" }]);
    assert.equal(s.seen.gets[0].url, "/v1/models");
    assert.equal(s.seen.gets[0].headers.authorization, `Bearer ${KEY}`);
    assert.equal(resolved.length, 1);
  } finally { await s.close(); }
  const e = await server(() => ({ status: 503, body: "down" }));
  try { await assert.rejects(createProvider(cfg(e.baseUrl), ctxWith()).listModels(), { code: "http" }); } finally { await e.close(); }
});

test("plain http is accepted only for loopback hosts; everything else needs https", () => {
  for (const ok of ["http://127.0.0.1:11434/v1", "http://127.1.2.3/v1", "http://localhost:11434/v1", "http://LOCALHOST/v1", "http://[::1]:11434/v1", "https://openrouter.ai/api/v1", "https://127.0.0.1/v1"]) {
    assert.ok(normalizeBaseUrl(ok), ok);
    assert.equal(baseUrlProblem(ok), null, ok);
  }
  for (const bad of ["http://openrouter.ai/api/v1", "http://10.0.0.5:11434/v1", "http://192.168.1.2/v1", "http://128.0.0.1/v1", "http://127.0.0.1.evil.example/v1", "http://localhost.evil.example/v1", "http://[::2]/v1", "http://0.0.0.0/v1"]) {
    assert.equal(normalizeBaseUrl(bad), null, bad);
    assert.match(baseUrlProblem(bad), /https|credentials|plain http/, bad);
  }
  assert.match(baseUrlProblem("http://gpu-box:11434/v1"), /plain http.*not loopback/);
  assert.throws(() => createProvider({ baseUrl: "http://gpu-box:11434/v1" }, ctxWith()), (e) => e.code === "not_configured" && /plain http/.test(e.message));
});

test("configuration and argument checks", () => {
  for (const bad of ["", "ftp://x/v1", "not a url", "http://user:pw@host/v1", "http://host/v1?key=1", null]) assert.equal(normalizeBaseUrl(bad), null, String(bad));
  assert.equal(normalizeBaseUrl("https://openrouter.ai/api/v1/"), "https://openrouter.ai/api/v1");
  assert.throws(() => createProvider({ baseUrl: "" }, ctxWith()), { code: "not_configured" });
  const p = createProvider(cfg("http://127.0.0.1:9/v1"), ctxWith());
  return Promise.all([
    assert.rejects(p.judge({ prompt: "", model: "m", k: 2 }), { code: "bad_request" }),
    assert.rejects(p.judge({ prompt: "x", model: "bad model", k: 2 }), { code: "bad_request" }),
    assert.rejects(p.judge({ prompt: "x", model: "m", k: 0 }), { code: "bad_request" }),
  ]);
});
