// End to end on the mocked context: install command -> enrolment -> judge tests -> model selection -> a request is judged by
// the real OpenAI-compatible provider against a local chat-completions server, delivered, and removed at lease end.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { makeWorld, user, ADMIN, COMPANY } from "./helpers/world.mjs";
import { FAKE_COOKIE_VALUE } from "../../tests/fakes/fake_vaultd.mjs";

const KEY = "sk-live-SUPER-SECRET-0123456789";

test("full flow with the real provider, signed protocol and workspace delivery", async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const body = JSON.parse(raw);
      seen.push({ auth: req.headers.authorization, model: body.model });
      const injection = body.messages[0].content.includes("injection");
      const answer = injection ? { decision: "d", max_minutes: 0, reason: "hostile" } : { decision: "b", max_minutes: 40, reason: "fits the task" };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(answer) } }] }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const w = await makeWorld({
    enrolled: false,
    config: { judge: { baseUrl: `http://127.0.0.1:${srv.address().port}/v1`, apiKey: { type: "secret_ref", secretId: "77777777-7777-4777-8777-777777777777" }, k: 2, temperature: 0.2, perCallTimeoutMs: 3000 } },
    overrides: { providerFor: undefined, enrol: { pins: { version: "0.1.0", baseUrl: "https://example.org/r/", installVaultSha256: "b".repeat(64) }, serviceUser: () => "paperclip" } },
  });
  w.data.secret = KEY;
  try {
    // 1. enrolment
    const cmd = await w.action("installCommand", {}, user(ADMIN));
    w.fake.enrolCode = (await w.services.state.enrol()).code;
    assert.ok(cmd.command.includes(`--company ${COMPANY}`));
    await w.c.jobs["enrol-tick"]({});
    assert.equal((await w.action("vaultStatus", {}, user(ADMIN))).enrolled, true);
    // 2. judge tests, then selection
    await w.action("runJudgeTests", { model: "vendor/judge-1" }, user(ADMIN));
    await w.services.judge.whenIdle();
    assert.equal((await w.services.state.judgeRun()).clean, true);
    await w.action("selectModel", { model: "vendor/judge-1" }, user(ADMIN));
    assert.equal(w.c.secretCalls.filter((c) => c.opts.configPath === "judge.apiKey").length >= 1, true);
    seen.length = 0;
    w.c.secretCalls.length = 0;
    // 3. a request
    const res = await w.tool("vault_request_login", { site: "example-admin", reason: "Check the admin UI for ticket 12", minutes: 30 });
    assert.equal(res.data.status, "ready", JSON.stringify(res));
    assert.equal(w.c.secretCalls.length, 1, "the key was resolved for this verdict");
    assert.deepEqual(seen.map((s) => [s.auth, s.model]), [[`Bearer ${KEY}`, "vendor/judge-1"], [`Bearer ${KEY}`, "vendor/judge-1"]]);
    assert.equal(w.fake.calls.find((c) => c.type === "verdict.submit").data.minutes, 30);
    const file = path.join(w.ws, res.data.path);
    assert.ok(fs.readFileSync(file, "utf8").includes(FAKE_COOKIE_VALUE));
    // nothing sensitive in logs, state, activity or results
    const everything = JSON.stringify([w.c.logs, [...w.c.store.values()], w.c.activity, res, w.fake.audit]);
    for (const secret of [KEY, FAKE_COOKIE_VALUE]) assert.ok(!everything.includes(secret));
    // 4. lease end
    w.clock.t += 31 * 60_000;
    await w.c.jobs["lease-sweep"]({});
    assert.equal(fs.existsSync(file), false);
  } finally { srv.closeAllConnections(); srv.close(); await w.cleanup(); }
});
