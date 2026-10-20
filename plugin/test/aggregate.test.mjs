import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { aggregate, parseSample, normalizeSample, VERDICT_SCHEMA } from "../src/verdict/aggregate.js";

const vectors = JSON.parse(fs.readFileSync(new URL("../../tests/vectors/aggregate.json", import.meta.url), "utf8"));

test("aggregate: shared vectors (hand-derived expectations, also run by vaultd)", () => {
  assert.ok(vectors.cases.length >= 30);
  for (const c of vectors.cases) assert.deepEqual(aggregate(c.samples, { requested: c.requested, ceiling: c.ceiling }), c.expected, c.name);
});

test("aggregate: the k-sample rule spelled out", () => {
  const ceiling = { maxMinutes: 60, narrowMinutes: 30 };
  const s = (decision, max_minutes = 60) => ({ decision, max_minutes, reason: "" });
  assert.equal(aggregate([s("d", 0), s("d", 0)], { requested: 60, ceiling }).lock, true, "all d locks");
  assert.equal(aggregate([s("c", 0), s("d", 0)], { requested: 60, ceiling }).lock, false, "c+d does not lock");
  assert.equal(aggregate([s("b"), s("d", 0)], { requested: 60, ceiling }).decision, "c");
  assert.equal(aggregate([s("b"), s("a")], { requested: 60, ceiling }).decision, "a", "safer approval wins");
});

test("parseSample: valid, truncated reason, and every failure becomes c + parseFailed", () => {
  assert.deepEqual(parseSample('{"decision":"b","max_minutes":45,"reason":"fine"}'), { decision: "b", max_minutes: 45, reason: "fine" });
  assert.equal(parseSample(JSON.stringify({ decision: "a", max_minutes: 30, reason: "x".repeat(500) })).reason.length, 200);
  assert.equal(parseSample('{"decision":"a","max_minutes":30,"reason":"line\\nbreak"}').reason, "line break");
  const failed = { decision: "c", max_minutes: 0, reason: "", parseFailed: true };
  for (const bad of ["", "not json", "[]", "null", '{"decision":"x","max_minutes":1,"reason":""}', '{"decision":"b","reason":""}',
    '{"decision":"b","max_minutes":"30","reason":""}', '{"decision":"b","max_minutes":30.5,"reason":""}', '{"decision":"b","max_minutes":481,"reason":""}',
    '{"decision":"b","max_minutes":-1,"reason":""}', '{"decision":"b","max_minutes":30}', '{"decision":"b","max_minutes":30,"reason":5}']) {
    assert.deepEqual(parseSample(bad), failed, JSON.stringify(bad));
  }
});

test("parseSample: an approval without minutes is a plain deny", () => {
  assert.deepEqual(parseSample('{"decision":"b","max_minutes":0,"reason":"no time"}'), { decision: "c", max_minutes: 0, reason: "no time" });
  assert.deepEqual(normalizeSample({ decision: "a", max_minutes: 0 }), { decision: "c", max_minutes: 0 });
  assert.deepEqual(normalizeSample({ decision: "d", max_minutes: 99999 }), { decision: "d", max_minutes: 0 });
});

test("normalizeSample: a parseFailed sample is c whatever it says (also d, also with minutes)", () => {
  for (const decision of ["a", "b", "c", "d"]) assert.deepEqual(normalizeSample({ decision, max_minutes: 60, reason: "x", parseFailed: true }), { decision: "c", max_minutes: 0 }, decision);
  const ceiling = { maxMinutes: 60, narrowMinutes: 30 };
  const s = (decision, extra = {}) => ({ decision, max_minutes: decision === "d" ? 0 : 60, reason: "", ...extra });
  assert.deepEqual(aggregate([s("b"), s("b", { parseFailed: true })], { requested: 60, ceiling }), { decision: "c", minutes: 0, lock: false });
  assert.deepEqual(aggregate([s("d"), s("d", { parseFailed: true })], { requested: 60, ceiling }), { decision: "c", minutes: 0, lock: false });
});

test("verdict schema matches the documented schema (strict, three required fields)", () => {
  assert.deepEqual(VERDICT_SCHEMA.required, ["decision", "max_minutes", "reason"]);
  assert.equal(VERDICT_SCHEMA.additionalProperties, false);
  assert.deepEqual(VERDICT_SCHEMA.properties.decision.enum, ["a", "b", "c", "d"]);
  assert.equal(VERDICT_SCHEMA.properties.max_minutes.maximum, 480);
  assert.equal(VERDICT_SCHEMA.properties.reason.maxLength, 200);
});
