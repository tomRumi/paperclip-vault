import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { createVaultClient, buildRequest, signMessage, VaultError, SIGN_PREFIX } from "../src/client.js";
import { loadOrCreateKey, loadKey, kidOf, KEY_FILE } from "../src/keys.js";
import { render } from "../scripts/gen-vectors.mjs";
import { startFakeVaultd, rawExchange } from "../../tests/fakes/fake_vaultd.mjs";
import { makeWorld } from "./helpers/world.mjs";

const vectorsPath = new URL("../../tests/vectors/ed25519.json", import.meta.url);
const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
const publicKey = (b64) => crypto.createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });

test("ed25519 vectors: the committed file is what the generator produces", () => {
  assert.equal(fs.readFileSync(vectorsPath, "utf8"), render());
});

test("ed25519 vectors: node:crypto agrees with every positive and negative vector", () => {
  assert.equal(vectors.signedPrefix, SIGN_PREFIX.toString("utf8"));
  for (const v of vectors.signatures) {
    const ok = (() => { try { return crypto.verify(null, Buffer.concat([SIGN_PREFIX, Buffer.from(v.msgB64url, "base64url")]), publicKey(v.publicKeySpkiB64), Buffer.from(v.sigB64, "base64")); } catch { return false; } })();
    assert.equal(ok, v.valid, v.name);
  }
  for (const v of vectors.rfc8032) {
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(v.publicKeyHex, "hex")]);
    assert.equal(crypto.verify(null, Buffer.from(v.msgHex, "hex"), crypto.createPublicKey({ key: spki, format: "der", type: "spki" }), Buffer.from(v.sigHex, "hex")), true, v.name);
  }
  assert.equal(vectors.key.kid, kidOf(Buffer.from(vectors.key.publicKeySpkiB64, "base64")));
  assert.ok(vectors.signatures.filter((v) => !v.valid).length >= 8);
});

test("wire vectors: the line decodes to the documented body and verifies", () => {
  for (const w of vectors.wire.filter((x) => x.valid)) {
    const env = JSON.parse(w.line);
    assert.deepEqual(Object.keys(env).sort(), ["kid", "msg", "sig"]);
    assert.equal(env.kid, vectors.key.kid);
    assert.deepEqual(JSON.parse(Buffer.from(env.msg, "base64url").toString()), w.body);
    assert.equal(w.body.v, 1);
    assert.match(w.body.ts, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.equal(Buffer.from(w.body.nonce).length, 24);
    assert.ok(crypto.verify(null, Buffer.concat([SIGN_PREFIX, Buffer.from(env.msg, "base64url")]), publicKey(vectors.key.publicKeySpkiB64), Buffer.from(env.sig, "base64")), w.name);
  }
  for (const w of vectors.wire.filter((x) => !x.valid)) {
    const env = JSON.parse(w.line);
    assert.equal(crypto.verify(null, Buffer.concat([SIGN_PREFIX, Buffer.from(env.msg, "base64url")]), publicKey(vectors.key.publicKeySpkiB64), Buffer.from(env.sig, "base64")), false, w.name);
  }
});

test("buildRequest: body fields, 24 char nonce, signature over prefix + raw bytes", () => {
  const dir = fs.mkdtempSync("/tmp/pcv-");
  try {
    const key = loadOrCreateKey(dir);
    const { line, nonce } = buildRequest({ key, installId: "inst-0123456789abcdef01234567", type: "hello", data: { a: 1 } });
    const env = JSON.parse(line);
    const bytes = Buffer.from(env.msg, "base64url");
    const body = JSON.parse(bytes.toString());
    assert.deepEqual({ ...body, ts: "", nonce: "" }, { v: 1, type: "hello", installId: "inst-0123456789abcdef01234567", ts: "", nonce: "", data: { a: 1 } });
    assert.equal(body.nonce, nonce);
    assert.match(nonce, /^[A-Za-z0-9_-]{24}$/);
    assert.equal(env.kid, key.kid);
    assert.equal(env.sig, signMessage(key.privateKey, bytes));
    assert.throws(() => buildRequest({ key, installId: "x", type: "t", data: { big: "x".repeat(300 * 1024) } }), { code: "too_large" });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("key file: created 0600 in a 0700 directory, reloaded, refused when others can read it", () => {
  const dir = fs.mkdtempSync("/tmp/pcv-");
  try {
    const data = path.join(dir, "d");
    const a = loadOrCreateKey(data);
    assert.equal(fs.statSync(path.join(data, KEY_FILE)).mode & 0o777, 0o600);
    assert.equal(fs.statSync(data).mode & 0o777, 0o700);
    assert.equal(loadOrCreateKey(data).kid, a.kid);
    assert.equal(loadKey(path.join(dir, "none")), null);
    fs.chmodSync(path.join(data, KEY_FILE), 0o640);
    assert.throws(() => loadKey(data), /mode 0600/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("signed messages are accepted by the fake vaultd; tampered, replayed and foreign ones are rejected", async () => {
  const w = await makeWorld();
  try {
    const getKey = () => w.key;
    const client = createVaultClient({ socketPath: w.socketPath, getKey, getInstallId: async () => w.fake.installId });
    const hello = await client.call("hello", {});
    assert.equal(hello.installId, w.fake.installId);
    assert.equal(w.fake.calls.at(-1).type, "hello");

    const good = buildRequest({ key: w.key, installId: w.fake.installId, type: "hello", data: {} });
    const env = JSON.parse(good.line);
    const code = async (line) => JSON.parse(await rawExchange(w.socketPath, line)).error?.code;
    // tampered msg (change the type), same signature
    const body = JSON.parse(Buffer.from(env.msg, "base64url").toString());
    const forged = Buffer.from(JSON.stringify({ ...body, type: "leases.list" })).toString("base64url");
    assert.equal(await code(JSON.stringify({ ...env, msg: forged })), "bad_signature");
    // flipped signature bit
    const sig = Buffer.from(env.sig, "base64"); sig[3] ^= 1;
    assert.equal(await code(JSON.stringify({ ...env, sig: sig.toString("base64") })), "bad_signature");
    // signed by another key under the enrolled kid
    const other = crypto.generateKeyPairSync("ed25519").privateKey;
    assert.equal(await code(JSON.stringify({ ...env, sig: signMessage(other, Buffer.from(env.msg, "base64url")) })), "bad_signature");
    // unknown kid
    assert.equal(await code(JSON.stringify({ ...env, kid: "0000000000000000" })), "bad_signature");
    // the genuine line works once, then it is a replay
    assert.equal(JSON.parse(await rawExchange(w.socketPath, good.line)).ok, true);
    assert.equal(await code(good.line), "replay");
    // old timestamp
    const old = buildRequest({ key: w.key, installId: w.fake.installId, type: "hello", data: {}, ts: "2020-01-01T00:00:00Z" });
    assert.equal(await code(old.line), "clock_skew");
    // wrong install id
    const wrong = buildRequest({ key: w.key, installId: "inst-ffffffffffffffffffffffff", type: "hello", data: {} });
    assert.equal(await code(wrong.line), "bad_request");
    // garbage
    assert.equal(await code("{not json"), "bad_request");
    // typed errors reach the caller
    await assert.rejects(client.call("no.such.op", {}), (e) => e instanceof VaultError && e.code === "unknown_type");
  } finally { await w.cleanup(); }
});

test("client: nonce echo is enforced, framing and limits", async () => {
  const dir = fs.mkdtempSync("/tmp/pcv-");
  const sock = path.join(dir, "s.sock");
  let reply;
  const server = net.createServer((s) => { s.once("data", (d) => { const body = JSON.parse(Buffer.from(JSON.parse(d.toString()).msg, "base64url").toString()); reply(s, body); }); s.on("error", () => {}); });
  await new Promise((r) => server.listen(sock, r));
  try {
    const key = loadOrCreateKey(path.join(dir, "k"));
    const client = createVaultClient({ socketPath: sock, getKey: () => key, getInstallId: async () => "inst-0123456789abcdef01234567", timeoutMs: 400 });
    reply = (s, b) => s.end(`${JSON.stringify({ ok: true, nonce: b.nonce, data: { fine: 1 } })}\n`);
    assert.deepEqual(await client.call("x"), { fine: 1 });
    reply = (s) => s.end(`${JSON.stringify({ ok: true, nonce: "someone-elses-nonce", data: {} })}\n`);
    await assert.rejects(client.call("x"), { code: "protocol", message: /nonce/ });
    reply = (s) => s.end(`${JSON.stringify({ ok: false, nonce: "other", error: { code: "denied", message: "no" } })}\n`);
    await assert.rejects(client.call("x"), { code: "protocol" });
    reply = (s) => s.end(`${JSON.stringify({ ok: false, nonce: null, error: { code: "bad_request", message: "no" } })}\n`);
    await assert.rejects(client.call("x"), { code: "bad_request" });
    reply = (s) => s.end("not json\n");
    await assert.rejects(client.call("x"), { code: "protocol" });
    reply = (s) => s.end(`${JSON.stringify({ ok: false, nonce: null, error: { code: "Weird CODE!", message: "x" } })}\n`);
    await assert.rejects(client.call("x"), { code: "internal" });
    reply = (s) => s.end("no newline at all");
    await assert.rejects(client.call("x"), { code: "protocol" });
    reply = () => {};
    await assert.rejects(client.call("x"), { code: "timeout" });
    reply = (s) => { s.write("x".repeat(2 * 1024 * 1024 + 10)); };
    await assert.rejects(client.call("x"), { code: "too_large" });
    const missing = createVaultClient({ socketPath: path.join(dir, "none.sock"), getKey: () => key, getInstallId: async () => "inst-0123456789abcdef01234567" });
    await assert.rejects(missing.call("x"), { code: "unreachable" });
    const unenrolled = createVaultClient({ socketPath: sock, getKey: () => key, getInstallId: async () => null });
    await assert.rejects(unenrolled.call("x"), { code: "not_enrolled" });
  } finally { server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("a client without a preflight pass makes no call (the socket is never touched)", async () => {
  const dir = fs.mkdtempSync("/tmp/pcv-");
  let touched = false;
  const sock = path.join(dir, "s.sock");
  const server = net.createServer(() => { touched = true; });
  await new Promise((r) => server.listen(sock, r));
  try {
    const key = loadOrCreateKey(path.join(dir, "k"));
    const client = createVaultClient({ socketPath: sock, getKey: () => key, getInstallId: async () => "inst-0123456789abcdef01234567", preflight: () => { throw new VaultError("exposed", "no"); } });
    await assert.rejects(client.call("hello"), { code: "exposed" });
    await assert.rejects(client.enrol({}), { code: "exposed" });
    assert.equal(touched, false);
  } finally { server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("fake vaultd: enrolment checks the code, the expiry and the proof of possession", async () => {
  const dir = fs.mkdtempSync("/tmp/pcv-");
  const sock = path.join(dir, "s.sock");
  const fake = await startFakeVaultd({ socketPath: sock, enrolCode: "ABCD-EFGH-JKMN-PQRS" });
  try {
    const key = loadOrCreateKey(path.join(dir, "k"));
    const client = createVaultClient({ socketPath: sock, getKey: () => key, getInstallId: async () => null });
    await assert.rejects(client.enrol({ code: "WRONG-CODE", publicKey: key.publicKeyB64 }), { code: "denied" });
    // proof of possession: the enrolled public key must be the signing key
    const other = loadOrCreateKey(path.join(dir, "k2"));
    await assert.rejects(client.enrol({ code: "ABCD-EFGH-JKMN-PQRS", publicKey: other.publicKeyB64 }), { code: "bad_signature" });
    const res = await client.enrol({ code: "ABCD-EFGH-JKMN-PQRS", publicKey: key.publicKeyB64 });
    assert.equal(res.installId, fake.installId);
    await assert.rejects(client.enrol({ code: "ABCD-EFGH-JKMN-PQRS", publicKey: key.publicKeyB64 }), { code: "denied" }, "single use");
  } finally { await fake.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
