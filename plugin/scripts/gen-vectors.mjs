// Regenerates tests/vectors/ed25519.json (shared with the Python side: host/vaultd/ed25519.py is tested against it).
// Keys come from fixed seeds, so the output is reproducible: `node scripts/gen-vectors.mjs` rewrites the file byte for byte,
// and the plugin tests fail when the committed file differs. `--check` only compares.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SIGN_PREFIX, buildRequest, signMessage } from "../src/client.js";
import { kidOf } from "../src/keys.js";

const here = path.dirname(fileURLToPath(import.meta.url));
export const VECTORS_FILE = path.join(here, "..", "..", "tests", "vectors", "ed25519.json");

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const keyFromSeed = (seedHex) => {
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  const spki = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  return { privateKey, spki, publicKeySpkiB64: spki.toString("base64"), kid: kidOf(spki), seedHex };
};

const SEED_A = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const SEED_B = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
// RFC 8032 section 7.1, TEST 1 and TEST 2 (plain Ed25519, no signing prefix): checks the verifier itself.
const RFC8032 = [
  { name: "RFC 8032 TEST 1 (empty message)", seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", msgHex: "" },
  { name: "RFC 8032 TEST 2 (one byte 0x72)", seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", msgHex: "72" },
];

export function generate() {
  const a = keyFromSeed(SEED_A);
  const b = keyFromSeed(SEED_B);

  const rfc8032 = RFC8032.map((v) => {
    const k = keyFromSeed(v.seed);
    const msg = Buffer.from(v.msgHex, "hex");
    const sig = crypto.sign(null, msg, k.privateKey);
    return { name: v.name, publicKeyHex: k.spki.subarray(12).toString("hex"), msgHex: v.msgHex, sigHex: sig.toString("hex"), valid: true };
  });

  const msgBytes = Buffer.from(JSON.stringify({ v: 1, type: "hello", installId: "inst-0123456789abcdef01234567", ts: "2026-10-19T12:00:00Z", nonce: "AAAAAAAAAAAAAAAAAAAAAAAA", data: {} }), "utf8");
  const sig = signMessage(a.privateKey, msgBytes);
  const msg = msgBytes.toString("base64url");
  const flip = (buf, i) => { const c = Buffer.from(buf); c[i] ^= 1; return c; };
  const entry = (name, publicKeySpkiB64, msgB64url, sigB64, valid, note) => ({ name, publicKeySpkiB64, msgB64url, sigB64, valid, note });

  const signatures = [
    entry("valid", a.publicKeySpkiB64, msg, sig, true, "signature over b'pcvault-v1\\n' + decoded msg"),
    entry("tampered msg (one bit)", a.publicKeySpkiB64, flip(msgBytes, 10).toString("base64url"), sig, false, "msg changed after signing"),
    entry("tampered sig (one bit)", a.publicKeySpkiB64, msg, flip(Buffer.from(sig, "base64"), 5).toString("base64"), false, "signature changed"),
    entry("wrong key", b.publicKeySpkiB64, msg, sig, false, "verified against another public key"),
    entry("signed without the prefix", a.publicKeySpkiB64, msg, crypto.sign(null, msgBytes, a.privateKey).toString("base64"), false, "signature over the bare msg bytes: the prefix is mandatory"),
    entry("signed over the base64url text", a.publicKeySpkiB64, msg, crypto.sign(null, Buffer.concat([SIGN_PREFIX, Buffer.from(msg, "utf8")]), a.privateKey).toString("base64"), false, "the signature covers the decoded bytes, not their text"),
    entry("truncated signature", a.publicKeySpkiB64, msg, Buffer.from(sig, "base64").subarray(0, 63).toString("base64"), false, "63 bytes"),
    entry("extended signature", a.publicKeySpkiB64, msg, Buffer.concat([Buffer.from(sig, "base64"), Buffer.from([0])]).toString("base64"), false, "65 bytes"),
    entry("all-zero signature", a.publicKeySpkiB64, msg, Buffer.alloc(64).toString("base64"), false, "64 zero bytes"),
    entry("S not reduced (S + L)", a.publicKeySpkiB64, msg, (() => {
      const raw = Buffer.from(sig, "base64");
      const L = (1n << 252n) + 27742317777372353535851937790883648493n;
      let s = 0n;
      for (let i = 31; i >= 0; i -= 1) s = (s << 8n) | BigInt(raw[32 + i]);
      let t = s + L;
      const out = Buffer.from(raw);
      for (let i = 0; i < 32; i += 1) { out[32 + i] = Number(t & 0xffn); t >>= 8n; }
      return out.toString("base64");
    })(), false, "malleable encoding: S must be < L"),
  ];

  const fixed = { ts: "2026-10-19T12:00:00Z", nonce: "BBBBBBBBBBBBBBBBBBBBBBBB" };
  const good = buildRequest({ key: a, installId: "inst-0123456789abcdef01234567", type: "hello", data: {}, ...fixed });
  const goodEnrol = buildRequest({ key: a, installId: null, type: "enrol", data: { code: "ABCD-EFGH-JKMN-PQRS", publicKey: a.publicKeySpkiB64, pluginVersion: "0.1.0" }, ...fixed });
  const parts = (line) => JSON.parse(line);
  const wire = [
    { name: "hello", line: good.line, valid: true, nonce: good.nonce, body: JSON.parse(Buffer.from(parts(good.line).msg, "base64url").toString("utf8")) },
    { name: "enrol (no install id, signed by the key being enrolled)", line: goodEnrol.line, valid: true, nonce: goodEnrol.nonce, body: JSON.parse(Buffer.from(parts(goodEnrol.line).msg, "base64url").toString("utf8")) },
    { name: "msg replaced after signing", line: JSON.stringify({ ...parts(good.line), msg: parts(goodEnrol.line).msg }), valid: false, nonce: null, body: null },
    { name: "sig of another request", line: JSON.stringify({ ...parts(good.line), sig: parts(goodEnrol.line).sig }), valid: false, nonce: null, body: null },
  ];

  return {
    version: 1,
    comment: "Generated by plugin/scripts/gen-vectors.mjs with node:crypto; keys are derived from fixed seeds. Signature = Ed25519 over b'pcvault-v1\\n' + base64url-decoded msg. kid = first 16 hex of sha256(SPKI DER).",
    signedPrefix: "pcvault-v1\n",
    key: { seedHex: a.seedHex, publicKeySpkiB64: a.publicKeySpkiB64, kid: a.kid },
    otherKey: { publicKeySpkiB64: b.publicKeySpkiB64, kid: b.kid },
    rfc8032,
    signatures,
    wire,
  };
}

export const render = () => `${JSON.stringify(generate(), null, 1)}\n`;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = render();
  if (process.argv.includes("--check")) {
    if (fs.readFileSync(VECTORS_FILE, "utf8") !== out) { console.error("tests/vectors/ed25519.json is out of date: run node scripts/gen-vectors.mjs"); process.exit(1); }
    console.log("ed25519 vectors up to date");
  } else {
    fs.mkdirSync(path.dirname(VECTORS_FILE), { recursive: true });
    fs.writeFileSync(VECTORS_FILE, out);
    console.log("wrote", VECTORS_FILE);
  }
}
