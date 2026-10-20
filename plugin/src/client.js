// The plugin -> vaultd protocol (design section 2): one connection = one signed request line + one response line, then close.
//
//   request  {"msg": base64url(JSON body bytes), "sig": base64(Ed25519), "kid": "<keyId>"}\n
//   body     {"v":1, "type", "installId", "ts", "nonce", "data"}
//   signed   b"pcvault-v1\n" + the decoded msg bytes (raw bytes: no JSON canonicalisation to agree on)
//   response {"ok":true,"nonce","data"} | {"ok":false,"nonce","error":{"code","message"}}   (not signed; the nonce echo is checked)
//
// Response limits: 2 MiB; request limit 256 KiB. There is no unsigned call. `enrol` is the only call sent without an
// installId (the plugin does not know it yet); it is signed with the key being enrolled.
import crypto from "node:crypto";
import net from "node:net";

export const PROTOCOL_VERSION = 1;
export const SIGN_PREFIX = Buffer.from("pcvault-v1\n", "utf8");
export const MAX_REQUEST_BYTES = 256 * 1024;
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 15_000;

/** Codes vaultd returns, plus the ones raised locally: `unreachable` (no socket / connection refused), `timeout`,
 *  `protocol` (malformed or mismatching answer), `not_enrolled` (no install id yet), `too_large`. */
export class VaultError extends Error {
  constructor(code, message) { super(message); this.name = "VaultError"; this.code = code; }
}

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

/** Ed25519 signature (base64) over the signing prefix plus the message bytes. */
export function signMessage(privateKey, msgBytes) {
  return crypto.sign(null, Buffer.concat([SIGN_PREFIX, msgBytes]), privateKey).toString("base64");
}

/** Builds the wire line (without the newline) and returns it with the nonce to expect back. */
export function buildRequest({ key, installId, type, data, ts = nowIso(), nonce = crypto.randomBytes(18).toString("base64url") }) {
  const body = { v: PROTOCOL_VERSION, type, installId: installId ?? null, ts, nonce, data: data ?? {} };
  const msgBytes = Buffer.from(JSON.stringify(body), "utf8");
  const line = JSON.stringify({ msg: msgBytes.toString("base64url"), sig: signMessage(key.privateKey, msgBytes), kid: key.kid });
  if (Buffer.byteLength(line) > MAX_REQUEST_BYTES) throw new VaultError("too_large", "the request is larger than vaultd accepts (256 KiB)");
  return { line, nonce };
}

/**
 * Sends one line, resolves with the one response line (string). Rejects with VaultError.
 * @param {{connect?: Function}} [opts] connect(socketPath) -> net.Socket (tests)
 */
function exchange(socketPath, line, { timeoutMs, connect = (p) => net.createConnection(p) }) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const socket = connect(socketPath);
    const finish = (err, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      err ? reject(err) : resolve(value);
    };
    const timer = setTimeout(() => finish(new VaultError("timeout", "vaultd did not answer in time")), timeoutMs);
    socket.on("error", (e) => finish(new VaultError("unreachable", e.code === "ENOENT" ? "the vaultd socket does not exist" : e.code === "EACCES" ? "no permission to use the vaultd socket" : `cannot reach vaultd (${e.code ?? "error"})`)));
    socket.on("connect", () => socket.write(`${line}\n`));
    socket.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_RESPONSE_BYTES) return finish(new VaultError("too_large", "vaultd answered with more than 2 MiB"));
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      const nl = buf.indexOf(0x0a);
      if (nl >= 0) finish(null, buf.subarray(0, nl).toString("utf8"));
    });
    socket.on("end", () => finish(new VaultError("protocol", "vaultd closed the connection without a complete answer")));
    socket.on("close", () => finish(new VaultError("protocol", "vaultd closed the connection without a complete answer")));
  });
}

/**
 * @param {object} o
 * @param {string} o.socketPath
 * @param {() => {privateKey, kid}} o.getKey  the signing key (loaded per call, never held)
 * @param {() => Promise<string|null>} o.getInstallId  null until enrolled
 * @param {() => void} [o.preflight]  called before every signed call; throws to refuse (src/exposure.js)
 * @param {number} [o.timeoutMs]
 * @param {Function} [o.connect]  tests
 */
export function createVaultClient({ socketPath, getKey, getInstallId, preflight, timeoutMs = DEFAULT_TIMEOUT_MS, connect }) {
  async function send(type, data, installId) {
    preflight?.(); // throws VaultError("exposed") before anything is signed
    const key = getKey();
    const { line, nonce } = buildRequest({ key, installId, type, data });
    const raw = await exchange(socketPath, line, { timeoutMs, connect });
    let res;
    try { res = JSON.parse(raw); } catch { throw new VaultError("protocol", "vaultd answered with invalid JSON"); }
    if (!res || typeof res !== "object" || typeof res.ok !== "boolean") throw new VaultError("protocol", "vaultd answered with an unexpected message");
    if (res.ok && res.nonce !== nonce) throw new VaultError("protocol", "the answer does not echo the request nonce");
    if (!res.ok) {
      // An error raised before vaultd could read the nonce may carry none; one that carries a nonce must match.
      if (res.nonce != null && res.nonce !== nonce) throw new VaultError("protocol", "the answer does not echo the request nonce");
      const code = typeof res.error?.code === "string" && /^[a-z_]{1,40}$/.test(res.error.code) ? res.error.code : "internal";
      throw new VaultError(code, typeof res.error?.message === "string" ? res.error.message.slice(0, 300) : "vaultd refused the request");
    }
    return res.data ?? {};
  }

  return {
    /** A signed call as the enrolled plugin. */
    async call(type, data = {}) {
      const installId = await getInstallId();
      if (!installId) throw new VaultError("not_enrolled", "the plugin is not enrolled with vaultd yet");
      return send(type, data, installId);
    },
    /** The enrolment call: signed with the key being enrolled, no install id yet. */
    enrol(data) {
      return send("enrol", data, null);
    },
  };
}
