// The plugin's Ed25519 signing key. Created by the first "installCommand" action, stored as PKCS8 PEM at
// <dataDir>/plugin-key.pem (mode 0600, directory 0700) outside every agent workspace root. vaultd learns the public half
// through the one-time-code enrolment (src/enrol.js). Accepted limit: the service user can read the file (agents are
// sandboxed away from it).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const KEY_FILE = "plugin-key.pem";

/** key id: the first 16 hex characters of sha256(SPKI DER). */
export const kidOf = (spkiDer) => crypto.createHash("sha256").update(spkiDer).digest("hex").slice(0, 16);

function describe(privateKey) {
  const publicKey = crypto.createPublicKey(privateKey);
  const der = publicKey.export({ type: "spki", format: "der" });
  return { privateKey, publicKeyDer: der, publicKeyB64: der.toString("base64"), kid: kidOf(der) };
}

/** The stored key, or null when there is none yet. Refuses a key file other users can read. */
export function loadKey(dataDir) {
  const file = path.join(dataDir, KEY_FILE);
  let st;
  try { st = fs.statSync(file); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
  if (!st.isFile() || (st.mode & 0o077) !== 0 || st.uid !== process.getuid())
    throw new Error(`${file} must be a regular file owned by the service user with mode 0600`);
  const privateKey = crypto.createPrivateKey(fs.readFileSync(file));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error(`${file} is not an Ed25519 key`);
  return describe(privateKey);
}

/** The stored key, created on first use. */
export function loadOrCreateKey(dataDir) {
  const existing = loadKey(dataDir);
  if (existing) return existing;
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dataDir, 0o700);
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  try {
    fs.writeFileSync(path.join(dataDir, KEY_FILE), privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  } catch (e) {
    if (e.code === "EEXIST") return loadKey(dataDir);
    throw e;
  }
  return describe(privateKey);
}
