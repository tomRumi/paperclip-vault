// AES-256-GCM sealed store. Key = the 32-byte `vault-helper.storekey`
// credential; a separate subkey is derived per record kind (HKDF-SHA256) and
// the record's kind and id are bound as additional authenticated data, so a
// sealed file cannot be moved to another name or kind.
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { HelperError } from './errors.js';

const MAGIC = Buffer.from('PCVS1');
const IV_LEN = 12;
const TAG_LEN = 16;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export const KINDS = Object.freeze({
  trust: 'store/trust',
  oauth: 'store/oauth',
  session: 'store/session',
  lease: 'leases',
});

export class Sealer {
  #key;

  constructor(storeKey) {
    if (!Buffer.isBuffer(storeKey) || storeKey.length !== 32) {
      throw new TypeError('storekey must be exactly 32 bytes');
    }
    this.#key = Buffer.from(storeKey);
  }

  #subkey(kind) {
    return Buffer.from(
      hkdfSync('sha256', this.#key, Buffer.alloc(0), `pcvault-seal-v1:${kind}`, 32),
    );
  }

  seal(kind, id, value) {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', this.#subkey(kind), iv);
    cipher.setAAD(Buffer.from(`${kind}:${id}`));
    const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), ct]);
  }

  open(kind, id, blob) {
    try {
      if (blob.length < MAGIC.length + IV_LEN + TAG_LEN || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new Error('format');
      }
      const iv = blob.subarray(MAGIC.length, MAGIC.length + IV_LEN);
      const tag = blob.subarray(MAGIC.length + IV_LEN, MAGIC.length + IV_LEN + TAG_LEN);
      const ct = blob.subarray(MAGIC.length + IV_LEN + TAG_LEN);
      const decipher = createDecipheriv('aes-256-gcm', this.#subkey(kind), iv);
      decipher.setAAD(Buffer.from(`${kind}:${id}`));
      decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
      return JSON.parse(plain.toString('utf8'));
    } catch {
      throw new HelperError('seal_unreadable', `sealed ${kind} record ${id} is unreadable`);
    }
  }
}

/** Atomic, 0600, directory-per-kind persistence of sealed records. */
export class SealedStore {
  #root;
  #sealer;

  constructor({ root, sealer }) {
    this.#root = root;
    this.#sealer = sealer;
  }

  #file(kind, id) {
    if (!KINDS[kind]) throw new TypeError(`unknown record kind ${kind}`);
    if (!ID_RE.test(id)) throw new TypeError('malformed record id');
    return path.join(this.#root, KINDS[kind], `${id}.enc`);
  }

  async put(kind, id, value) {
    const file = this.#file(kind, id);
    await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.${randomBytes(6).toString('hex')}.tmp`;
    const fh = await fsp.open(tmp, 'wx', 0o600);
    try {
      await fh.writeFile(this.#sealer.seal(kind, id, value));
      await fh.sync();
    } catch (err) {
      await fh.close();
      await fsp.rm(tmp, { force: true });
      throw err;
    }
    await fh.close();
    await fsp.rename(tmp, file);
  }

  /** Is there a record? (No decryption.) */
  async has(kind, id) {
    try {
      await fsp.access(this.#file(kind, id));
      return true;
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      throw err;
    }
  }

  /** The record, or null when absent. Throws seal_unreadable when corrupt or sealed under another key. */
  async get(kind, id) {
    let blob;
    try {
      blob = await fsp.readFile(this.#file(kind, id));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
    return this.#sealer.open(kind, id, blob);
  }

  /** Overwrite with zeros, then unlink. (Best effort: a copy-on-write filesystem may keep old blocks.) */
  async shred(kind, id) {
    const file = this.#file(kind, id);
    let fh;
    try {
      fh = await fsp.open(file, 'r+');
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      throw err;
    }
    try {
      const { size } = await fh.stat();
      await fh.write(Buffer.alloc(size), 0, size, 0);
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fsp.rm(file, { force: true });
    return true;
  }

  async list(kind) {
    this.#file(kind, 'x');
    let names;
    try {
      names = await fsp.readdir(path.join(this.#root, KINDS[kind]));
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
    return names.filter((n) => n.endsWith('.enc')).map((n) => n.slice(0, -4)).filter((id) => ID_RE.test(id));
  }
}
