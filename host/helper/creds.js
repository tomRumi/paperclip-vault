// Credentials come from the systemd credentials directory (tmpfs, visible to
// this unit only). Nothing is cached: every read goes to the file, so a secret
// lives in memory only for the duration of one login.
import fs from 'node:fs/promises';
import path from 'node:path';
import { HelperError } from './errors.js';

const PARTS = new Set(['username', 'password', 'totp', 'oauth-client-secret']);

function trimOneNewline(text) {
  return text.endsWith('\n') ? text.slice(0, text.endsWith('\r\n') ? -2 : -1) : text;
}

export class Credentials {
  #dir;

  constructor(dir) {
    this.#dir = dir;
  }

  /** Is the credential provisioned (a non-empty file)? Reads nothing into memory but its size. */
  async has(siteId, part) {
    if (!PARTS.has(part)) throw new TypeError('unknown credential part');
    if (!this.#dir) return false;
    try {
      return (await fs.stat(path.join(this.#dir, `vault-helper.site.${siteId}.${part}`))).size > 0;
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      throw err;
    }
  }

  /** The credential, or null when it is not provisioned (for parts that are optional). */
  async optional(siteId, part) {
    try {
      return await this.site(siteId, part);
    } catch (err) {
      if (err.code === 'missing_credential') return null;
      throw err;
    }
  }

  async site(siteId, part) {
    if (!PARTS.has(part)) throw new TypeError('unknown credential part');
    if (!this.#dir) throw new HelperError('missing_credential', 'no credentials directory configured');
    try {
      const text = await fs.readFile(path.join(this.#dir, `vault-helper.site.${siteId}.${part}`), 'utf8');
      const value = trimOneNewline(text);
      if (value.length === 0) throw Object.assign(new Error('empty'), { code: 'EMPTY' });
      return value;
    } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'EMPTY') {
        throw new HelperError('missing_credential', `credential ${part} of site ${siteId} is not provisioned`);
      }
      throw err;
    }
  }
}

/** The 32-byte store key credential. */
export async function readStoreKey(dir, name = 'vault-helper.storekey') {
  if (!dir) throw new Error('no credentials directory: cannot read the store key');
  const key = await fs.readFile(path.join(dir, name));
  if (key.length !== 32) throw new Error(`credential ${name} must be exactly 32 bytes`);
  return key;
}
