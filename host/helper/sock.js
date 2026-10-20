// Line-JSON unix socket server. One connection = one request line and one
// response line, then close (same framing as the plugin socket). Every request
// carries a bearer token: /etc/vault/helper.token for the day-to-day ops, and
// the separate root-only /etc/vault/helper-admin.token (which is also accepted
// everywhere else) for every op outside `vaultdOps`.
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import { isHelperError } from './errors.js';

export const MAX_REQUEST_BYTES = 8 * 1024 * 1024; // session.import carries a whole storageState
const FIRST_BYTE_TIMEOUT_MS = 10_000;

function digest(text) {
  return createHash('sha256').update(text).digest();
}

export function tokenMatches(expected, given) {
  if (typeof given !== 'string') return false;
  return timingSafeEqual(digest(expected), digest(given));
}

/** Numeric gid of a group name (or numeric string) from /etc/group. */
export function resolveGid(group, groupFile = '/etc/group') {
  if (/^[0-9]+$/.test(group)) return Number(group);
  for (const line of fs.readFileSync(groupFile, 'utf8').split('\n')) {
    const [name, , gid] = line.split(':');
    if (name === group && /^[0-9]+$/.test(gid ?? '')) return Number(gid);
  }
  throw new Error(`group ${group} not found`);
}

/**
 * @param vaultdOps the ops the day-to-day token may call; null: all of them. Any other op needs the admin token.
 * @param handle async (op, params) -> data; throws HelperError for expected failures
 */
export function createSocketServer({ socketPath, mode = '0660', group = null, token, adminToken = null, vaultdOps = null, handle, log }) {
  const server = net.createServer((socket) => serve(socket));
  const live = new Set();

  function reply(socket, body) {
    socket.end(`${JSON.stringify(body)}\n`);
  }

  function fail(socket, code, message) {
    reply(socket, { ok: false, error: { code, message } });
  }

  async function dispatch(socket, line) {
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      return fail(socket, 'bad_request', 'request is not valid JSON');
    }
    if (req === null || typeof req !== 'object' || Array.isArray(req)) {
      return fail(socket, 'bad_request', 'request must be a JSON object');
    }
    // Token first: an unauthenticated peer learns nothing about ops or params.
    const isAdmin = adminToken !== null && tokenMatches(adminToken, req.token);
    if (!isAdmin && !tokenMatches(token, req.token)) return fail(socket, 'unauthorized', 'missing or wrong token');
    const { token: _token, op, ...params } = req;
    if (typeof op !== 'string' || op.length === 0) return fail(socket, 'bad_request', 'op missing');
    if (vaultdOps !== null && !vaultdOps.has(op) && !isAdmin) return fail(socket, 'unauthorized', 'this operation needs the admin token');
    const started = Date.now();
    try {
      const data = await handle(op, params);
      log('info', 'request', { op, ok: true, ms: Date.now() - started });
      return reply(socket, { ok: true, data });
    } catch (err) {
      if (isHelperError(err)) {
        log('info', 'request', { op, ok: false, code: err.code, ms: Date.now() - started });
        return fail(socket, err.code, err.message);
      }
      log('error', 'request crashed', { op, error: err?.name });
      return fail(socket, 'internal', 'internal error');
    }
  }

  function serve(socket) {
    live.add(socket);
    socket.on('close', () => live.delete(socket));
    socket.on('error', () => socket.destroy());
    socket.setTimeout(FIRST_BYTE_TIMEOUT_MS, () => socket.destroy());
    const chunks = [];
    let size = 0;
    let got = false;
    socket.on('data', (chunk) => {
      if (got) return;
      const nl = chunk.indexOf(0x0a);
      size += nl >= 0 ? nl : chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        got = true;
        return fail(socket, 'bad_request', 'request too large');
      }
      chunks.push(nl >= 0 ? chunk.subarray(0, nl) : chunk);
      if (nl < 0) return;
      got = true;
      socket.setTimeout(0); // the operation itself may take a minute
      void dispatch(socket, Buffer.concat(chunks).toString('utf8'));
    });
  }

  return {
    async listen() {
      try {
        if (fs.lstatSync(socketPath).isSocket()) fs.unlinkSync(socketPath); // stale socket of a dead helper
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, () => {
          server.off('error', reject);
          resolve();
        });
      });
      fs.chmodSync(socketPath, parseInt(mode, 8));
      if (group) fs.chownSync(socketPath, process.getuid(), resolveGid(group));
    },
    async close() {
      for (const s of live) s.destroy();
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(socketPath, { force: true });
    },
  };
}
