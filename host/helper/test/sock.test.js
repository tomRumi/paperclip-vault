import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { HelperError } from '../errors.js';
import { Semaphore, KeyedMutex } from '../queue.js';
import { createSocketServer, resolveGid, tokenMatches } from '../sock.js';
import { rawCall, scratch, teardown } from './support.js';

async function withServer(fn, handle) {
  const env = scratch();
  const logs = [];
  const server = createSocketServer({
    socketPath: env.sock,
    token: env.token,
    log: (...a) => logs.push(a),
    handle:
      handle ??
      (async (op, params) => {
        if (op === 'echo') return params;
        if (op === 'boom') throw new Error('secret detail');
        if (op === 'denied') throw new HelperError('login_failed', 'nope');
        throw new HelperError('unknown_op', op);
      }),
  });
  await server.listen();
  try {
    await fn(env, logs);
  } finally {
    await teardown(() => server.close(), () => env.cleanup());
  }
}

test('token auth: missing, wrong and non-string tokens are refused before dispatch', async () => {
  let called = 0;
  await withServer(
    async (env) => {
      for (const body of [{ op: 'echo' }, { op: 'echo', token: 'wrong' }, { op: 'echo', token: 5 }, { op: 'echo', token: env.token.slice(0, -1) }]) {
        const res = await rawCall(env.sock, body);
        assert.deepEqual(res, { ok: false, error: { code: 'unauthorized', message: 'missing or wrong token' } });
      }
      assert.equal(called, 0);
      const ok = await rawCall(env.sock, { op: 'echo', token: env.token, a: 1 });
      assert.deepEqual(ok, { ok: true, data: { a: 1 } });
      assert.equal(called, 1);
    },
    async (_op, params) => {
      called += 1;
      return params;
    },
  );
});

test('error mapping: helper errors keep their code, crashes become internal without detail', async () => {
  await withServer(async (env, logs) => {
    const t = env.token;
    assert.deepEqual((await rawCall(env.sock, { op: 'denied', token: t })).error, { code: 'login_failed', message: 'nope' });
    const boom = await rawCall(env.sock, { op: 'boom', token: t });
    assert.deepEqual(boom.error, { code: 'internal', message: 'internal error' });
    assert.equal(JSON.stringify(logs).includes('secret detail'), false);
    assert.equal((await rawCall(env.sock, { op: 'nothing', token: t })).error.code, 'unknown_op');
  });
});

test('malformed requests', async () => {
  await withServer(async (env) => {
    assert.equal((await rawCall(env.sock, 'not json\n')).error.code, 'bad_request');
    assert.equal((await rawCall(env.sock, '[1]\n')).error.code, 'bad_request');
    assert.equal((await rawCall(env.sock, { token: env.token })).error.code, 'bad_request');
    assert.equal((await rawCall(env.sock, { op: 5, token: env.token })).error.code, 'bad_request');
  });
});

test('one request, one response, then the connection closes; extra lines are ignored', async () => {
  await withServer(async (env) => {
    const text = await new Promise((resolve, reject) => {
      const s = net.createConnection(env.sock);
      let buf = '';
      s.on('data', (d) => (buf += d));
      s.on('close', () => resolve(buf));
      s.on('error', reject);
      s.write(`${JSON.stringify({ op: 'echo', token: env.token, n: 1 })}\n${JSON.stringify({ op: 'echo', token: env.token, n: 2 })}\n`);
    });
    assert.equal(text.trim().split('\n').length, 1);
    assert.deepEqual(JSON.parse(text).data, { n: 1 });
  });
});

test('socket file mode follows the config and a stale socket is replaced', async () => {
  const env = scratch();
  const servers = [];
  let dead;
  try {
    const mk = (socketPath, handle) => {
      const server = createSocketServer({ socketPath, mode: '0660', token: env.token, log() {}, handle });
      servers.push(server);
      return server;
    };
    await mk(env.sock, async () => ({})).listen();
    assert.equal(fs.statSync(env.sock).mode & 0o777, 0o660);

    // A helper killed with SIGKILL leaves its socket file behind.
    const stale = path.join(env.root, 'stale.sock');
    dead = spawn('python3', ['-I', '-c', 'import socket,sys,time;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);print(1,flush=True);time.sleep(60)', stale], { stdio: ['ignore', 'pipe', 'inherit'] });
    await new Promise((r) => dead.stdout.once('data', r));
    dead.kill('SIGKILL');
    await new Promise((r) => dead.once('exit', r));
    assert.equal(fs.existsSync(stale), true);

    await mk(stale, async () => ({ up: true })).listen();
    assert.deepEqual((await rawCall(stale, { op: 'x', token: env.token })).data, { up: true });
  } finally {
    await teardown(
      () => Promise.all(servers.map((s) => s.close())),
      () => dead?.kill('SIGKILL'), // an assertion failed before the kill
      () => env.cleanup(),
    );
  }
});

test('tokenMatches / resolveGid', () => {
  assert.equal(tokenMatches('abc', 'abc'), true);
  assert.equal(tokenMatches('abc', 'abd'), false);
  assert.equal(tokenMatches('abc', undefined), false);
  const env = scratch();
  try {
    const f = path.join(env.root, 'group');
    fs.writeFileSync(f, 'root:x:0:\nvault:x:998:vault-helper\n');
    assert.equal(resolveGid('vault', f), 998);
    assert.equal(resolveGid('1234', f), 1234);
    assert.throws(() => resolveGid('nope', f), /not found/);
  } finally {
    env.cleanup();
  }
});

test('Semaphore: FIFO, never more than N holders, abortable waiters', async () => {
  const sem = new Semaphore(3);
  let holders = 0;
  let peak = 0;
  const work = async () => {
    const release = await sem.acquire();
    holders += 1;
    peak = Math.max(peak, holders);
    await new Promise((r) => setTimeout(r, 20));
    holders -= 1;
    release();
  };
  await Promise.all(Array.from({ length: 10 }, work));
  assert.equal(peak, 3);

  const one = new Semaphore(1);
  const r1 = await one.acquire();
  const ac = new AbortController();
  const waiting = one.acquire(ac.signal);
  ac.abort();
  await assert.rejects(waiting, (e) => e.code === 'timeout');
  r1();
  r1(); // double release is harmless
  const r2 = await one.acquire();
  r2();
});

test('KeyedMutex serialises per key and runs different keys in parallel', async () => {
  const m = new KeyedMutex();
  const log = [];
  const task = async (key, name) => {
    const release = await m.acquire(key);
    log.push(`${name}+`);
    await new Promise((r) => setTimeout(r, 30));
    log.push(`${name}-`);
    release();
  };
  await Promise.all([task('a', 'a1'), task('a', 'a2'), task('b', 'b1')]);
  assert.ok(log.indexOf('a1-') < log.indexOf('a2+'));
  assert.ok(log.indexOf('b1+') < log.indexOf('a1-'));
});
