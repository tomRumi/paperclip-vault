// The per-browser forward proxy: only the exact host:port pairs of allowedHosts
// are reached upstream. The last test drives a real Chromium through a 307 to
// another port of the same host (heavy: run under the shared lock).
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { after, before, describe, test } from 'node:test';
import { BrowserPool } from '../browser.js';
import { startProxy } from '../proxy.js';
import { SKIP_BROWSER, teardown } from './support.js';

/** An HTTP server on 127.0.0.1 that counts requests and answers with `answer(req, res)`. */
async function origin(answer = (_req, res) => res.end('hello')) {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    answer(req, res);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    hits,
    port,
    host: `127.0.0.1:${port}`,
    origin: `http://127.0.0.1:${port}`,
    stop: () => new Promise((r) => (server.close(r), server.closeAllConnections())),
  };
}

/** GET `url` through the proxy the way a browser does: absolute URI in the request line. */
function viaProxy(proxy, url, { method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: proxy.port, method, path: url, headers: { Host: new URL(url).host } }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.once('error', reject);
    req.end();
  });
}

/** CONNECT host:port through the proxy; resolves the status line and the open socket. */
function connectVia(proxy, target) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxy.port, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    s.once('error', reject);
    s.once('data', (d) => resolve({ status: Number(String(d).split(' ')[1]), socket: s }));
  });
}

describe('proxy', () => {
  let allowed, other, proxy;
  before(async () => {
    allowed = await origin((req, res) => {
      if (req.url === '/hop') res.writeHead(307, { Location: `${other.origin}/landing` }).end();
      else res.end('hello');
    });
    other = await origin();
    proxy = await startProxy([allowed.host]);
  });
  after(() => teardown(() => proxy?.close(), () => allowed?.stop(), () => other?.stop()));

  test('plain HTTP: an allowed host:port is forwarded, redirects are passed on as they are', async () => {
    const res = await viaProxy(proxy, `${allowed.origin}/page?x=1`);
    assert.deepEqual([res.status, res.body], [200, 'hello']);
    assert.deepEqual(allowed.hits, ['GET /page?x=1']);
    const hop = await viaProxy(proxy, `${allowed.origin}/hop`);
    assert.deepEqual([hop.status, hop.headers.location], [307, `${other.origin}/landing`]);
  });

  test('plain HTTP: the same host on another port gets a 403 and is never connected', async () => {
    const res = await viaProxy(proxy, `${other.origin}/landing`);
    assert.equal(res.status, 403);
    assert.deepEqual(other.hits, []);
    assert.ok(proxy.refused.includes(other.host));
  });

  test('CONNECT: only an allowed host:port is tunnelled', async () => {
    const denied = await connectVia(proxy, other.host);
    assert.equal(denied.status, 403);
    denied.socket.destroy();
    const ok = await connectVia(proxy, allowed.host);
    assert.equal(ok.status, 200);
    ok.socket.write(`GET /tunnel HTTP/1.1\r\nHost: ${allowed.host}\r\nConnection: close\r\n\r\n`);
    await new Promise((r) => ok.socket.once('data', r));
    ok.socket.destroy();
    assert.ok(allowed.hits.includes('GET /tunnel'));
    assert.deepEqual(other.hits, []);
    assert.equal((await connectVia(proxy, 'localhost:1/../x').catch(() => ({ status: 0 }))).status, 400);
  });

  test('http outside loopback is refused even for a listed host; the port must match exactly', async () => {
    const strict = await startProxy(['app.example.org', 'app.example.org:8443']);
    try {
      for (const url of ['http://app.example.org/', 'http://app.example.org:8443/', 'http://other.example.org/']) {
        assert.equal((await viaProxy(strict, url)).status, 403, url);
      }
      assert.equal((await connectVia(strict, 'app.example.org:80')).status, 403);
      assert.equal((await connectVia(strict, 'app.example.org:8080')).status, 403);
      assert.deepEqual(strict.refused.length, 5);
    } finally {
      await strict.close();
    }
  });
});

describe('browser behind the proxy', { skip: SKIP_BROWSER }, () => {
  test('a 307 to the same host on another port never reaches that port', async () => {
    const second = await origin();
    const first = await origin((req, res) => res.writeHead(307, { Location: `${second.origin}/steal` }).end());
    const pool = new BrowserPool({ allowNoSandbox: true, log() {} });
    try {
      await pool.with(AbortSignal.timeout(30_000), [first.host], async (browser) => {
        const page = await (await browser.newContext()).newPage();
        const res = await page.goto(`${first.origin}/start`, { waitUntil: 'domcontentloaded' }).catch(() => null);
        assert.notEqual(res?.status(), 200, 'the redirect target was not served');
        // typing the other port's address is refused the same way
        const direct = await page.goto(`${second.origin}/direct`, { waitUntil: 'domcontentloaded' }).catch(() => null);
        assert.notEqual(direct?.status(), 200);
      });
      assert.deepEqual(first.hits, ['GET /start']);
      assert.deepEqual(second.hits, [], 'the other port\'s server saw no request');
    } finally {
      await teardown(() => pool.closeAll(), () => first.stop(), () => second.stop());
    }
  });
});
