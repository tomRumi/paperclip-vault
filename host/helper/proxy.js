// Forward proxy in front of one browser: the navigation guard that prevents
// instead of detects. Route handlers do not see the hops of a redirect and
// the host-resolver rule ignores ports, so a 307/308 to the same host on
// another port could carry cookies or the password there. Every request of
// the browser goes through this proxy instead, and it connects upstream only
// to the exact host:port pairs of allowedHosts (urlAllowed: https, or http for
// loopback). Everything else gets a 403 and no upstream connection is made.
import http from 'node:http';
import net from 'node:net';
import { urlAllowed } from './sites.js';

// Per-hop headers a proxy must not forward (RFC 9110 7.6.1), plus our own credentials.
const HOP_HEADERS = ['connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate'];

const bareHost = (hostname) => hostname.replace(/^\[|\]$/g, '');

/** The authority of a CONNECT request line ("host:port"), or null when it is anything else. */
function tunnelTarget(line) {
  if (!/^[^\s/?#@]+$/.test(line)) return null;
  try {
    return new URL(`https://${line}/`);
  } catch {
    return null;
  }
}

/** May a tunnel to `u` be opened? (TLS to an https origin, or a plain socket to a loopback http origin.) */
function tunnelAllowed(u, allowedHosts) {
  return urlAllowed(u, allowedHosts) || urlAllowed(new URL(`http://${u.hostname}:${u.port || '443'}/`), allowedHosts);
}

/**
 * Start a proxy on 127.0.0.1 (ephemeral port). Resolves { port, refused, close }:
 * `refused` lists the host:port of every refused request, `close()` ends the
 * server and every open connection.
 */
export async function startProxy(allowedHosts) {
  const sockets = new Set();
  const refused = [];
  const track = (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
  };
  const deny = (target) => {
    refused.push(target);
  };

  const server = http.createServer((req, res) => {
    let u;
    try {
      u = new URL(req.url);
    } catch {
      res.writeHead(400, { Connection: 'close' }).end();
      return;
    }
    if (u.protocol !== 'http:' || !urlAllowed(u, allowedHosts)) {
      deny(u.host);
      res.writeHead(403, { Connection: 'close', 'Content-Type': 'text/plain' }).end('blocked: host is not in allowedHosts\n');
      return;
    }
    const headers = { ...req.headers };
    for (const name of [...HOP_HEADERS, ...String(req.headers.connection ?? '').toLowerCase().split(/\s*,\s*/)]) delete headers[name];
    const upstream = http.request({
      hostname: bareHost(u.hostname),
      port: u.port || 80,
      path: `${u.pathname}${u.search}`,
      method: req.method,
      headers,
      agent: false,
    });
    upstream.once('response', (answer) => {
      const out = { ...answer.headers };
      for (const name of HOP_HEADERS) delete out[name];
      res.writeHead(answer.statusCode, answer.statusMessage, out);
      answer.pipe(res);
    });
    upstream.once('error', () => {
      if (res.headersSent) res.destroy();
      else res.writeHead(502, { Connection: 'close' }).end();
    });
    upstream.once('socket', track);
    req.pipe(upstream);
  });
  server.on('connection', track);

  server.on('connect', (req, client, head) => {
    const u = tunnelTarget(req.url);
    if (!u) {
      client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }
    if (!tunnelAllowed(u, allowedHosts)) {
      deny(u.host);
      client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    const upstream = net.connect(Number(u.port || 443), bareHost(u.hostname));
    track(upstream);
    upstream.once('connect', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.once('error', () => {
      if (client.writable) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
      client.destroy();
    });
    upstream.once('close', () => client.destroy());
    client.once('close', () => upstream.destroy());
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  return {
    port: server.address().port,
    refused,
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
