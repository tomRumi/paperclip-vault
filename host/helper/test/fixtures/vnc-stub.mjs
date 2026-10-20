#!/usr/bin/env node
// Stands in for x11vnc in the tests (VAULT_VNC_CMD): records its arguments and
// the password file as it found it, listens on the -rfbport on 127.0.0.1, and
// exits on SIGTERM like x11vnc does.
import fs from 'node:fs';
import net from 'node:net';

const args = process.argv.slice(2);
const arg = (name) => args[args.indexOf(name) + 1];
const pwFile = arg('-rfbauth');
fs.appendFileSync(process.env.VNC_STUB_LOG, `${JSON.stringify({
  args,
  pid: process.pid,
  pwMode: fs.statSync(pwFile).mode & 0o777,
  pwHex: fs.readFileSync(pwFile).toString('hex'),
})}\n`);
const server = net.createServer((s) => s.destroy());
server.listen(Number(arg('-rfbport')), process.env.VNC_STUB_HOST ?? '127.0.0.1'); // VNC_STUB_HOST=0.0.0.0 plays a server that ignores -localhost
process.on('SIGTERM', () => process.exit(0));
