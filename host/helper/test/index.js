// `node --test test/` entry point. Node 24 treats a directory argument as a
// module path (it no longer scans it), so this file loads every *.test.js in
// one process. `npm test` runs the files in parallel instead.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
for (const name of fs.readdirSync(here).filter((n) => n.endsWith('.test.js')).sort()) {
  await import(pathToFileURL(path.join(here, name)).href);
}
