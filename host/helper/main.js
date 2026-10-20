// Entry point: node main.js --config /etc/vault/helper.json
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { loadConfig } from './config.js';
import { readStoreKey } from './creds.js';
import { createHelper, createLogger } from './helper.js';

const { values } = parseArgs({ options: { config: { type: 'string' } } });
if (!values.config) {
  process.stderr.write('usage: node main.js --config <helper.json>\n');
  process.exit(2);
}

const log = createLogger();
try {
  const config = loadConfig(values.config);
  const token = fs.readFileSync(config.tokenFile, 'utf8').trim();
  if (token.length < 32) throw new Error('helper token must be at least 32 characters');
  const adminToken = fs.readFileSync(config.adminTokenFile, 'utf8').trim();
  if (adminToken.length < 32) throw new Error('helper admin token must be at least 32 characters');
  const storeKey = await readStoreKey(config.credentialsDir, config.storeKeyCredential);
  const helper = createHelper({ config, token, adminToken, storeKey }, { log });
  await helper.start();
  void helper.deps.pool.works(); // logs which sandbox mode is active
  const shutdown = (signal) => {
    log('info', 'stopping', { signal });
    helper.stop().then(() => process.exit(0), () => process.exit(1));
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
} catch (err) {
  log('error', 'helper failed to start', { error: err.message });
  process.exit(1);
}
