// Chromium sandbox probe, run once by install-vault.sh inside a copy of the vault-helper unit (same account, same hardening),
// so the answer is the one the helper itself will get. Usage: node probe-chromium.mjs <playwright-core directory>
// Exit status: 0 = Chromium starts with its sandbox, 3 = only without the sandbox, 4 = does not start at all.
// Prints one line to stdout ("sandbox: on|off|unavailable") and, on failure, the first error line to stderr.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const dir = process.argv[2];
if (!dir) {
  process.stderr.write('usage: node probe-chromium.mjs <playwright-core directory>\n');
  process.exit(2);
}
const { chromium } = await import(pathToFileURL(path.join(dir, 'index.mjs')).href);

async function launches(chromiumSandbox) {
  let browser;
  try {
    browser = await chromium.launch({ headless: true, chromiumSandbox, timeout: 45_000 });
    const page = await browser.newPage();
    await page.goto('about:blank');
    return null;
  } catch (err) {
    return String(err?.message ?? err).split('\n')[0];
  } finally {
    await browser?.close().catch(() => {});
  }
}

const withSandbox = await launches(true);
if (withSandbox === null) {
  process.stdout.write('sandbox: on\n');
  process.exit(0);
}
const without = await launches(false);
if (without === null) {
  process.stdout.write('sandbox: off\n');
  process.stderr.write(`with the sandbox: ${withSandbox}\n`);
  process.exit(3);
}
process.stdout.write('sandbox: unavailable\n');
process.stderr.write(`with the sandbox: ${withSandbox}\nwithout it: ${without}\n`);
process.exit(4);
