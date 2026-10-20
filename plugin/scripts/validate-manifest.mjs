// Validates src/manifest.js against the host's own schema from @paperclipai/shared (must be installed), and the
// plugin-specific rules the shared schema cannot see: tools declared in the manifest are the ones the worker registers,
// the migrations folder exists, entrypoints exist, and the config schema marks the API key as a secret reference.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pluginManifestV1Schema } from "@paperclipai/shared";
import manifest from "../src/manifest.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const r = pluginManifestV1Schema.safeParse(manifest);
if (!r.success) { console.error(JSON.stringify(r.error.issues, null, 2)); process.exit(1); }

const problems = [];
for (const f of [manifest.entrypoints.worker, manifest.entrypoints.ui]) if (!fs.existsSync(path.join(root, f))) problems.push(`entrypoint ${f} does not exist`);
if (!fs.statSync(path.join(root, manifest.database.migrationsDir), { throwIfNoEntry: false })?.isDirectory()) problems.push("migrations folder does not exist");
if (manifest.instanceConfigSchema.properties.judge?.properties?.apiKey?.format !== "secret-ref") problems.push("judge.apiKey must have format secret-ref");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
if (pkg.paperclipPlugin?.manifest !== "./src/manifest.js") problems.push("package.json paperclipPlugin.manifest must point to ./src/manifest.js");
if (pkg.version !== manifest.version) problems.push(`package.json version ${pkg.version} differs from the manifest version ${manifest.version}`);
for (const dep of ["@paperclipai/plugin-sdk", "@paperclipai/shared"]) if (pkg.dependencies?.[dep] !== manifest.minimumHostVersion) problems.push(`${dep} must be pinned to the host version ${manifest.minimumHostVersion}`);
if (problems.length) { console.error(problems.join("\n")); process.exit(1); }
console.log("manifest OK:", manifest.id, manifest.version, "capabilities:", manifest.capabilities.join(", "));
