import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { pluginManifestV1Schema } from "@paperclipai/shared";
import manifest, { PLUGIN_ID } from "../src/manifest.js";
import { READ_ACTIONS, WRITE_ACTIONS } from "../src/actions.js";
import { makeWorld } from "./helpers/world.mjs";

const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("the manifest satisfies the host's own schema", () => {
  const r = pluginManifestV1Schema.safeParse(manifest);
  assert.ok(r.success, r.success ? "" : JSON.stringify(r.error.issues));
  assert.equal(manifest.id, "paperclip-vault");
  assert.equal(PLUGIN_ID, manifest.id);
});

test("validate-manifest.mjs passes", () => {
  const out = execFileSync(process.execPath, [new URL("../scripts/validate-manifest.mjs", import.meta.url).pathname], { encoding: "utf8" });
  assert.match(out, /manifest OK: paperclip-vault 0.1.0/);
});

test("package.json: SDK and shared pinned to the host version, paperclipPlugin key, scripts", () => {
  assert.equal(pkg.dependencies["@paperclipai/plugin-sdk"], "2026.1012.0");
  assert.equal(pkg.dependencies["@paperclipai/shared"], "2026.1012.0");
  assert.equal(manifest.minimumHostVersion, "2026.1012.0");
  assert.deepEqual(pkg.paperclipPlugin, { manifest: "./src/manifest.js", worker: "./src/worker.js", ui: "./src/ui.js" });
  assert.equal(pkg.type, "module");
  assert.ok(pkg.scripts.test.includes("node --test"));
  assert.ok(pkg.scripts["validate-manifest"]);
  assert.equal(pkg.version, manifest.version);
});

test("capabilities: exactly the documented set (plus the migrate capability the host requires), nothing risky", () => {
  const expected = ["agent.tools.register", "ui.page.register", "plugin.state.read", "plugin.state.write", "jobs.schedule", "activity.log.write", "database.namespace.read",
    "database.namespace.migrate", "issues.read", "projects.read", "execution.workspaces.read", "http.outbound", "secrets.read-ref"];
  assert.deepEqual([...manifest.capabilities].sort(), expected.sort());
  assert.equal(manifest.webhooks, undefined);
  assert.equal(manifest.localFolders, undefined);
  assert.equal(manifest.agents, undefined);
  assert.deepEqual(manifest.database.coreReadTables, ["heartbeat_runs"]);
  assert.ok(fs.existsSync(new URL("../src/migrations/", import.meta.url)));
  assert.deepEqual(fs.readdirSync(new URL("../src/migrations/", import.meta.url)).filter((f) => f.endsWith(".sql")), []);
});

test("jobs, tools and the config schema", () => {
  assert.deepEqual(manifest.jobs.map((j) => j.jobKey).sort(), ["enrol-tick", "lease-sweep"]);
  assert.ok(manifest.jobs.every((j) => j.schedule === "* * * * *"));
  const props = manifest.instanceConfigSchema.properties;
  assert.deepEqual(Object.keys(props).sort(), ["adminUserIds", "agentHomeRoot", "dataDir", "gatekeeper", "instanceRoot", "sandboxExtraPaths", "socketPath", "toolWaitMs", "workspaceRoots"]);
  assert.equal(manifest.instanceConfigSchema.additionalProperties, false);
  assert.equal(props.gatekeeper.properties.apiKey.format, "secret-ref");
  assert.deepEqual(Object.keys(props.gatekeeper.properties).sort(), ["apiKey", "baseUrl", "k", "perCallTimeoutMs", "temperature"]);
  assert.equal(props.gatekeeper.properties.k.minimum, 2);
  assert.equal(props.gatekeeper.properties.k.default, 2);
  assert.equal(props.toolWaitMs.default, 7000);
  for (const t of manifest.tools) {
    assert.equal(t.parametersSchema.type, "object");
    assert.equal(t.parametersSchema.additionalProperties, false);
  }
});

test("the worker registers exactly what the manifest declares, and the UI file parses", async () => {
  const w = await makeWorld();
  try {
    assert.deepEqual(Object.keys(w.c.tools).sort(), manifest.tools.map((t) => t.name).sort());
    assert.deepEqual(Object.keys(w.c.jobs).sort(), manifest.jobs.map((j) => j.jobKey).sort());
    assert.deepEqual(Object.keys(w.c.actions).sort(), [...READ_ACTIONS, ...WRITE_ACTIONS].sort());
    for (const t of manifest.tools) {
      assert.equal(w.c.tools[t.name].decl.displayName, t.displayName);
      assert.deepEqual(w.c.tools[t.name].decl.parametersSchema, t.parametersSchema);
    }
  } finally { await w.cleanup(); }
  execFileSync(process.execPath, ["--check", new URL("../src/ui.js", import.meta.url).pathname]);
  assert.ok(manifest.ui.slots.some((s) => s.exportName === "VaultPage" && s.routePath === "vault"));
  assert.match(fs.readFileSync(new URL("../src/ui.js", import.meta.url), "utf8"), /export function VaultPage/);
});

test("the shipped release pins are all null in a development checkout", () => {
  const pins = JSON.parse(fs.readFileSync(new URL("../src/release-pins.json", import.meta.url), "utf8"));
  assert.deepEqual([pins.version, pins.baseUrl, pins.installVaultSha256], [null, null, null]);
});
