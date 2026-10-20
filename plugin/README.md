# Paperclip plugin: Vault

The Paperclip side of paperclip-vault. It gives agents four tools, asks a language model whether each request is justified, hands the
verdict to `vaultd` (which holds the ceilings, the leases and the audit log) and places the resulting session or token file in the
agent's workspace. What the package is for, how to install and configure it, and its limits are in the [root README](../README.md); the
design is in [docs/DESIGN.md](../docs/DESIGN.md) (sections 2, 3 and 7) and [docs/judge-model-selection.md](../docs/judge-model-selection.md).
The protocol to `vaultd` is implemented in `src/client.js` (signed line-JSON over `/run/vault/plugin.sock`, Ed25519).

## Install

From the release tarball (`paperclip-vault-plugin-<version>.tgz`, which extracts to `plugin/` with its dependencies and the release pins), by absolute path:

```
paperclipai plugin install "$PWD/plugin"
```

then set the plugin's settings and follow the Install tab; the numbered steps are in the root README. A checkout of this repository works as a
plugin folder after `npm ci` in `plugin/`, but its Install tab shows no install command: `src/release-pins.json` is filled in by
`scripts/release.sh` only.

## Code map

* **Tools** (`src/tools.js`): `vault_request_login`, `vault_request_credential`, `vault_request_status`, `vault_list_sites`. Results carry fixed messages
  (`src/messages.js`), the relative path of the file and its expiry, never contents.
* **Verdict** (`src/verdict/`): `provider.js` is the interface, `openai-compat.js` the implementation (OpenRouter, Ollama, any OpenAI-compatible
  endpoint; the API key is a Paperclip company secret), `aggregate.js` the aggregation rule shared with `vaultd`. `src/judge.js` produces and posts verdicts and runs the judge tests.
  Paperclip has no plugin API for its own AI connections, so this provider is the only model path.
* **Delivery** (`src/delivery.js`, `src/workspace.js`): workspace resolution, containment in `workspaceRoots`, `.vault/`, 0600 atomic writes, zero-overwrite removal.
* **Enrolment and commands** (`src/enrol.js`, `src/keys.js`): the signing key, the one-time code (60 minutes, single use), the install, uninstall, add-site and remove-site command lines.
* **Guards**: the run guard (`src/tools.js`), the admin matrix (`src/assert-admin.js`) and the exposure check (`src/exposure.js`: the plugin makes no signed call if its key
  directory or the `vaultd` socket lies inside a workspace root, the agent home root, the instance root or an extra sandbox path).
* **Actions** (`src/actions.js`): reads need a signed-in user, writes need a user listed in `adminUserIds`.
* **Vault page** (`src/ui.js`, route `vault`, one tab each; plain ESM, no build step, host components only). Every read and write is an action; the page shows
  read-only views (buttons disabled with the reason) to anyone who is not an admin.
  * *Install*: connection badge, the one-line install command with the installer fingerprint and expiry (60 minutes, single use), the uninstall command; it names the setting
    to fix when the plugin refuses to operate (for example `workspaceRoots` unset).
  * *Sites*: sites with their state, per-site one-liners (test, authorize, log in by hand, remove) and the Add-site form. The form only builds
    `sudo vault-site add --site-json-b64 ...`: it never asks for or sends a password, one-time-code seed or client secret (those are typed on the host's terminal),
    and the site file is built from schema fields only, so nothing else can be emitted.
  * *Ceilings*: read-only agent pins, roles to classes, never-list, maxima, locked agents, and the root command that edits the policy.
  * *Decision log*: time, agent, target, minutes, decision, model, provider, each sample's answer with its reason, hash; paged.
  * *Leases*: active leases with Revoke (asks first; removes the file at once).
  * *Gatekeeper*: provider status, model list, selected model, judge-test result and progress, Run judge tests; Select stays disabled until the model has a clean
    record for the current prompt, scenarios and `k`.

## Tests

From `plugin/` (after `npm ci`): `npm test` runs `node --test test/*.test.js test/*.test.mjs` with a mocked plugin context; `test/ui.test.mjs` renders the page against the real
actions with a small React stand-in, and the tests talk to `../tests/fakes/fake_vaultd.mjs` and share vectors with `vaultd` in `../tests/vectors/`.
`npm run validate-manifest` checks the manifest with Paperclip's own `pluginManifestV1Schema`. `node scripts/gen-vectors.mjs` regenerates the Ed25519 vectors.
From the repository root, `npm test` runs these together with the host tests.
