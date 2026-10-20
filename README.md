# paperclip-vault

A credential vault for [Paperclip](https://github.com/paperclipai/paperclip) agents, installed as a Paperclip plugin plus a small
host service.

Agents never hold a standing secret or a password. When an agent needs to log in to a website or to call an API, it asks the vault
for a short lease. The vault checks hard limits that only the host owner can change, a decision model (the judge) decides each
request that passes those limits, and a login helper that runs outside every agent sandbox performs the login. The agent gets back a
file with a browser session or a short-lived access token that stops working when the lease ends; it never sees the password, the
one-time-code seed or a refresh token. Every decision is written to a hash-chained audit log.

No person decides individual requests: the ceilings are set once by the owner, and the judge decides inside them.

## What it protects

* Passwords, one-time-code seeds and OAuth refresh tokens stay with the login helper (its own system account, encrypted with
  `systemd-creds`). They are never written into an agent workspace, a run log or a Paperclip database.
* Leases are short. The requester states the minutes; a hard maximum per credential class and per site is checked in code, and a request above it is denied.
  At the end of a lease the helper logs out where the site supports it and the plugin removes the file.
* A request has to pass, in this order: the agent is pinned to a role by the owner, the role may use that kind of credential,
  the site lists that agent, the loop guards allow it, and only then does the judge see it. The judge can lower
  the duration or refuse; it cannot raise anything above the ceilings.
* Text written by agents (issue titles, the stated reason) reaches the judge only inside a length-capped, control-character-stripped section the prompt marks as untrusted.
* The audit log (`/var/log/vault/audit.jsonl`) is append-only and hash-chained; `vaultctl verify-audit` checks the chain offline.

## How it works

| Component | Runs as | Does |
|---|---|---|
| Plugin (`plugin/`) | the Paperclip service user, inside Paperclip | gives agents four tools, asks the judge, posts verdicts, writes the session file into the agent's workspace, shows the Vault page |
| `vaultd` (`host/vaultd/`) | system user `vault`, no network | ceilings, request ledger, leases, loop guards, prompt rendering, verdict checks, judge-test records, audit log |
| Login helper (`host/helper/`) | system user `vault-helper` | holds the site secrets, drives headless Chromium for logins, mints OAuth access tokens, keeps the sealed session store, logs out at lease end |
| `vault-site`, `vaultctl` | root (through `sudo`) | add and remove sites, OAuth authorization, interactive login, status, revoke, unlock |

```
agent -> plugin tool -> plugin.sock -> vaultd -> helper.sock -> helper (Chromium) -> website
         (Paperclip)    signed         ceilings   admin token    password, TOTP seed
                        messages       ledger     + socket mode  never leave the helper
                        judge     audit
                        model call
```

A request, step by step:

1. The agent calls `vault_request_login` (a site) or `vault_request_credential` (a named token) with a reason and a number of minutes.
   The plugin checks that the call comes from the agent's own running task, then sends a signed request to `vaultd`.
2. `vaultd` applies the ceilings. A failing ceiling is a final denial with a code.
3. `vaultd` renders the judge prompt itself and returns it with its hash. The plugin sends the prompt to the configured model `k` times
   (default 2) and posts the raw answers. `vaultd` recomputes the decision from the raw answers and refuses it unless the model has passed
   the judge tests for exactly this prompt. No answer in time is a denial.
4. If the decision is a grant, the helper logs in (or mints a token) and `vaultd` hands the result to the plugin once.
5. The plugin writes `.vault/<site>-<lease>.session.json` (or `.token.json`) with mode 0600 into the agent's workspace.
6. At lease end `vaultd` tells the helper to log out or revoke, and the plugin overwrites and removes the file.

The design is described in [docs/DESIGN.md](docs/DESIGN.md); the judge gate in [docs/judge-model-selection.md](docs/judge-model-selection.md).

### The judge is not "Paperclip's AI connections"

Paperclip has no plugin API that lets a plugin use the AI connections configured in Paperclip. The plugin therefore calls an
OpenAI-compatible chat-completions endpoint itself: either OpenRouter (or any hosted provider with that API), with the API key stored
as a Paperclip company secret and referenced from the plugin settings, or a local Ollama URL that needs no key. This key is
separate from any key your agents use.

## Requirements

* A Linux host with **systemd 254 or newer** (`systemd-creds`, `ImportCredential=`), running Paperclip **2026.1012.0 or newer**
  (the plugin manifest sets that minimum; it is the version this release was built and tested against).
  Paperclip's plugin runtime is alpha: expect to re-check this package after a Paperclip update.
* **Node.js 24 or newer** (Paperclip's own requirement) for the plugin. The helper needs a **root-owned** Node 24+ at `/usr/bin/node` or
  `/usr/local/bin/node`; if the host has none, the installer downloads the official Node tarball (SHA-256 pinned in the installer, needs `xz`) into `/opt/vault/node`.
  A Node under a user's home directory is never used for root-run code.
* **Python 3.11 or newer** at `/usr/bin/python3` (`vaultd` and the CLIs use the standard library only).
* **Debian or Ubuntu** (`apt-get`) for the automatic dependency install: `xvfb`, `x11vnc`, `acl` and the libraries Chromium needs.
  On other distributions run the installer with `--skip-deps` and install the packages yourself (it prints the list).
* `curl`, `sha256sum`, `tar`, `gzip`, and `setfacl` (package `acl`) on the host.
* Outbound HTTPS from the host to GitHub (release download), the Debian/Ubuntu mirrors and Playwright's Chromium download; from the Paperclip process to your judge provider.
* A Paperclip instance-admin login for the command line (`paperclipai`) and at least one company.

## Assumptions

* Paperclip runs as a **normal user without sudo** (never root). A **separate admin account with sudo** exists and is used only for the
  one-command root steps below. Nothing the Paperclip user can write is ever run as root.
* **Agents run in a sandbox** that limits their filesystem to their workspace (for example with the companion package
  [paperclip-security-hardening](https://github.com/tomRumi/paperclip-security-hardening)). The agent processes run as the same user as the Paperclip
  plugin; what keeps them away from the plugin's signing key and from `/run/vault/plugin.sock` is that the sandbox does not mount those paths.
  The plugin checks its settings for this (see `workspaceRoots`, `dataDir`, `socketPath` below) and refuses to work if its key directory or the socket lies inside a path that agents can see.
  Without any sandbox the vault still keeps passwords away from agents, but an agent could then call the plugin's socket itself and forge verdicts within the ceilings.
* The owner pins each agent's id to a role in `/etc/vault/policy.json`. The vault trusts only that pin, never a role reported by Paperclip or by the plugin.
* Paperclip is reachable only by people you trust (authenticated mode on a private network is recommended).

## Install

All steps in this section run as the account that runs Paperclip, except steps 6 and 8, which run as the admin account (the one with sudo).

1. **Sign the Paperclip command line in as an instance admin.** Installing a plugin is instance-admin only.
   ```
   paperclipai auth login --instance-admin
   ```
   It prints a confirmation URL; open it while signed in to Paperclip as an instance admin. Add `--no-browser` on a server without a browser.
   `paperclipai auth whoami` then shows your user id, which step 4 needs.

2. **Download and verify the plugin** from the release page, and unpack it in a folder you will keep (Paperclip loads the plugin from there):
   ```
   v=0.1.1
   base=https://github.com/tomRumi/paperclip-vault/releases/download/v$v
   mkdir -p ~/paperclip-vault && cd ~/paperclip-vault
   curl -fsSL -O "$base/paperclip-vault-plugin-$v.tgz" -O "$base/SHA256SUMS"
   sha256sum -c --ignore-missing SHA256SUMS
   tar -xzf "paperclip-vault-plugin-$v.tgz"
   ```
   The package is not published to npm. The tarball already contains the plugin's two `@paperclipai` dependencies and the release pins
   (download URL and installer fingerprint) that the Install tab uses.

3. **Install it into Paperclip** from the local folder (`-l` marks the argument as a local path; Paperclip rejects git and tarball specs):
   ```
   paperclipai plugin install -l "$PWD/plugin"
   paperclipai plugin list
   ```
   `paperclipai plugin list` should show `paperclip-vault` as `ready`; if it says `disabled` or `error`, run `paperclipai plugin enable paperclip-vault`.
   The install command ends with a hint to keep `pnpm dev` running. That hint is printed for every local plugin; ignore it, this plugin has no build step.

4. **Set the plugin's settings for each company that will use the vault.** Settings are stored per company, and only instance admins can save them.
   At minimum set `adminUserIds` (who may change things; everyone else gets read-only views) and `workspaceRoots` (the absolute folders that hold your agents' workspaces, with none set nothing is ever delivered and the Install tab refuses to create a command). By default Paperclip keeps agent workspaces in `<instance root>/workspaces/<agent id>`, where the instance root is `~/.paperclip/instances/default` of the Paperclip user (use the absolute path; it differs if `PAPERCLIP_HOME` or `PAPERCLIP_INSTANCE_ID` is set), so the usual value is `/home/<paperclip user>/.paperclip/instances/default/workspaces`:
   ```
   paperclipai company list
   paperclipai plugin config:set paperclip-vault --company-id <company id> \
     --payload-json '{"configJson":{"adminUserIds":["<your user id>"],"workspaceRoots":["/home/<paperclip user>/.paperclip/instances/default/workspaces"]}}'
   ```
   `config:set` replaces all settings of that company, so put everything you already know into the first call; afterwards use the plugin's settings form in Paperclip's plugin manager.
   All settings:

   | Setting | Meaning |
   |---|---|
   | `adminUserIds` | Paperclip user ids that may create install commands, select the judge, run judge tests and revoke leases. |
   | `workspaceRoots` | Session and token files are written only into the run's issue execution workspace or into `<agentHomeRoot>/<agentId>`, and only when that folder's real path lies under one of these folders. Use the same list as your sandbox's workspace roots. |
   | `agentHomeRoot` | Workspace `<root>/<agentId>` used when the run's issue has no execution workspace (Paperclip's default: the `workspaces` folder above). Must lie under a workspace root. There is no other fallback: the project's shared workspace is never used. |
   | `instanceRoot` | Optional: the Paperclip instance folder. The plugin refuses to work if its key directory or the socket lies inside it. |
   | `sandboxExtraPaths` | Optional: further paths the agent sandboxes mount. Same refusal rule. |
   | `dataDir` | Where the plugin keeps its signing key (`plugin-key.pem`, mode 0600). Default `~/.local/share/paperclip-vault` of the Paperclip user. Must be outside everything above. |
   | `socketPath` | Default `/run/vault/plugin.sock`. |
   | `toolWaitMs` | How long a tool call waits for the verdict before answering "pending" (default 7000, keep it under the tool gateway's 10 s). |
   | `judge` | Provider URL, API key (secret), temperature, `k` (samples per request, 2 to 9, default 2) and per-call timeout. See "Configure the judge". |

5. **Open the Vault page** in Paperclip (the "Vault" entry; route `vault`), tab **Install**, and press **Create install command**.
   It shows one line, valid for 60 minutes and for a single use. The line downloads `install-vault.sh` from this release, checks its SHA-256 fingerprint, and runs it with `sudo`.
   It has this shape (the plugin fills in the fingerprint, the service user, your company id and a one-time code):
   ```
   d=$(mktemp -d) && curl -fsSL <release url>/install-vault.sh -o "$d/install-vault.sh" && echo "<sha256>  $d/install-vault.sh" | sha256sum -c - && sudo bash "$d/install-vault.sh" --service-user <paperclip user> --company <company id> --enrol <one-time code>
   ```
   If the page shows no command, the plugin was not built by `scripts/release.sh` (a development checkout has no release pins) or the settings check in step 4 is failing; the page names the reason.

6. **Run that line as the admin account** (the one with sudo), on the same host. The one-time enrolment code is part of that command line, so it appears in shell history and in the process list; it is stored only as a hash, can be used once, only by the Paperclip service user's uid, and expires after 60 minutes. The installer:
   * downloads the host bundle and checks it against the SHA-256 pinned in the installer; it refuses links and special files in the bundle;
   * creates the system accounts `vault` and `vault-helper` (no login shell, no sudo) and records everything it creates in `/etc/vault/installed-by`;
   * installs the code root-owned under `/opt/vault`, the wrappers `/usr/local/sbin/vault-site` and `/usr/local/sbin/vaultctl`, and the systemd units;
   * installs `xvfb`, `x11vnc`, `acl` and the Chromium libraries with apt, then Chromium itself as `vault-helper`;
   * probes whether Chromium's own sandbox works under the helper's unit and records the result (see "Known limits");
   * writes `/etc/vault/config.json`, `helper.json`, the tokens, a starter `policy.json` (never overwritten on a re-run) and the audit log (append-only);
   * as the last step stores only the **hash** of the one-time code, starts everything and prints the bundle fingerprint and an install id.

   Compare the printed fingerprint with the one in the release notes. Options: `--node PATH` (a root-owned Node 24+), `--skip-deps` (no apt), `--base-url URL` (https only). Running the line again is safe: it updates code and units and keeps keys, policy, sites, credentials and the audit log.

7. **Let the plugin finish the enrolment.** Within a minute the plugin sends its public key, proves it holds the private key, and presents the one-time code;
   `vaultd` stores the key and the install id. The Install tab then shows "enrolled" with the vaultd version and helper state. The code is single use and expires after 60 minutes; if it expires, press **Create a new install command** and run the new line.

8. **Pin your agents to roles and allow your company.** The starter `/etc/vault/policy.json` contains placeholder agent ids. As the admin account:
   ```
   sudoedit /etc/vault/policy.json && sudo systemctl restart vaultd
   ```
   Replace the placeholder ids in `agents` with your agents' UUIDs and the role names you use (the role is shown to the judge as written, so prefer the names in the example: Engineer, QA, UI Tester, Architect, Designer, Researcher, Data Scientist, Business Analyst, Coordinator, Triage Clerk, Security). The Ceilings tab shows the result read-only.
   If you installed without `--company`, add the company: `sudo vaultctl company add <company id>`.

## Configure

### The judge

1. Create the provider key as a **company secret** in Paperclip, for example (reads the value from an environment variable so it does not appear in the process list; Paperclip's web UI works too):
   ```
   read -rs JUDGE_KEY && export JUDGE_KEY
   paperclipai secrets create --company-id <company id> --name vault-judge-key --value-env JUDGE_KEY
   ```
   Skip this for a local Ollama.
2. In the plugin's settings form (company selected), fill in `judge`: **Base URL** (`https://openrouter.ai/api/v1`, or `http://127.0.0.1:11434/v1` for Ollama on the Paperclip host) and **API key** (pick the secret). Leave `k` at 2 or raise it (every one of the `k` answers must allow a request for it to be granted; changing `k` needs new judge tests).
3. Vault page, tab **Judge**: **Load model list from provider**, pick a model, **Run judge tests**. The plugin sends the 140 scenarios (those that reach the judge; the others are stopped by the ceilings before it) to the model, three repeats, `k` answers each, which is several hundred model calls. A model passes only if it granted no injection attempt, made no grant outside the accepted answers, answered stably (mean majority-agreement of the repeats, at least 0.95) and produced at most 1 % unusable answers. `vaultd` re-checks these numbers itself.
4. When the result is "passed", press **Select**. Until a model is selected and has a clean result for the current prompt, scenarios and `k`, every request is denied.

The record is bound to the hash of the prompt and of the scenario file: any change to either voids all results, and you run the tests again. Details: [docs/judge-model-selection.md](docs/judge-model-selection.md).

### Ceilings (root only)

`/etc/vault/policy.json` is edited by root and read when `vaultd` starts (`sudoedit /etc/vault/policy.json && sudo systemctl restart vaultd`). Reference: `host/policy.example.json`.

* `agents`: agent UUID to role. An agent that is not listed is denied (`agent_unpinned`).
* `roles`: role to the credential classes it may request.
* `classes`: per class, a `match` glob (or list), `max_minutes` (default 60, never above 480), `scopes`, and `narrow_minutes` (the cap when the judge chooses "narrow").
  Credentials named `web-<site>` fall under `web-login` and `oauth-<site>` under `oauth-token`.
* `never`: extra name patterns that can never be granted. Names starting with `vault` never are.
* Per site, `allowedAgents` is the hard list of agents that may use it and `maxMinutes` can only lower the class maximum.

Other host settings are in `/etc/vault/config.json` (see `host/config.example.json`). `sudo vaultctl unlock <agent id>` lifts a lock that the judge set.

### Add a site

Open the Vault page, tab **Sites**, fill in the **Add site** form and copy the command it builds. The form never asks for a password or a seed; the command asks for them on the terminal. Run it as the admin account:

```
sudo vault-site add --site-json-b64 <long base64 string from the form>
```

`vault-site add` shows a summary of the site, asks for the username, the password (twice) and the TOTP seed (the "setup key" the site shows next to its QR code) on the terminal, encrypts each one with `systemd-creds` straight from standard input (never on a command line or in a temporary file), writes `/etc/vault/sites/<id>.json`, restarts the helper and runs one test login. Use `--no-totp` for a site without a one-time code and `--no-test` to skip the test. The form lists only agents that are pinned in the policy (step 8) and writes the ones you tick into `allowedAgents`; with an empty list nobody can use the site.

Three kinds of site:

* **Website login** (`password-totp`): username, password and optional TOTP. The site file holds a short recipe of `fill`, `click`, `press` and `waitFor` steps, a success check, and an optional logout. If the site asks for an e-mail or SMS code once to trust the device, run `sudo vault-site test <id> --attended`; the code is typed on the terminal and the helper keeps the device-trust cookie to itself.
* **OAuth access token** (`oauth`): no password. Run `sudo vault-site authorize <id>` once. The device flow prints a code and an address to confirm on any device. The redirect flow (`sudo vault-site authorize <id> --redirect PORT`) makes the helper listen on `127.0.0.1:PORT` for ten minutes and prints the `ssh -L` command to run on your laptop, then a link to open there. The helper keeps the refresh token and mints a short-lived access token for each granted request.
* **Website that blocks automation** (`interactive`, for example a "Sign in with Google" page): run `sudo vault-site interactive <id>`. The helper starts a virtual display, a headed Chromium and a VNC server bound to `127.0.0.1`; the command prints a one-time VNC password and the `ssh -L` line to run on your laptop. Connect a VNC viewer to `localhost:5900`, log in completely (second factor included), return to the terminal and press Enter. The helper stores the logged-in session, sealed. Alternative: `sudo vault-site import-session <id> --file state.json` with a Playwright storage state exported from another browser. See the limit about logout below.

Other commands: `sudo vault-site list`, `sudo vault-site remove <id>` (revokes active leases, deletes the credentials and the helper's stored state; `--keep-creds` keeps the credential blobs).

Static tokens (a GitHub token, an API key) can also be held by `vaultd` itself. Name the credential so that a class in the policy matches it (for example `github-ro-myrepo` matches `github-ro-*`): `systemd-ask-password -n "value:" | sudo systemd-creds encrypt --name=vault.<credential> - /etc/credstore.encrypted/vault.<credential>` and `sudo systemctl restart vaultd`. They are handed out as a `.token.json` file and cannot be revoked at the provider by the vault, so keep them narrow.

## How agents use it

Agents need no vault command in their sandbox and no special instructions; the plugin gives them four tools:

| Tool | Use |
|---|---|
| `vault_list_sites` | List the sites and items this agent may ask for: id, purpose, kind, longest lease. |
| `vault_request_login` | `site`, `reason` (10 to 500 characters), `minutes`. Asks for a browser login to a site. |
| `vault_request_credential` | `credential`, `reason`, `minutes`. Asks for a short-lived access token (an OAuth site is `oauth-<site>`, a static token is its name). |
| `vault_request_status` | `requestId`. Returns `pending`, `preparing`, `ready`, `denied`, `expired`, `ended` or `failed`, with a fixed message. |

The request tools wait a few seconds for the verdict and otherwise answer `pending`; the agent then polls `vault_request_status`. A request must come from the agent's own running task, with the issue in progress and assigned to that agent, and must state the minutes. A request above the maximum is denied and the answer carries `maxMinutes` so the agent can ask again.

When a request is ready, the answer contains a relative path and the expiry time, never the contents:

* a login: `.vault/<site>-<lease>.session.json`, a Playwright storage state (`browser.newContext({ storageState: path })`);
* a token: `.vault/<credential>-<lease>.token.json` with `accessToken`, `tokenType`, `expiresAt` and `scopes`.

The folder `.vault/` inside the workspace has mode 0700 and a `.gitignore` containing `*`. Files are mode 0600 and are removed when the lease ends or is revoked. The agent should use the file only for the task it named.

## Verify

* Vault page, tab Install: "enrolled", vaultd version, helper "up".
* On the host: `sudo systemctl status vaultd.socket vaultd vault-helper` and `sudo vaultctl status` (version, install id, helper state, open leases, locked agents, allowed companies).
* `sudo vault-site list` shows the sites and whether their credentials are in place; `sudo vault-site test <id>` logs in once and logs out again.
* End to end: give a pinned agent an issue, let it call `vault_list_sites` and request a login for a test site. The Decision log tab shows the verdict with each model answer; the Leases tab shows the active lease (with Revoke); the session file appears in the agent's workspace under `.vault/` and disappears at the end.
* Audit chain: `sudo vaultctl verify-audit /var/log/vault/audit.jsonl` (list rotated files first, oldest to newest, `.gz` works; `--allow-partial` once retention has removed the first file).

## Update

Unpack the new plugin release over the old folder as in step 2 and install the same path again (step 3); if Paperclip reports the plugin as already installed, run `paperclipai plugin upgrade paperclip-vault` instead. Then press **Create a new install command** on the Install tab and run the line again. The installer keeps the policy, sites, credentials and audit log. Changing the judge prompt or the scenario file voids all judge-test results; run the tests again.

## Uninstall

On the host, as the admin account. The Install tab has a section **Uninstall from the host** (tick the box for `--purge`, then **Show uninstall command**) that shows the same download-verify-run line as the install. By hand, from the release page:

```
v=0.1.1; base=https://github.com/tomRumi/paperclip-vault/releases/download/v$v
d=$(mktemp -d) && cd "$d" && curl -fsSL -O "$base/install-vault.sh" -O "$base/SHA256SUMS" && sha256sum -c --ignore-missing SHA256SUMS
sudo bash install-vault.sh --uninstall           # stops and removes the units, /opt/vault and the wrappers
sudo bash install-vault.sh --uninstall --purge   # the same, and deletes what the installer created
```

`--uninstall` keeps `/etc/vault`, the credential blobs, `/var/lib/vault`, `/var/lib/vault-helper`, the audit log and the two accounts, so a later install resumes where this one stopped. `--purge` removes what `/etc/vault/installed-by` lists as created by the installer, including the site credentials added with `vault-site`, the accounts and the audit log (it lifts the append-only flag first). Anything that existed before the install (your own `vault.<name>` credentials, an existing `/etc/vault`) stays and the output says so.

Then, as the Paperclip user, remove the plugin: `paperclipai plugin uninstall paperclip-vault` (add `--force` to purge its state). Delete `~/.local/share/paperclip-vault` (the plugin key) and the company secret you created for the judge.

## Known limits

* **Verdicts are produced inside Paperclip's account.** The plugin calls the model and signs the verdict with a key that the Paperclip user can read. Someone who controls that account (for example with the Paperclip admin key) could forge verdicts, but only inside the ceilings: for pinned agents, allowed sites, classes and maximum minutes. They still cannot read the stored passwords. `vaultd` recomputes every decision from the raw answers and refuses unvetted models, which stops accidents and a misbehaving provider, not an attacker holding the plugin key.
* **A granted token is visible to the agent.** An agent that is granted a narrow token (a GitHub token, an access token) sees and can misuse it until the lease ends. Keep classes narrow and `max_minutes` short; the vault limits and logs use, it does not police it.
* **An issue's execution workspace is shared on that issue.** A session or token is written into the workspace of the issue the agent works on, or into the agent's own folder when the issue has none. If several agents work on one issue and share its execution workspace, each of them can read what is delivered there. Give such issues one agent at a time, or no execution workspace, if that matters. The project's shared workspace is never used.
* **Plugin key.** The plugin's signing key is a file readable by the Paperclip service user (mode 0600). Agents are kept away from it by their sandbox, not by file permissions.
* **Interactive sites without a logout step.** For a site of type `interactive` the agent receives a copy of your logged-in session. If the site has no logout step in its recipe, the copy stays valid at the site after the lease ends; revoking deletes the file, not the copy. `vault-site interactive` explains this and asks for an explicit `y` (it records `acceptNoLogout` in the site file); without that, the site is not usable. Prefer sites with a logout step or a dedicated account.
* **Chromium `--no-sandbox` fallback.** The installer tests whether Chromium's own sandbox starts under the helper's unit. On hosts where the kernel blocks unprivileged user namespaces (common on recent Ubuntu), it sets `allowNoSandbox: true` and Chromium runs without its sandbox; the installer prints which mode is active. Isolation then rests on the `vault-helper` account, the hardened unit, and a proxy that lets the browser reach only the hosts listed in the site file.
* **The interactive login profile** (`/var/lib/vault-helper/profiles/<id>`) is Chromium's own cookie store and is not sealed by the helper's key; it is readable only by `vault-helper` and root.
* **Debian and Ubuntu only** for the automatic dependency install. Elsewhere use `--skip-deps` and install the packages yourself.
* **The judge is a model.** A model that passed the tests can still be wrong on inputs the scenarios do not cover, and a provider can change a model behind the same name. The ceilings bound the damage; read the Decision log and re-run the tests now and then.
* **Plugin runtime is alpha** in Paperclip. The plugin UI is plain ES modules against the SDK UI components and is tested with a stand-in for them, not in every Paperclip release.
* Linux only. One `vaultd` per host, one Paperclip instance per vault.

## Tests

```
npm test
```

runs `scripts/test-all.sh` from the repository root and needs no root. Its stages: the `vaultd` unit tests (Python), the judge-scenario checks (`score.py --dry-run` and `--oracle`), the plugin tests with a fake `vaultd`, the helper tests against a fake login site and a fake OAuth provider, the installer tests (they build a release and install it into a scratch directory with `--prefix`), an end-to-end run of the real `vaultd`, helper and plugin logic, and a scan of the repository for secrets and host-specific data. It prints PASS, FAIL or SKIP per stage and a summary, and exits non-zero on any failure.

Requirements: Python 3.11+, Node 24+ and npm. The dependencies of `plugin/` and `host/helper/` are installed from their lock files when `node_modules` is missing. The helper and end-to-end tests drive a real headless Chromium; install the revision `playwright-core` wants once with `cd host/helper && npx playwright-core install chromium` (on a bare host also `npx playwright-core install-deps chromium` as root), or run `SKIP_BROWSER=1 npm test`, which skips the browser suites and says so. The installer tests run `npm ci` twice while building a release, so a full run takes several minutes.

Build a release yourself (writes `dist/`, publishes nothing): `scripts/release.sh --version 0.1.1`; for a local test add `--base-url file:///absolute/dist/` and run the installer with `--prefix DIR` (see `tests/install/test_install.py`).

## Repository layout

* `plugin/`: the Paperclip plugin (see [plugin/README.md](plugin/README.md)).
* `host/`: `vaultd`, the login helper, CLIs, systemd units, judge scenarios ([host/README.md](host/README.md), [host/INSTALL.md](host/INSTALL.md), [host/judge-tests/README.md](host/judge-tests/README.md)).
* `scripts/release.sh`: builds the release assets. `tests/`: fakes and installer tests. `docs/`: design and judge selection.

## Licence

MIT, copyright 2026 tomRumi. See [LICENSE](LICENSE).
