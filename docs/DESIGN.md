# paperclip-vault: design

How the vault is built (version 0.1.0). The README says how to install and use it; this file says what each part does and why it is built that way. Where this text and the code disagree, the code is right.

## 1. Parts, accounts, files

```
agent -> plugin tool -> plugin.sock -> vaultd -> helper.sock -> helper (Chromium, sealed store) -> site
```

| Part | Runtime | Account | Does |
|---|---|---|---|
| `vaultd` | `/usr/bin/python3` 3.11+, standard library only | `vault` (system, no login) | ceilings, request ledger (sqlite), leases, loop guards, prompt rendering, verdict checks, judge-test records, audit log |
| helper | root-owned Node 24+ with vendored `playwright-core` | `vault-helper` (system, no login) | logins, logout, OAuth, interactive login, sealed store of mutable secrets |
| CLIs `vault-site`, `vaultctl` | Python | root (through `sudo`) | owner commands |
| plugin | Paperclip plugin worker | the Paperclip service user | four agent tools, the Vault page, the gatekeeper model call, delivery of the session file |

`vaultd` has no network (`PrivateNetwork=yes`, `AF_UNIX` only), calls no model and holds no model key. It never calls the plugin or Paperclip: the plugin always initiates. The plugin has no root and no access to the site secrets.

Paths (all under a fake root when the installer runs with `--prefix`):

```
/opt/vault/                    root:root 0755, code only (vaultd, helper, bin, sbin, units, judge-tests, VERSION; node/ if vendored)
/usr/local/sbin/               vault-site, vaultctl: wrappers around the root-owned copies in /opt/vault
/etc/vault/                    root:vault 0750
  config.json, policy.json     vaultd configuration and ceilings (0640 root:vault)
  helper.json                  helper configuration (0640 root:vault)
  sites/<id>.json              site files, no secrets (0640 root:vault)
  helper.token                 shared by vaultd and the helper (0640 root:vault)
  helper-admin.token           root CLI only (0600 root:root); handed to the helper unit as a credential
  enrol.json                   one-time enrolment record (hash of the code, expiry, service uid)
  installed-by                 what the installer created (0600 root)
/etc/credstore.encrypted/      systemd-creds blobs (0700 root)
  vault.<name>                 static tokens imported by vaultd only
  vault-helper.storekey        32 random bytes; seals the helper's store
  vault-helper.site.<id>.username | .password | .totp | .oauth-client-secret    imported by the helper only
/var/lib/vault/                vault 0700: vault.db (requests, leases, judge_records, nonces, locks, companies), plugin-key.json (enrolled public key)
/var/log/vault/audit.jsonl     vault 0600, append-only (chattr +a), hash-chained; rotated monthly by vault-audit-rotate.timer
/var/lib/vault-helper/         vault-helper 0700: store/{oauth,trust,session}/<id>.enc, leases/<lease>.enc (AES-256-GCM),
                               profiles/<id>/ (Chromium profile of interactive sites), browsers/ (Chromium)
/run/vault/plugin.sock         created by vaultd.socket: 0600 vault:vault plus an ACL entry for the service user
/run/vault/admin.sock          vault:vault 0600
/run/vault-helper/helper.sock  vault-helper:vault 0660
```

### Who may talk to what

* `plugin.sock`: systemd creates the socket (`vaultd.socket`, socket activation) and gives the Paperclip service user read and write through one POSIX ACL entry. There is no group to join, so no new login session and no Paperclip restart. `vaultd` additionally checks `SO_PEERCRED` (uid equals `plugin_uid` from `config.json`) and an Ed25519 signature on every message. The ACL decides who may connect; the signature and uid decide who is believed.
* `admin.sock`: peer uid 0 or `vault`.
* `helper.sock`: mode 0660 `vault-helper:vault` plus a bearer token on every request. Node has no `SO_PEERCRED`, so the token and the socket mode are the check. Two tokens: `helper.token` (vaultd) permits only the operations a lease needs (`ping`, `session.open`, `session.close`, `token.mint`, `token.revoke`); every other operation (site test, OAuth, interactive login, import, forget, reload) needs `helper-admin.token`, which only root can read. systemd hands the helper a copy as a credential, so the helper account compares tokens without being able to read the file.
* Same-user agents are kept away from the sockets and the plugin key by their sandbox (the sockets live under `/run`, the key under `dataDir`), not by file permissions. The plugin refuses to make a signed call if `dataDir` or the socket lies inside a workspace root, the agent home root, the instance root or an extra sandbox path.

### Secrets

Root encrypts, PID 1 decrypts. `vault-site add` pipes each secret on standard input (never argv, never a temporary file) into `systemd-creds encrypt --with-key=host --name=<name> - /etc/credstore.encrypted/<name>`. The units use `ImportCredential=`, so PID 1 decrypts into a tmpfs `$CREDENTIALS_DIRECTORY` visible only to that unit. `vaultd` imports `vault.*` and never a site password; the helper imports `vault-helper.*`. Credentials are fixed when a unit starts, so `vault-site add` and `remove` restart the helper; leases are sealed on disk and resume.

Secrets that change at run time (rotating OAuth refresh tokens, device-trust cookies, live sessions) are sealed by the helper itself with AES-256-GCM. The key is `vault-helper.storekey`; a subkey per record kind is derived with HKDF and the kind and id are authenticated data, so a sealed file cannot be moved to another name. Python's standard library has no AES, which is why the helper is Node.

No code from a user's home directory ever runs as root or as `vault*`: Node, Python, the helper and Chromium come from root-owned `/opt/vault` or system paths. The installer refuses a Node under a home directory.

### Units

* `vaultd.service`: `User=vault`, `ImportCredential=vault.*`, `python3 -s -m vaultd serve`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `MemoryDenyWriteExecute`, empty capability set, system-call filter, `ProtectSystem=strict`, `ReadWritePaths=/var/log/vault`.
* `vaultd.socket`: `plugin.sock` as above, `/run/vault` mode 0711 so the service user can reach it.
* `vault-helper.service`: `User=vault-helper`, `SupplementaryGroups=vault`, `ImportCredential=vault-helper.*`, `LoadCredential=helper-admin.token`, `IPAddressDeny=link-local` (cloud metadata endpoints), `RestrictNamespaces=user pid net` (Chromium's sandbox), no `MemoryDenyWriteExecute` (V8), `MemoryMax=1G`, `TasksMax=512`. Each relaxation against `vaultd.service` is commented in the unit.
* `vault-audit-rotate.service` and `.timer`: monthly rotation that keeps the chain.

## 2. The protocol between plugin and vaultd

One connection carries one request line and one response line (UTF-8 JSON, 256 KiB request, 2 MiB response), then closes. There is no unsigned call.

```
request  {"msg": base64url(JSON body), "sig": base64(Ed25519), "kid": key id}
body     {"v":1, "type", "installId", "ts", "nonce", "data"}
response {"ok":true, "nonce", "data"}  or  {"ok":false, "nonce", "error":{"code","message"}}
```

The signature covers `b"pcvault-v1\n"` followed by the decoded body bytes, so Node and Python need no common JSON canonicalisation. `kid` is the first 16 hex characters of the SHA-256 of the public key. Error codes: `bad_signature, bad_request, replay, clock_skew, unknown_type, not_enrolled, denied, not_found, conflict, busy, internal`.

`vaultd` checks in this order: peer uid, size, JSON, key id, signature, install id, timestamp within 120 s and not earlier than 10 s before the start of this `vaultd` run (a restart cannot replay old messages; the grace covers the message whose arrival socket-activates `vaultd`, which the plugin timestamped before the process existed; persisted nonces cover the rest), nonce unused in the last 10 minutes. Failures are audited (in full up to 20 a minute, then every 100th). Ed25519 verification is a vendored pure-Python RFC 8032 implementation, tested against signatures from Node and OpenSSL, so no subprocess runs inside the locked-down unit.

Types: `hello, enrol, sites.list, ceilings.get, request.create, verdict.submit, request.status, request.list, lease.fetch, lease.ack, lease.revoke, leases.list, log.read, judge.testset, judge.record`.

### Enrolment

`vaultd` cannot call the plugin, so the plugin proves itself to `vaultd`:

1. An admin presses "Create install command". The plugin creates an Ed25519 key pair if absent (`<dataDir>/plugin-key.pem`, mode 0600, in a 0700 directory) and a 16-character one-time code (about 78 bits, shown in groups of four). One code is active at a time, valid 60 minutes.
2. The command downloads `install-vault.sh`, checks its SHA-256 against the value baked into the plugin release, and runs it with `--service-user`, `--company` and `--enrol CODE`. The installer writes `/etc/vault/enrol.json` with only `sha256("pcvault-enrol:" + code)`, the install id, the expiry and the service uid, as the last step before the units start.
3. Every minute while a code is pending and the socket exists, the plugin sends `enrol` with the code and its public key, signed with the key being enrolled (proof of possession). `vaultd` compares the code hash in constant time, checks the expiry, and stores `{installId, kid, publicKey, serviceUid, codeHash}` in `/var/lib/vault/plugin-key.json`. `/etc` is read-only to `vaultd`, so single use is enforced by the stored hash of the consumed code, not by deleting `enrol.json`. The plugin then deletes the code from its state.
4. Running the installer with a new code replaces the trusted key (key rotation); without a code it keeps it.

### Agent identity

A tool call carries `{agentId, runId, companyId, projectId}` from Paperclip. Before any request the plugin reads Paperclip's `heartbeat_runs` table (core read) and requires a row with this run id, this agent and company, status `running`, then takes the issue id from the run's context snapshot and requires the issue to be `in_progress` and assigned to the agent. `vaultd` holds no Paperclip credential and cannot check this again; it checks that the agent is pinned in the policy (the role comes from the pin, never from the plugin), that the company is allowed, and the loop guards.

## 3. A request, end to end

States: `awaiting_verdict -> denied | issuing -> ready -> delivered -> ended`, side states `failed`, `expired`, `revoked`. Ids: `req_<16 hex>`, `lse_<16 hex>`.

1. **Create.** `request.create` carries the target (a site or a credential name), the reason, the minutes, the agent and `context` (issue title, project, stage; all untrusted). The first failing ceiling wins and is returned as `{state:"denied", code}`: `agent_unpinned, company_not_allowed, agent_locked, rate_limited, bad_target, never_list, role_class, site_agent_not_allowed, minutes_missing, minutes_over_max, site_not_ready`. `minutes` is required and has no default. The maximum is the smallest of the class `max_minutes` (60 when unset), the site's `maxMinutes` (60 when unset) and 480; a request above it is denied and the answer carries `maxMinutes`, never shortened silently.
   Loop guards: exponential backoff from 30 s to 1 h per (agent, target, issue) after a denial, 3 denials an hour per (agent, target), at most 3 open requests per agent, one request per (run, target) unless the previous was denied.
2. **Prompt.** `vaultd` stores the request and renders the gatekeeper prompt itself from `judge_prompt.md`. The agent's id, role, credential, the site's purpose, kind and roles (read from the site file, trusted), the scope, the duration and the agent's recent requests and denials come from `vaultd`'s own data; issue title, project, stage and reason come from the plugin and are capped and stripped of control characters. The answer contains the prompt, its template hash `promptSha256`, the ceiling (`maxMinutes`, `narrowMinutes`) and a deadline (`verdict_timeout_s`, default 180, at most 600). No verdict by then is `denied/no_verdict`.
3. **Verdict.** The plugin asks the selected model `k` times and posts `verdict.submit` with the raw answers, the aggregate, model, provider and both prompt hashes. `vaultd` accepts it only if: the request is still waiting; the prompt hash and the hash of the rendered prompt match its own; a clean judge-test record exists for exactly (model, provider, prompt hash, scenario hash); `k >= 2` and there are `k` raw answers; the aggregate recomputed from the raw answers equals the submitted one; and the ceilings still hold. Minutes are `min(requested, ceiling maximum, smallest max_minutes among the answers)`, and at most `narrowMinutes` for a "narrow" grant. Minutes are never raised.
4. **Aggregation** (identical in `plugin/src/verdict/aggregate.js` and `host/vaultd/judge.py`, tested against shared vectors). Answers are `a` allow narrow, `b` allow standard, `c` deny, `d` deny and lock the agent. A request is granted only if all `k` answers are `a` or `b`; the safer one (`a`) wins and the minutes are the smallest. It is a lock only if all `k` answers are `d`. Any other mix, an unparseable answer or fewer than 1 minute is a plain deny. A lock holds until `vaultctl unlock AGENT`.
5. **Issue.** On a grant `vaultd` creates the lease (`issuing`) and calls the helper: `session.open` for a login or `token.mint` for an OAuth token; static tokens come from `vault.<name>` credentials. Helper failures end the request as `failed` with a code (`login_failed, totp_failed, challenge_required, needs_interactive, captcha, site_unreachable, recipe_error, helper_down, timeout`). The payload is held in `vaultd`'s memory only (a session at most 2 MB).
6. **Deliver.** When the request is `ready` the plugin (from `vault_request_status` or its every-minute sweep) calls `lease.fetch`, which returns the payload once (a second call is `conflict`). The plugin resolves the workspace from exactly two sources, in this order: the run's issue execution workspace, else `<agentHomeRoot>/<agentId>`. The project's primary workspace is deliberately not a source: every agent of the project can read it (same user, same mount), so a session leased to one agent would be readable by another. If neither source yields a directory, delivery fails closed (`no_workspace`). The plugin requires its real path to lie under a configured `workspaceRoot`, and writes `<workspace>/.vault/<name>-<lease>.session.json` or `.token.json`. `.vault` is opened once with `O_DIRECTORY|O_NOFOLLOW` and every later operation goes through that descriptor; the file is created `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, by temporary file and rename. Tool results carry the relative path and expiry, never the contents. Agent-facing messages are fixed strings; the model's reason is shown only in the admin UI.
7. **End.** The sweeper in `vaultd` (every 5 s), `lease.revoke` or `vaultctl revoke` ends a lease: the helper logs out where the site allows it (`recipe.logout` steps or `logoutUrl`) or revokes the token, and the result is audited (`lease_end` with `logout: ok | unsupported | failed`). The plugin overwrites the file with zeros and removes it. If the plugin is down the file is stale anyway: the helper has clamped every cookie's expiry to the lease end and logged out server-side. The helper enforces the end itself even if `vaultd` is gone, and after a restart it closes sealed leases whose time has passed.

## 4. The login helper

* **Operations.** `ping`, `session.open`, `session.close`, `token.mint`, `token.revoke` (vaultd); `site.test`, `challenge.submit`, `interactive.start`, `interactive.finish`, `oauth.start`, `oauth.finish`, `session.import`, `site.forget`, `site.reload` (root CLI).
* **A login** uses a fresh browser context for each lease (headless Chromium from `browsers/`). The recipe runs `fill`, `click`, `press` and `waitFor` steps only, no scripts; values come from `username`, `password` and `totp` (RFC 6238, SHA-1, 6 digits, 30 s); the success check is mandatory. The returned storage state holds cookies new or changed during this login, minus the device-trust cookies named in `recipe.trustCookies`, with every `expires` set to at most the lease end (session cookies get the lease end).
* **Navigation limit.** Every request of a browser goes through a per-browser forward proxy on `127.0.0.1` that connects upstream only to the exact `host:port` pairs of the site's `allowedHosts` (https, or http for loopback); everything else gets a 403. A proxy is used because Playwright route handlers do not see the hops of a redirect and a host rule ignores ports.
* **Device trust.** Cookies that make a site skip its SMS or e-mail step next time are kept in `store/trust/<id>.enc`, loaded into the next login and never returned. A site that asks for a code once is handled by `vault-site test <id> --attended`, which types the code on the terminal.
* **Concurrency.** One login per site at a time (queued), at most 3 browsers.
* **OAuth.** `vault-site authorize <id>`: the device flow polls the token endpoint while the terminal shows a code and an address; the redirect flow listens on `127.0.0.1:<port>` (PKCE and `state`, one callback, 10 minutes) and the CLI prints the `ssh -L` command. The refresh token (rotation supported) is sealed in `store/oauth/<id>.enc`. `token.mint` is a refresh grant with `expires_at = min(provider, lease end)`; `token.revoke` calls `revokeUrl` when the site has one.
* **Interactive sites** (those that block automation): `vault-site interactive <id>` starts `Xvfb` with `-nolisten tcp -nolisten local` and a per-session cookie (`-auth`), a headed Chromium on `profiles/<id>`, and `x11vnc -localhost` on a free port in 5900-5999 with a one-time password, for 15 minutes at most. The CLI prints the password and the `ssh -L` line. After the owner logs in and presses Enter, the helper checks `successCheck`, seals the exported storage state in `store/session/<id>.enc` and stops everything. Leases for such a site get a copy of that state, refreshed by re-opening the profile headless. Without a logout step the copy cannot be revoked at lease end, so a site of this type must carry `acceptNoLogout: true`, which `vault-site interactive` writes only after an explicit `y`; otherwise `session.open` returns `needs_owner_ack` and `vaultd` denies with `site_not_ready`. `vault-site import-session` seals a storage state exported elsewhere.
* **Chromium sandbox.** The helper tries Chromium's sandbox; if Chromium cannot start with it, it runs with `--no-sandbox` only when `helper.json` has `allowNoSandbox: true`. The installer probes this once inside a copy of the helper unit and writes the value.

## 5. Site files

`/etc/vault/sites/<id>.json`, written by `vault-site add`, validated with the same rules by `vaultd`, the helper, the plugin form and the CLI; unknown keys are rejected at every level, so a secret field cannot ride along.

```json
{"schema":1,"id":"example-admin","displayName":"Example admin","type":"password-totp","kind":"test",
 "purpose":"QA login for the example app",
 "loginUrl":"https://app.example.org/login","logoutUrl":"https://app.example.org/logout",
 "allowedHosts":["app.example.org"],"allowedAgents":["<agent uuid>"],"roles":["QA"],"maxMinutes":60,
 "recipe":{"steps":[{"fill":"#email","from":"username"},{"click":"button[type=submit]"},
                    {"fill":"#password","from":"password"},{"click":"#login"},
                    {"fill":"#otp","from":"totp","optional":true}],
           "successCheck":{"urlMatches":"^https://app\\.example\\.org/dashboard"},
           "logout":{"steps":[{"click":"#logout"}]},"trustCookies":["^device_"],"timeoutSeconds":45},
 "oauth":null}
```

`type` is `password-totp`, `interactive` or `oauth` (an OAuth site has `oauth: {flow, authUrl, tokenUrl, deviceUrl, revokeUrl, clientId, scopes, accessTtlMaxMinutes}` and no recipe). `kind` is `test`, `owner` or `research`. `purpose`, `kind` and `roles` are shown to the gatekeeper as trusted text; `allowedAgents` and `maxMinutes` are hard ceilings. Credential names are `web-<id>` for logins and `oauth-<id>` for OAuth; the policy classes `web-login` and `oauth-token` match them.

## 6. Policy

`/etc/vault/policy.json`: `agents` (uuid to role), `never` (extra patterns that can never be granted; names starting with `vault` never are), `roles` (role to classes) and `classes` (`match` glob or list, `description`, `max_minutes`, `scopes`, `narrow_minutes`). Every request is decided by the gatekeeper after the ceilings; no class skips it, and no request is decided by a person. The policy is read when `vaultd` starts.

## 7. The plugin

* **Manifest.** Capabilities: agent tools, UI page, plugin state, scheduled jobs, activity log, core-table read of `heartbeat_runs` (the plugin creates no tables), issues, projects, execution workspaces, outbound HTTP (the gatekeeper only) and secret references (the gatekeeper key). No webhooks, no managed agents, no local folders. Minimum Paperclip version 2026.1012.0.
* **Tools** (named without write or send verbs so the gateway treats them as reads): `vault_request_login`, `vault_request_credential`, `vault_request_status`, `vault_list_sites`. A call waits up to `toolWaitMs` for the verdict (default 7000, under the gateway's 10 s) and otherwise answers `pending`.
* **Actions.** Reads need a signed-in user; writes (`installCommand`, `uninstallCommand`, `addSiteCommand`, `removeSiteCommand`, `revokeLease`, `selectModel`, `refreshModels`, `runJudgeTests`) refuse agents and need a user in `adminUserIds`. Plugin actions can be called by company members and agents alike, so every one checks the actor.
* **Jobs.** `lease-sweep` (deliver prepared sessions, remove files of ended or expired leases, also at start) and `enrol-tick`, both every minute.
* **Page.** One route, six tabs: Install, Sites, Ceilings (read-only), Decision log, Leases, Gatekeeper. The Sites form only builds the `sudo vault-site add --site-json-b64 ...` command line; the password and seed are typed on the host. The decision log and the leases are read live from `vaultd`.
* **Settings** are stored per company: `adminUserIds, workspaceRoots, agentHomeRoot, instanceRoot, sandboxExtraPaths, dataDir, socketPath, toolWaitMs, gatekeeper{baseUrl, apiKey, temperature, k, perCallTimeoutMs}`.
* **Verdict provider.** `plugin/src/verdict/provider.js` is the interface; `openai-compat.js` implements it for any OpenAI-compatible endpoint: `POST {baseUrl}/chat/completions` with a strict JSON-schema response format (`decision`, `max_minutes`, `reason`), `k` calls in parallel, `GET {baseUrl}/models` for the model picker. The key is resolved from the company secret for each call and never cached or logged. Paperclip has no plugin API for its own AI connections, so this provider is the only model path.
* **Judge tests.** See [judge-model-selection.md](judge-model-selection.md).

## 8. Installer and release

`scripts/release.sh --version X.Y.Z` writes `paperclip-vault-host-X.Y.Z.tar.gz` (reproducible: sorted, mtime 0, owner 0, `gzip -n`; vaultd, helper with its production `node_modules`, CLIs, units, judge tests), `install-vault.sh` (version, download URL, bundle SHA-256 and the pinned Node filled in), `paperclip-vault-plugin-X.Y.Z.tgz` (the plugin with its dependencies and `release-pins.json`) and `SHA256SUMS`. The default download URL is the GitHub release of that version.

`install-vault.sh` is idempotent. It validates arguments, downloads over https only, checks the bundle against the pinned SHA-256 and refuses links, devices and unsafe paths in it, creates the accounts, installs `/opt/vault`, finds a root-owned Node 24+ or vendors the pinned official tarball, installs apt packages (`xvfb x11vnc acl` and the Chromium libraries through `playwright-core install-deps`), installs Chromium as `vault-helper`, probes the sandbox, writes configuration and tokens, writes `enrol.json`, installs the units and starts them. `--prefix DIR` runs it against a fake root without root rights: system changes are printed as `would run: ...` and `file://` download URLs are allowed only in that mode. `--uninstall` and `--uninstall --purge` are described in the README; `--purge` only removes paths from a short allow-list that the manifest says the installer created, and never `vault.*` credentials.

## 9. Tests

`npm test` runs `scripts/test-all.sh`, which writes only into a scratch directory and needs no root:

* the `vaultd` unit tests (`host/tests`: ceilings, verdict checks, enrolment, peer credentials, audit chain, sweeper, protocol, Ed25519 and aggregation vectors shared with the plugin);
* `host/judge-tests/score.py --dry-run` and `--oracle` (the scenarios, the prompt and the metric code agree);
* the plugin tests (`plugin/test`, with a fake `ctx` and `tests/fakes/fake_vaultd.mjs`);
* the helper tests (`host/helper/test`) against `tests/fakes/fake_site.py` and `fake_oauth.py`, with a real headless Chromium unless `SKIP_BROWSER=1`;
* the installer tests (`tests/install`: release build, `--prefix` installs, refusals, uninstall and purge, `vault-site add --stdin-secrets`);
* an end-to-end test (`tests/e2e`) with the real `vaultd` and helper and the plugin's worker logic;
* a scan of the repository for secrets, e-mail addresses, home-directory paths and real UUIDs.

## 10. Known limits

See the README. In short: the verdict is produced inside the Paperclip account, a granted narrow token is visible to the agent, the plugin key is readable by the service user, interactive sites without a logout step cannot be revoked at lease end, Chromium may run with `--no-sandbox`, an issue's execution workspace is visible to every agent working on that issue, dependency installation is Debian and Ubuntu only, and Paperclip's plugin runtime is alpha.
