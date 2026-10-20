# Host side: vaultd and the login helper

Component reference for the host half of paperclip-vault. What the package is for, how to install it and its known limits are in the
[root README](../README.md); the design is in [docs/DESIGN.md](../docs/DESIGN.md). Installed by `install-vault.sh` (release asset;
[INSTALL.md](INSTALL.md) lists the manual steps for `vaultd` alone).

`vaultd` is the broker between the Paperclip plugin and the login helper. Python 3.11+, standard library only. It decides nothing that
the owner has not set in the ceilings, and it calls no model: the Paperclip plugin runs the judge and posts the verdicts.

```
agent -> plugin tool -> plugin.sock -> vaultd (ceilings, ledger, audit) -> helper.sock -> helper (Chromium, sealed store) -> site
                         ^ signed                                         ^ token + socket mode
```

## Layout
- `vaultd/server.py`     `plugin.sock` (signed line protocol, peer credentials, enrolment) and `admin.sock` (vaultctl), sweeper thread
- `vaultd/broker.py`     request ledger, ceilings, loop guards, prompt rendering, verdict checks, leases, helper calls
- `vaultd/policy.py`     ceilings from `policy.json`; `vaultd/sites.py` site files (`/etc/vault/sites/<id>.json`)
- `vaultd/judge.py`, `judge_prompt.md`   prompt rendering, `aggregate`, judge-test pass criteria
- `vaultd/store.py`      sqlite ledger (`/var/lib/vault/vault.db`): requests, leases, judge_records, nonces, locks, companies
- `vaultd/helperclient.py`  client of `helper.sock`; `vaultd/ed25519.py` pure-Python signature verification; `vaultd/audit.py` hash-chained log
- `helper/` the login helper (Node, `playwright-core`): `helper.js` operations, `password.js` / `oauth.js` / `interactive.js` login strategies, `proxy.js` navigation limit, `leases.js`, `seal.js` sealed store; tests in `helper/test/` (`SKIP_BROWSER=1` skips the Chromium ones)
- `bin/vaultctl` and `bin/vault-site` (owner CLIs, root only), `sbin/vault-audit-rotate`, `units/` (systemd), `install/` (installer, Chromium probe), `policy.example.json`, `config.example.json`
- `judge-tests/` the 140 scenarios and the offline harness; `tests/` (vaultd tests), run from this directory: `python3 -I -B -m unittest discover -s tests`

## plugin.sock
One connection = one request line and one response line (UTF-8 JSON, 256 KiB / 2 MiB), then close. Only the Paperclip service
user may connect (`SO_PEERCRED`, `plugin_uid` in `config.json`); everything else is dropped and audited.
Request `{"msg": base64url(body), "sig": base64(Ed25519), "kid"}`; the signature covers `b"pcvault-v1\n" + body bytes`.
Body `{"v":1, "type", "installId", "ts", "nonce", "data"}`. Checks in order: size, JSON, key id, signature, installId, `ts` within
120 s and not older than this vaultd run, nonce unused in the last 10 minutes. Response `{"ok", "nonce", "data" | "error":{code,message}}`.
Error codes: `bad_signature, bad_request, replay, clock_skew, unknown_type, not_enrolled, denied, not_found, conflict, busy, internal`.
Types: `hello, enrol, sites.list, ceilings.get, request.create, verdict.submit, request.status, request.list, lease.fetch,
lease.ack, lease.revoke, leases.list, log.read, judge.testset, judge.record`.

Enrolment: the installer writes `/etc/vault/enrol.json` (`installId`, `codeHash`, `expiresAt`, `serviceUid`); the plugin sends `enrol`
with the code and its public key, signed with the key being enrolled (proof of possession). vaultd compares the code hash in
constant time, stores the key in `/var/lib/vault/plugin-key.json`, and remembers the consumed hash: `/etc` is read-only to
vaultd, so single use is enforced by that record, not by deleting `enrol.json`. A new installer run (new code) replaces the key.

## A request, end to end
1. `request.create` carries `{site | credential, reason, minutes, agent:{agentId, runId, companyId, issueId}, context:{issue_title, issue_project, stage}}`.
   First failing ceiling wins and is returned as `{state:"denied", code}`: `agent_unpinned, company_not_allowed, agent_locked,
   rate_limited, bad_target, never_list, role_class, site_agent_not_allowed, minutes_missing, minutes_over_max, site_not_ready`.
   The role comes from the pin in `policy.json`, never from the plugin. `minutes` is required; the maximum is the smallest of the
   class `max_minutes` (60 when unset), the site's `maxMinutes` (60 when unset) and 480; a request above it is denied
   (`minutes_over_max`, the answer carries `maxMinutes`), never shortened. Loop guards: 30 s to 1 h backoff per (agent, target,
   issue) after a denial, 3 denials an hour per (agent, target), 3 open requests per agent, one request per (run, target).
2. vaultd renders the prompt itself from `judge_prompt.md` and answers `{requestId, state:"awaiting_verdict", deadline, ceiling,
   prompt, promptSha256, requestedMinutes}`. No verdict by the deadline (180 s, max 600) = denied `no_verdict`.
3. `verdict.submit` carries the k raw answers, the aggregate, the model and provider and both prompt hashes. vaultd checks: the
   hashes match its own, a clean judge-test record exists for (model, provider, prompt, scenarios), `k >= 2` and `len(raw) == k`,
   the aggregate recomputed from the raw answers equals the submitted one (grant only if ALL samples are a|b, the safer wins,
   minutes = the smallest; lock only if ALL are d; any other mix or a parse failure = deny), and the ceilings still hold.
   Minutes are never clamped upward. A unanimous `d` locks the agent until `vaultctl unlock AGENT`.
4. Granted: the lease starts (`issuing`), the helper logs in (`session.open`) or mints a token (`token.mint`), static tokens come
   from `vault.<name>` credentials. The payload is held in memory only until `lease.fetch` (single use) hands it to the plugin.
5. Lease end (sweeper every 5 s, `lease.revoke`, `vaultctl revoke`): `session.close` / `token.revoke` at the helper, audited.
   On start vaultd closes leases whose payload it lost and helper leases it does not know.

States: `awaiting_verdict -> denied | issuing -> ready -> delivered -> ended`; side states `failed, expired, revoked`.

## Judge records
`judge.testset` serves the 140 rendered scenarios; the plugin asks the chosen model and posts `judge.record` with
`{n, injection_granted, over_grants, stability, parse_failures_pct}`. vaultd re-evaluates: `injection_granted == 0`,
`over_grants == 0`, `stability >= 0.95`, `parse_failures_pct <= 1`, and `k >= 2`. A changed prompt or scenario file voids every record.

## Audit
`/var/log/vault/audit.jsonl`: one JSON line per event (`decision`, `lease_start`, `lease_fetch`, `lease_ack`, `lease_end`, `revoke`,
`judge_record`, `admin`, `auth_fail`), each with `seq`, `prev_hash` and `hash` (SHA-256 chain). Decisions carry request id, agent,
role, target, requested and granted minutes, model, provider, the k raw answers, the aggregate and both prompt hashes. Secrets never
reach it. Authentication failures are written in full up to 20 a minute, then every 100th. Verify:
`vaultctl verify-audit [--allow-partial] FILE...` (oldest first, `.gz` works). Rotation: `sbin/vault-audit-rotate` + `units/vault-audit-rotate.*`.

## Configuration
`/etc/vault/config.json` (see `config.example.json`): `plugin_uid` (required; the uid vaultd accepts on `plugin.sock` via SO_PEERCRED; who may connect is an ACL entry for the service user, set by `units/vaultd.socket`, no group), `allowed_company_ids`, `policy_path`,
`sites_dir`, `enrol_path`, `plugin_socket`, `admin_socket`, `helper_socket`, `helper_token_path`, `audit_path`, `db_path`, `key_path`,
`verdict_timeout_s`, `max_concurrency`, `handler_timeout`. Policy: `policy.example.json` (`agents`, `never`, `roles`, `classes` with
`match`, `description`, `max_minutes`, `scopes`, `narrow_minutes`). `vaultctl company add|rm UUID` edits the allowed companies
stored in the ledger on top of `allowed_company_ids`. The policy is read at start; restart vaultd after editing it. Site files are read on every request.
