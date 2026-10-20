# Installing vaultd by hand (admin steps)

`install-vault.sh` (release asset; see the [root README](../README.md#install)) does all of this, installs the login helper and
completes the plugin enrolment: use it. These are the steps for `vaultd` alone, for review or a hand install; the helper, Chromium and
the helper's credentials are not covered. Run as root. Paths match `units/vaultd.service`.

0. Stage and verify. Never install from a directory the Paperclip user can write. The host bundle is the release asset
   `paperclip-vault-host-<version>.tar.gz`; compare its SHA-256 with the one in the release notes (an anchor you obtained separately from the download).
   ```
   v=0.1.1; base=https://github.com/tomRumi/paperclip-vault/releases/download/v$v
   sudo install -d -m 0755 -o root -g root /opt/paperclip-vault-src && cd /opt/paperclip-vault-src
   sudo curl -fsSL -O "$base/paperclip-vault-host-$v.tar.gz" -O "$base/SHA256SUMS"
   sudo sha256sum -c --ignore-missing SHA256SUMS
   sudo tar -xzf "paperclip-vault-host-$v.tar.gz" --no-same-owner
   cd paperclip-vault-host                                       # the commands below are relative to this directory
   ```

1. Users, groups, directories (needs the `acl` package: `apt-get install acl`)
   ```
   useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vault
   install -d -o root -g root -m 0755 /opt/vault
   install -d -o root -g vault -m 0750 /etc/vault /etc/vault/sites
   install -d -o root -g vault -m 0750 /var/log/vault
   cp -r vaultd bin sbin judge-tests units install VERSION /opt/vault/ && chown -R root:root /opt/vault
   install -m 0640 -g vault policy.example.json /etc/vault/policy.json          # then edit: pin every agent UUID to a role
   install -m 0640 -g vault config.example.json /etc/vault/config.json          # then set plugin_uid (id -u <service user>) and allowed_company_ids
   head -c 32 /dev/urandom | base64 -w0 | install -m 0640 -o root -g vault /dev/stdin /etc/vault/helper.token
   printf '#!/bin/sh\nexec /usr/bin/python3 -I /opt/vault/bin/vaultctl "$@"\n' > /usr/local/sbin/vaultctl && chmod 0755 /usr/local/sbin/vaultctl   # optional wrapper
   ```
   Keep `/opt/vault` root-owned so neither the service user nor `vault` can rewrite the code. `/var/lib/vault` (ledger, enrolled key) is
   created by `StateDirectory=vault`. The helper token `/etc/vault/helper.token` (32 random bytes, base64, 0640 root:vault) is shared with the helper.
2. Append-only audit log
   ```
   getent group vaultaudit >/dev/null || groupadd --system vaultaudit      # read-only access to the log for rotation and other readers
   touch /var/log/vault/audit.jsonl && chown vault:vault /var/log/vault/audit.jsonl && chmod 0600 /var/log/vault/audit.jsonl
   setfacl -m g:vaultaudit:rx /var/log/vault && setfacl -d -m g:vaultaudit:r /var/log/vault && setfacl -m g:vaultaudit:r /var/log/vault/audit.jsonl
   chattr +a /var/log/vault/audit.jsonl      # ACL FIRST: +a makes the kernel reject ACL/chmod changes, even for root
   ```
   (Needs the `acl` package. The log is 0600 on purpose: `vault-helper` is in the group `vault` and must not read it; the `vaultaudit` ACL entry is the only other reader (add the accounts that may read the log to that group). To change the ACL later, lift the append-only flag as in step 6, with vaultd stopped, change it, and set the flag again.)
   The Paperclip service user cannot read or write `/var/log/vault` (mode 0750 root:vault). The directory is root-owned on purpose: `vault-audit-rotate` refuses a directory the `vault` user owns, and `vaultd` only appends to the existing file.
3. Static credentials (optional), one per secret, named `vault.<credential>`. Read the value without putting it in a shell variable or history:
   ```
   systemd-ask-password -n "value:" | systemd-creds encrypt --name=vault.github-ro-myrepo - /etc/credstore.encrypted/vault.github-ro-myrepo
   ```
   A new credential needs `systemctl restart vaultd` (running leases survive in the helper only; vaultd closes undelivered ones on start).
   Web logins and OAuth sources are not set up here: `vault-site add` writes the site files and the helper's credentials.
4. Units and enrolment
   ```
   cp units/vaultd.service /etc/systemd/system/
   sed "s|@SVC@|<paperclip service user>|" units/vaultd.socket > /etc/systemd/system/vaultd.socket
   systemctl daemon-reload && systemctl enable vaultd.socket vaultd.service
   # LAST, right before the start: write /etc/vault/enrol.json {installId, codeHash, expiresAt, serviceUid} as the installer does
   # (expiresAt = now + 60 minutes), then:
   systemctl start vaultd.socket vaultd.service
   ```
   `plugin.sock` is created by systemd (`vaultd.socket`: 0600 vault:vault, `SocketMode=0600`) and handed to vaultd (socket activation,
   `LISTEN_FDS`/`LISTEN_PID`, descriptor 3). The Paperclip service user reaches it through one ACL entry
   (`ExecStartPost=setfacl -m u:<user>:rw /run/vault/plugin.sock`, which is why `acl` is a dependency) and `/run/vault` is 0711 so it can
   be traversed. There is no group to join: no new login session and no Paperclip restart. Access control is unchanged: vaultd
   still requires `SO_PEERCRED` uid == `plugin_uid` and the Ed25519 signature on every message; the ACL only decides who may connect.
   Without socket activation (tests, development) vaultd binds `plugin_socket` itself.

   Enrolment design: the installer writes `enrol.json` as the last step before the units start, so its 60 minutes run from that moment
   (the plugin's one-time code has the same 60 minute lifetime). vaultd does not delete `enrol.json` (`/etc` is read-only to it);
   single use is enforced by the code hash vaultd stores next to the enrolled key in `/var/lib/vault/plugin-key.json`: a record
   whose hash is already stored is refused, and an expired one too. A new installer run with a new code replaces the trusted key.
   The plugin's Install tab shows the command that creates the enrolment record; the plugin completes the enrolment within the hour.
   Admin: `vaultctl status|leases|revoke LEASE|unlock AGENT|company add|rm UUID` (the socket `/run/vault/admin.sock` is 0600 vault, so root
   or vault only; peers are also checked with SO_PEERCRED).
5. Judge records: in the plugin's Judge tab choose a model and run the judge tests. vaultd accepts verdicts only from a
   (model, provider) with a clean record for the current prompt and scenario file; a prompt change voids all records.
6. Monthly rotation that keeps the chain (the log is `+a`, so lift it briefly). Stop vaultd for
   the swap so no record is written between the `mv` and the `install` (requests fail closed meanwhile):
   ```
   systemctl stop vaultd
   chattr -a /var/log/vault/audit.jsonl
   mv /var/log/vault/audit.jsonl /var/log/vault/audit-$(date +%Y-%m).jsonl
   install -o vault -g vault -m 0600 /dev/null /var/log/vault/audit.jsonl
   chattr +a /var/log/vault/audit.jsonl
   chattr +a /var/log/vault/audit-*.jsonl
   systemctl start vaultd
   ```
   (Alternative without stopping: `kill -STOP` / `kill -CONT` the vaultd main PID around the swap.)
   vaultd reopens the file on every write and keeps the last hash in memory; after a
   restart it recovers the hash from the newest `audit-*.jsonl`. Check everything with
   `sudo vaultctl verify-audit /var/log/vault/audit-*.jsonl /var/log/vault/audit.jsonl`
   (oldest first; the first record must chain from genesis, or pass `--allow-partial`). A torn
   last line after a crash is skipped with an ALERT and vouched for by the next record. Copy the
   last hash off-host from time to time: a root attacker can rewrite a whole chain, an off-host
   copy of the head detects that.

   Automated: `sbin/vault-audit-rotate` + `units/vault-audit-rotate.{service,timer}` (copy both to `/etc/systemd/system/` and `systemctl enable --now vault-audit-rotate.timer`; monthly, `Persistent=true`) do the
   rotation above (the file is named `audit-<UTC rotation time>.jsonl`, e.g. `audit-2026-11-01T003000Z.jsonl`; vaultd is restarted
   on any failure), gzip every rotated file except the newest (the `.gz` keeps the data's mtime), and delete rotated files older
   than 365 days. `vault-audit-rotate --dry-run` only prints. It refuses to run unless `/var/log/vault` is owned by root (so the
   vault user cannot plant symlinks while root works there): run `chown root:vault /var/log/vault; chmod 0750 /var/log/vault`
   once (vaultd only appends to the existing live file; it never creates files there; keep both ACL entries).
   Verify rotated files (oldest first, `.gz` is read transparently; add `--allow-partial` once retention has deleted the first file):
   `sudo bash -c 'shopt -s nullglob; cd /var/log/vault; vaultctl verify-audit --allow-partial audit-*.jsonl.gz audit-*.jsonl audit.jsonl'`

