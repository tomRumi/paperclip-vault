#!/usr/bin/env bash
# install-vault.sh: one-line installer for paperclip-vault (vaultd + vault-helper), run by an admin with sudo.
#
#   sudo bash install-vault.sh --service-user U --company UUID --enrol CODE     install (or update) and enrol
#   sudo bash install-vault.sh                                                  update an installed vault
#   sudo bash install-vault.sh --uninstall [--purge]                            remove it (--purge: what this installer created)
#
# Options:
#   --service-user U  the account Paperclip runs as (not root). Its uid is the only one vaultd accepts on plugin.sock, and it gets
#                     read/write on that socket through a POSIX ACL entry (no group, so no new login session and no Paperclip
#                     restart). Needed on the first install.
#   --company UUID    a Paperclip company that may use the vault (repeatable; the plugin's command names one). Without any,
#                     add one later with: vaultctl company add UUID
#   --enrol CODE      one-time code from the plugin's Install tab (60 minutes, single use). Only its hash is stored.
#   --base-url URL    where the host bundle is downloaded from (default: the GitHub release of this version; also
#                     $VAULT_BASE_URL). Only https:// (file:// only together with --prefix, for tests).
#   --node PATH       a root-owned Node.js >= 24 for the helper. Default: /usr/bin/node or /usr/local/bin/node when root-owned
#                     and >= 24, otherwise the official nodejs.org tarball pinned below is vendored into /opt/vault/node.
#                     A Node under a user's home is always refused: that user could rewrite code the helper runs.
#   --skip-deps       do not run apt; print the packages to install yourself and continue (acl must be there: setfacl is needed)
#   --prefix DIR      install into a fake root for tests: an absolute path to an existing or creatable directory, never "/";
#                     no root check, no useradd/systemctl/chown/apt/runuser, prints "would run: ..." instead, files are written
#                     under DIR
#   --uninstall       stop and remove units, /opt/vault and the wrappers. Keeps /etc/vault, the credential blobs, /var/lib/vault*,
#                     the audit log and the accounts, so a later install resumes where this one stopped.
#   --purge           with --uninstall: also delete what THIS installer created (listed in /etc/vault/installed-by: directories,
#                     files, the store key credential, accounts and groups). Anything that was already there before is kept:
#                     an existing /etc/vault, existing vault.* credential blobs, an existing audit log; the output says so.
#
# What it does (host/INSTALL.md has the manual steps for vaultd alone):
#   1. downloads the host bundle from the official release and checks it against the sha256 pinned below (written by
#      scripts/release.sh); a mismatch stops before anything is installed; links, devices and FIFOs in the bundle are refused;
#   2. creates the system accounts vault and vault-helper (no shell, no sudo); records every account, group, directory, file and
#      credential it created in /etc/vault/installed-by; installs the code root-owned under /opt/vault;
#   3. finds or vendors a root-owned Node, installs the system packages (xvfb, x11vnc, acl, the Chromium libraries) with apt, and
#      Chromium itself as vault-helper into /var/lib/vault-helper/browsers (the Node runs with a cleaned environment);
#   4. probes the Chromium sandbox once inside a copy of the helper unit and writes allowNoSandbox from the result;
#   5. writes config.json, helper.json, the helper tokens, the store key credential, a starter policy.json (never overwritten),
#      installs the units (vaultd.socket creates plugin.sock and gives the service user an ACL entry on it), and as the LAST step
#      before the units start enrol.json (the hash of the code, never the code; valid 60 minutes from that moment);
#   6. starts everything, waits for plugin.sock and prints the fingerprint. The plugin completes the enrolment within the hour.
# Idempotent: running it again updates code and units and keeps keys, tokens, policy, sites and credentials.
set -euo pipefail
umask 022

VERSION="__VERSION__"
BUNDLE_SHA256="__BUNDLE_SHA256__"
DEFAULT_BASE_URL="__BASE_URL__"
NODE_VERSION="__NODE_VERSION__"
NODE_X64_SHA256="__NODE_X64_SHA256__"
NODE_ARM64_SHA256="__NODE_ARM64_SHA256__"
BUNDLE="paperclip-vault-host-${VERSION}.tar.gz"
PY=/usr/bin/python3
SAFE_PATH=/usr/sbin:/usr/bin:/sbin:/bin       # the only PATH root-invoked Node (and what it starts) gets
SYSTEM_PACKAGES=(xvfb x11vnc acl)

die() { echo "install-vault: $*" >&2; exit 1; }
say() { echo "install-vault: $*"; }
warn() { echo "install-vault: WARNING: $*" >&2; }

SVC="" CODE="" BASE_URL="${VAULT_BASE_URL:-}" PREFIX="" UNINSTALL=0 PURGE=0 NODE_ARG="" SKIP_DEPS=0
COMPANIES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --service-user) SVC="${2:-}"; shift 2 ;;
    --company) COMPANIES+=("${2:-}"); shift 2 ;;
    --enrol) CODE="${2:-}"; shift 2 ;;
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --node) NODE_ARG="${2:-}"; shift 2 ;;
    --skip-deps) SKIP_DEPS=1; shift ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done
[ "$PURGE" -eq 0 ] || [ "$UNINSTALL" -eq 1 ] || die "--purge only goes with --uninstall"

if [ -n "$PREFIX" ]; then
  case "$PREFIX" in /*) ;; *) die "--prefix must be an absolute path" ;; esac
  [[ "$PREFIX" =~ ^/[A-Za-z0-9._/+@-]*$ ]] || die "--prefix may only hold letters, digits and . _ / + @ -"
  # Normalise first ("//", "/./", "/a/.." ...): a prefix that is the real root would turn the test mode into a live install.
  PREFIX="$(realpath -m -- "$PREFIX")" || die "--prefix cannot be resolved"
  [ "$PREFIX" != "/" ] || die "--prefix must not be / (it would not be a fake root)"
  if [ -e "$PREFIX" ] && [ ! -d "$PREFIX" ]; then die "--prefix is not a directory"; fi
  mkdir -p "$PREFIX" 2>/dev/null || die "--prefix directory cannot be created"
else
  [ "$(id -u)" -eq 0 ] || die "run this with sudo (as the admin account, not Paperclip's account)"
fi
R="$PREFIX"
OPT="$R/opt/vault" ETC="$R/etc/vault" CRED="$R/etc/credstore.encrypted" UNITDIR="$R/etc/systemd/system"
SBIN="$R/usr/local/sbin" VARLIB="$R/var/lib" LOG="$R/var/log/vault" RUN="$R/run"
SITES="$ETC/sites" MANIFEST="$ETC/installed-by"

# Privileged system changes: real commands, or "would run" lines in a --prefix test install (paths shown without the prefix).
# VAULT_INSTALL_FAIL="word ..." (fake roots only, for tests) makes every printed command containing such a word report failure.
run() {
  if [ -n "$PREFIX" ]; then
    local s="$*"
    echo "would run: ${s//"$PREFIX"/}"
    local w
    for w in ${VAULT_INSTALL_FAIL:-}; do case " $s " in *" $w "*) return 1 ;; esac; done
  else
    "$@"
  fi
}
need() { for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done; }

# Directory with mode and owner (the owner change is a system change: printed in a prefix install).
mkd() { # mode owner dir
  [ "$3" = "$OPT" ] || note_new "${3#"$R"}"          # /opt/vault is removed by --uninstall itself
  install -d -m "$1" "$3"
  chmod "$1" "$3"
  run chown "$2" "$3"
}

# Atomically replace a file with stdin; mode and owner as given (the owner change is applied to the final path).
put() { # mode owner dest
  local tmp
  tmp="$(mktemp "$3.XXXXXX")"
  cat > "$tmp"
  chmod "$1" "$tmp"
  mv -f "$tmp" "$3"
  run chown "$2" "$3"
}

record() { # one line of the install manifest, once
  grep -qxF "$1" "$MANIFEST" 2>/dev/null || { (umask 077; echo "$1" >> "$MANIFEST"); }
}
recorded() { grep -qxF "$1" "$MANIFEST" 2>/dev/null; }
# A path (without the prefix) this installer is about to create and that is not there yet: --purge may remove it again.
note_new() { [ -e "$R$1" ] || record "path:$1"; }

user_exists() { if [ -n "$PREFIX" ]; then recorded "user:$1"; else getent passwd "$1" >/dev/null; fi; }
group_exists() { if [ -n "$PREFIX" ]; then recorded "group:$1"; else getent group "$1" >/dev/null; fi; }

# -------------------------------------------------------------------------------------------------- uninstall
# Purge helpers. Only what the manifest says this installer created is removed, and only paths from a short allow-list, so a
# damaged manifest cannot point rm at anything else. A step that fails is reported at the end; the others still run.
PURGE_FAILED=()
attempt() { # what, command...
  local what="$1"; shift
  if ! "$@"; then PURGE_FAILED+=("$what"); warn "$what failed; carrying on with the rest of the purge"; fi
  return 0
}
purge_path_ok() {
  case "$1" in
    *..*|*//*|*[!A-Za-z0-9._/+@-]*) return 1 ;;
    /etc/vault|/etc/vault/*|/var/lib/vault|/var/lib/vault-helper|/var/log/vault|/var/log/vault/*|/etc/credstore.encrypted) return 0 ;;
    *) return 1 ;;
  esac
}
purge_cred_ok() { [[ "$1" =~ ^vault-helper\.[A-Za-z0-9._-]+$ ]]; }    # never vault.* (the admin's own credentials)

if [ "$UNINSTALL" -eq 1 ]; then
  run systemctl disable --now vault-audit-rotate.timer vaultd.socket vaultd.service vault-helper.service || true
  for u in vaultd.service vaultd.socket vault-helper.service vault-helper-probe.service vault-audit-rotate.service vault-audit-rotate.timer; do
    rm -f "$UNITDIR/$u"
  done
  run systemctl daemon-reload || true
  rm -rf "$OPT" "$SBIN/vault-site" "$SBIN/vaultctl" "$RUN/vault" "$RUN/vault-helper"
  say "removed: units, /opt/vault, /usr/local/sbin/vault-site and vaultctl, sockets"
  if [ "$PURGE" -eq 1 ]; then
    MANI=()
    if [ -f "$MANIFEST" ]; then mapfile -t MANI < "$MANIFEST"; fi
    PATHS=() CREDS=() USERS=() GROUPS_=()
    for line in "${MANI[@]+"${MANI[@]}"}"; do
      case "$line" in
        path:*) if purge_path_ok "${line#path:}"; then PATHS+=("${line#path:}"); else warn "ignoring an unexpected manifest entry: $line"; fi ;;
        cred:*) if purge_cred_ok "${line#cred:}"; then CREDS+=("${line#cred:}"); else warn "ignoring an unexpected manifest entry: $line"; fi ;;
        user:*) USERS+=("${line#user:}") ;;
        group:*) GROUPS_+=("${line#group:}") ;;
      esac
    done
    # The audit log (and rotated files) are append-only: lift that first, only where the directory or the file is ours.
    LOG_OURS=0 AUDIT_OURS=0
    for q in "${PATHS[@]+"${PATHS[@]}"}"; do
      [ "$q" = /var/log/vault ] && LOG_OURS=1
      [ "$q" = /var/log/vault/audit.jsonl ] && AUDIT_OURS=1
    done
    if [ "$LOG_OURS" -eq 1 ] && [ -d "$LOG" ]; then
      attempt "lifting the append-only flag (chattr -a) in /var/log/vault" run find "$LOG" -maxdepth 1 -type f -exec chattr -a {} +
    elif [ "$AUDIT_OURS" -eq 1 ] && [ -e "$LOG/audit.jsonl" ]; then
      attempt "lifting the append-only flag (chattr -a) on the audit log" run chattr -a "$LOG/audit.jsonl"
    fi
    for c in "${CREDS[@]+"${CREDS[@]}"}"; do
      [ -e "$CRED/$c" ] && attempt "removing credential $c" rm -f "$CRED/$c"
    done
    # Deepest paths first, so a file goes before its directory; credential directories only when empty.
    while IFS= read -r q; do
      [ -n "$q" ] || continue
      [ -e "$R$q" ] || continue
      if [ "$q" = /etc/credstore.encrypted ]; then
        rmdir "$R$q" 2>/dev/null || say "kept $q: it still holds credentials that are not this installer's"
      elif [ -d "$R$q" ]; then attempt "removing $q" rm -rf "$R$q"
      else attempt "removing $q" rm -f "$R$q"
      fi
    done < <(printf '%s\n' "${PATHS[@]+"${PATHS[@]}"}" | awk 'NF{print length($0) " " $0}' | sort -rn | cut -d' ' -f2-)
    # Accounts and groups only if this installer created them (the manifest), in the order that keeps userdel happy.
    for u in "${USERS[@]+"${USERS[@]}"}"; do
      attempt "removing account $u" run userdel "$u"
    done
    for g in "${GROUPS_[@]+"${GROUPS_[@]}"}"; do
      if printf '%s\n' "${USERS[@]+"${USERS[@]}"}" | grep -qxF "$g"; then continue; fi    # userdel took the user's own group with it
      if [ -n "$PREFIX" ] || getent group "$g" >/dev/null; then attempt "removing group $g" run groupdel "$g"; fi
    done
    if [ "${#PURGE_FAILED[@]}" -eq 0 ]; then rm -f "$MANIFEST"; fi        # kept on failure: a second --purge finishes the job
    say "purged what this installer created: ${#PATHS[@]} paths, ${#CREDS[@]} credentials, ${#USERS[@]} accounts and ${#GROUPS_[@]} groups (the list was /etc/vault/installed-by)"
    KEPT=()
    for k in "$ETC" "$VARLIB/vault" "$VARLIB/vault-helper" "$LOG" "$CRED"; do [ ! -e "$k" ] || KEPT+=("${k#"$R"}"); done
    if [ -d "$CRED" ] && compgen -G "$CRED/vault.*" >/dev/null; then KEPT+=("the credential blobs vault.* (yours, never removed)"); fi
    if [ "${#KEPT[@]}" -gt 0 ]; then
      say "kept, because it was there before this installer or is not its own: ${KEPT[*]}"
    fi
    if [ "${#PURGE_FAILED[@]}" -gt 0 ]; then
      echo "install-vault: PURGE INCOMPLETE, these steps failed: $(IFS=';'; echo "${PURGE_FAILED[*]}")" >&2
      echo "install-vault: fix the cause (for the append-only flag: lsattr /var/log/vault; chattr -a FILE) and run --uninstall --purge again" >&2
      echo "The plugin can be removed in Paperclip (Plugins -> paperclip-vault -> Uninstall)."
      exit 1
    fi
  else
    say "kept: /etc/vault, the credential blobs, /var/lib/vault, /var/lib/vault-helper, the audit log in /var/log/vault, and the accounts vault and vault-helper"
    say "(a removed account's numeric id would be handed to the next system account, which would then own this data; add --purge to delete what this installer created, accounts included)"
  fi
  echo "The plugin can be removed in Paperclip (Plugins -> paperclip-vault -> Uninstall)."
  exit 0
fi

# -------------------------------------------------------------------------------------------------- install: checks
# Every value scripts/release.sh fills in must be filled in: an unfilled placeholder means this is the repository copy, not a release.
case "$BUNDLE_SHA256" in
  [0-9a-f]*) [ "${#BUNDLE_SHA256}" -eq 64 ] && [[ "$BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "corrupt pinned fingerprint" ;;
  *) die "this is not a release build of the installer (no pinned bundle fingerprint); download install-vault.sh from the release page" ;;
esac
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "this is not a release build of the installer (no version is pinned); download install-vault.sh from the release page"
[[ "$NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "this is not a release build of the installer (no pinned Node version); download install-vault.sh from the release page"
[[ "$NODE_X64_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "this is not a release build of the installer (no pinned Node x64 fingerprint); download install-vault.sh from the release page"
[[ "$NODE_ARM64_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "this is not a release build of the installer (no pinned Node arm64 fingerprint); download install-vault.sh from the release page"
case "$DEFAULT_BASE_URL" in https://*|file://*) ;; *) die "this is not a release build of the installer (no download URL is pinned); download install-vault.sh from the release page" ;; esac
need curl sha256sum tar gzip install head base64 od "$PY"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "vaultd needs $PY from Python 3.11 or newer"
if [ -z "$PREFIX" ]; then
  need runuser systemctl systemd-creds useradd groupadd
  if [ "$SKIP_DEPS" -eq 1 ]; then need setfacl; fi         # vaultd.socket and the audit log use ACLs (package acl)
  sd="$(systemctl --version | awk 'NR==1{print $2}')"
  [ "${sd:-0}" -ge 254 ] 2>/dev/null || die "systemd 254 or newer is needed (ImportCredential=); this host has ${sd:-an unknown version}"
fi

BASE_URL="${BASE_URL:-$DEFAULT_BASE_URL}"
case "$BASE_URL" in
  https://*) CURL_PROTO="=https" ;;
  file://*) [ -n "$PREFIX" ] || die "file:// downloads are only for --prefix test installs"; CURL_PROTO="=file" ;;
  *) die "the download URL must be https://" ;;
esac
case "$BASE_URL" in */) ;; *) BASE_URL="$BASE_URL/" ;; esac

UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
for c in "${COMPANIES[@]+"${COMPANIES[@]}"}"; do
  [[ "$c" =~ $UUID_RE ]] || die "--company must be a Paperclip company UUID"
done
if [ -n "$CODE" ]; then
  [[ "$CODE" =~ ^[A-Za-z0-9-]{8,40}$ ]] || die "the enrolment code is malformed (copy the whole line from the plugin's Install tab again)"
fi
if [ -n "$SVC" ]; then
  [[ "$SVC" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--service-user is not a valid user name"
  case "$SVC" in root|vault|vault-helper) die "--service-user must be the account Paperclip runs as, not $SVC" ;; esac
  SVC_UID="$(id -u "$SVC" 2>/dev/null)" || die "the service user $SVC does not exist on this host"
  [ "$SVC_UID" -ne 0 ] || die "the service user must not be root"
fi

FIRST=0
[ -f "$ETC/config.json" ] || FIRST=1
if [ "$FIRST" -eq 1 ] && [ -z "$SVC" ]; then die "first install: --service-user U is required"; fi
if [ ! -f "$VARLIB/vault/plugin-key.json" ] && [ ! -f "$ETC/enrol.json" ] && [ -z "$CODE" ]; then
  die "this vault is not enrolled yet: --enrol CODE is required (the plugin's Install tab shows the whole line)"
fi
if [ -z "$SVC" ]; then
  SVC_UID="$("$PY" -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["plugin_uid"])' "$ETC/config.json")" || die "cannot read plugin_uid from $ETC/config.json"
fi
# The account name for the ACL entry on plugin.sock (the uid itself if no name is found).
SVC_NAME="$SVC"
if [ -z "$SVC_NAME" ]; then SVC_NAME="$(getent passwd "$SVC_UID" | cut -d: -f1)" || true; fi
[ -n "$SVC_NAME" ] || SVC_NAME="$SVC_UID"
[[ "$SVC_NAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ || "$SVC_NAME" =~ ^[0-9]+$ ]] || die "the service user name has characters a unit file cannot hold"

# -------------------------------------------------------------------------------------------------- the Node rule
# The helper (and the install-deps step below) run as root or vault-helper, so their Node must not be writable by anybody
# else: root-owned file in a root-owned chain of directories, never under a user's home.
NODE_WHY=""
node_ok() {
  local p real part mode owner uid home
  p="$1"
  if ! { [ -f "$p" ] && [ -x "$p" ]; }; then NODE_WHY="$p is not an executable file"; return 1; fi
  real="$(readlink -f -- "$p")"
  if ! [[ "$real" =~ ^/[A-Za-z0-9._/+-]+$ ]]; then NODE_WHY="the path of $p has characters a unit file cannot hold"; return 1; fi
  case "$real" in
    /home/*|/root/*|/var/home/*) NODE_WHY="$real is under a home directory: that user could rewrite the code the helper runs"; return 1 ;;
  esac
  while IFS=: read -r _ _ uid _ _ home _; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && [ -n "$home" ] && [ "$home" != "/" ]; then
      case "$real/" in "$home"/*) NODE_WHY="$real is under the home directory $home"; return 1 ;; esac
    fi
  done < <(getent passwd)
  if [ -z "$PREFIX" ]; then
    part="$real"
    while :; do
      owner="$(stat -c %u -- "$part")" mode="$(stat -c %a -- "$part")"
      if [ "$owner" != 0 ] || [ $(( 8#$mode & 8#022 )) -ne 0 ]; then NODE_WHY="$part is not root-owned and closed to writes by others"; return 1; fi
      [ "$part" = "/" ] && break
      part="$(dirname -- "$part")"
    done
  fi
  local ver
  ver="$(env -i PATH="$SAFE_PATH" "$real" -p 'process.versions.node' 2>/dev/null)" || { NODE_WHY="$real does not run"; return 1; }
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && [ "${ver%%.*}" -ge 24 ] || { NODE_WHY="$real is Node $ver; 24 or newer is needed"; return 1; }
  NODE_BIN="$real"
}

NODE_BIN="" NODE_VENDOR=0
if [ -n "$NODE_ARG" ]; then
  node_ok "$NODE_ARG" || die "--node refused: $NODE_WHY"
else
  # The places a distribution or NodeSource puts Node (VAULT_INSTALL_NODE_CANDIDATES narrows the list; fake roots only, for tests).
  CANDIDATES="/usr/bin/node /usr/local/bin/node"
  [ -z "$PREFIX" ] || CANDIDATES="${VAULT_INSTALL_NODE_CANDIDATES-$CANDIDATES}"
  for cand in $CANDIDATES; do
    if node_ok "$cand"; then break; fi
  done
  if [ -z "$NODE_BIN" ]; then
    NODE_VENDOR=1
    NODE_BIN="/opt/vault/node/bin/node"
  fi
fi

# -------------------------------------------------------------------------------------------------- download and verify
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say "downloading ${BASE_URL}${BUNDLE}"
curl -fsSL --proto "$CURL_PROTO" --proto-redir "$CURL_PROTO" "${BASE_URL}${BUNDLE}" -o "$TMP/bundle.tar.gz" || die "download failed"
echo "${BUNDLE_SHA256}  $TMP/bundle.tar.gz" | sha256sum -c --status - \
  || die "the bundle's fingerprint does not match the one pinned in this installer; nothing was installed"
tar -tzf "$TMP/bundle.tar.gz" > "$TMP/list" || die "the bundle is not a readable archive"
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$TMP/list"; then die "the bundle contains unsafe paths"; fi
# Regular files and directories only: no links, devices (character, block), FIFOs or anything else.
tar -tvzf "$TMP/bundle.tar.gz" > "$TMP/listv" || die "the bundle is not a readable archive"     # a file, not a pipe: grep -q would SIGPIPE tar
if grep -Eq '^[^-d]' "$TMP/listv"; then die "the bundle contains links, devices, FIFOs or other special files"; fi
mkdir "$TMP/x"
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP/x" --no-same-owner --no-same-permissions
SRC="$TMP/x/paperclip-vault-host"
for f in vaultd/__main__.py helper/main.js helper/node_modules/playwright-core/cli.js bin/vault-site bin/vaultctl \
         units/vaultd.service units/vaultd.socket units/vault-helper.service install/probe-chromium.mjs judge-tests/scenarios.jsonl \
         config.example.json policy.example.json VERSION; do
  [ -e "$SRC/$f" ] || die "the bundle is incomplete ($f missing)"
done
[ "$(cat "$SRC/VERSION")" = "$VERSION" ] || die "the bundle's version does not match this installer"

# -------------------------------------------------------------------------------------------------- 1. accounts, directories
# The manifest comes first: every account, group, directory, file and credential created from here on is written into it, so
# --purge removes exactly that (and nothing that was there before).
ETC_NEW=0
[ -d "$ETC" ] || ETC_NEW=1
mkdir -p "$ETC"
(umask 077; touch "$MANIFEST")
[ "$ETC_NEW" -eq 0 ] || record "path:/etc/vault"
ensure_group() {
  group_exists "$1" && return 0
  run groupadd --system "$1"
  record "group:$1"
}
ensure_user() { # name home
  user_exists "$1" && return 0
  if group_exists "$1"; then run useradd --system -g "$1" --home-dir "$2" --no-create-home --shell /usr/sbin/nologin "$1"
  else run useradd --system --user-group --home-dir "$2" --no-create-home --shell /usr/sbin/nologin "$1"
  fi
  record "user:$1"
  record "group:$1"
}
ensure_group vaultaudit       # vault-audit-rotate checks its ACL on the audit log
ensure_user vault /nonexistent
ensure_user vault-helper /var/lib/vault-helper

mkdir -p "$R/opt" "$UNITDIR" "$SBIN"          # standard system directories: created in a fake root, never re-owned
mkd 0755 root:root "$OPT"
mkd 0750 root:vault "$ETC"
mkd 0750 root:vault "$SITES"
[ -d "$CRED" ] || mkd 0700 root:root "$CRED"       # recorded: --purge removes it again only when it is empty
mkd 0700 vault:vault "$VARLIB/vault"
mkd 0700 vault-helper:vault-helper "$VARLIB/vault-helper"
[ -d "$LOG" ] || mkd 0750 root:vault "$LOG"   # root-owned: vault-audit-rotate refuses a directory the vault user owns

# -------------------------------------------------------------------------------------------------- 2. code (root-owned)
for e in "$SRC"/*; do
  name="$(basename "$e")"
  rm -rf "${OPT:?}/$name"
  cp -r "$e" "$OPT/$name"
done
find "$OPT" -name __pycache__ -prune -exec rm -rf {} +
chmod -R go-w "$OPT"
chmod 0755 "$OPT"/bin/* "$OPT"/sbin/* 2>/dev/null || true
run chown -R root:root "$OPT"
for w in vault-site vaultctl; do
  put 0755 root:root "$SBIN/$w" <<EOF
#!/bin/sh
# Installed by install-vault.sh: runs the root-owned copy in /opt/vault.
exec /usr/bin/python3 -I /opt/vault/bin/$w "\$@"
EOF
done

# -------------------------------------------------------------------------------------------------- 3. Node, packages, Chromium
HELPER_CLI="$OPT/helper/node_modules/playwright-core/cli.js"
if [ "$NODE_VENDOR" -eq 1 ]; then
  case "$(uname -m)" in
    x86_64) NODE_ARCH=x64 NODE_SHA="$NODE_X64_SHA256" ;;
    aarch64|arm64) NODE_ARCH=arm64 NODE_SHA="$NODE_ARM64_SHA256" ;;
    *) die "no root-owned Node >= 24 found and no pinned Node for $(uname -m): install Node 24 from your distribution and pass --node PATH" ;;
  esac
  NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
  say "no root-owned Node >= 24 on this host: vendoring Node ${NODE_VERSION} into /opt/vault/node"
  if [ -n "$PREFIX" ]; then
    echo "would run: curl -fsSL --proto =https $NODE_URL (sha256 ${NODE_SHA}) | tar -xJ --strip-components=1 -C /opt/vault/node bin/node"
  else
    need xz
    curl -fsSL --proto "=https" --proto-redir "=https" "$NODE_URL" -o "$TMP/node.tar.xz" || die "the Node download failed"
    echo "${NODE_SHA}  $TMP/node.tar.xz" | sha256sum -c --status - || die "the Node tarball's fingerprint does not match the pinned one"
    mkdir -p "$OPT/node"
    tar -xJf "$TMP/node.tar.xz" -C "$OPT/node" --strip-components=1 --no-same-owner "node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/node" \
      "node-v${NODE_VERSION}-linux-${NODE_ARCH}/LICENSE"
    chown -R root:root "$OPT/node"
  fi
fi

if [ "$SKIP_DEPS" -eq 1 ]; then
  say "--skip-deps: not running apt. Install these yourself (Debian/Ubuntu names):"
  say "  apt-get install ${SYSTEM_PACKAGES[*]}"
  say "  ${NODE_BIN} ${HELPER_CLI#"$PREFIX"} install-deps chromium     (the libraries Chromium needs)"
  say "x11vnc is only needed for interactive logins (vault-site interactive); xvfb and acl are needed as well for those and for audit rotation."
else
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found: this installer installs system packages on Debian or Ubuntu only. Install ${SYSTEM_PACKAGES[*]} and the Chromium libraries yourself and run again with --skip-deps"
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${SYSTEM_PACKAGES[@]}"
  # Root runs this Node: a cleaned environment (no NODE_OPTIONS, LD_PRELOAD, ... from the admin's shell), only what apt needs.
  run env -i PATH="$SAFE_PATH" HOME=/root LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive "$NODE_BIN" "$HELPER_CLI" install-deps chromium
fi
[ -n "$PREFIX" ] || command -v setfacl >/dev/null 2>&1 || die "setfacl is missing (package acl): vaultd.socket needs it to give $SVC_NAME access to plugin.sock"

BROWSERS="/var/lib/vault-helper/browsers"
say "installing Chromium as vault-helper into $BROWSERS"
run runuser -u vault-helper -- env -i PATH="$SAFE_PATH" HOME=/var/lib/vault-helper PLAYWRIGHT_BROWSERS_PATH="$BROWSERS" \
  "$NODE_BIN" "$HELPER_CLI" install chromium

# -------------------------------------------------------------------------------------------------- 4. units
sed -e "s|@NODE@|${NODE_BIN}|g" "$OPT/units/vault-helper.service" | put 0644 root:root "$UNITDIR/vault-helper.service"
for u in vaultd.service vault-audit-rotate.service vault-audit-rotate.timer; do
  put 0644 root:root "$UNITDIR/$u" < "$OPT/units/$u"
done
# plugin.sock: created by systemd, 0600 vault:vault, plus an ACL entry for the service user (@SVC@).
sed -e "s|@SVC@|${SVC_NAME}|g" "$OPT/units/vaultd.socket" | put 0644 root:root "$UNITDIR/vaultd.socket"

# Chromium sandbox probe (docs/DESIGN.md section 4): once, as vault-helper, inside a copy of the helper unit (same account and hardening),
# so the answer is the one the helper gets. Exit 0: sandbox works; 3: only without it; 4: neither.
probe_sandbox() {
  PROBE_RESULT=none
  if [ -n "$PREFIX" ]; then
    echo "would run: systemctl start vault-helper-probe.service"
    case "${VAULT_INSTALL_PROBE_RESULT:-on}" in on|off|none) PROBE_RESULT="${VAULT_INSTALL_PROBE_RESULT:-on}" ;; *) die "VAULT_INSTALL_PROBE_RESULT must be on, off or none" ;; esac
    return 0
  fi
  local unit=/etc/systemd/system/vault-helper-probe.service status
  "$PY" -I - "$UNITDIR/vault-helper.service" "$unit" "$NODE_BIN" "$OPT" <<'PY'
import os, sys
src, dst, node, opt = sys.argv[1:5]
drop = ("ExecStart=", "Restart=", "RestartSec=", "RuntimeDirectory", "ImportCredential=", "LoadCredential=", "WorkingDirectory=")
out, section = [], None
for line in open(src).read().splitlines():
    if line.startswith("["):
        section = line
    if section == "[Install]" or line.startswith(drop):
        continue
    if line.startswith("Description="):
        line = "Description=vault-helper Chromium sandbox probe (install-time, removed after use)"
    out.append(line)
    if line == "[Service]":
        out += ["Type=oneshot", "SuccessExitStatus=3", "TimeoutStartSec=240",
                "ExecStart=%s %s/install/probe-chromium.mjs %s/helper/node_modules/playwright-core" % (node, opt, opt)]
with open(dst, "w") as f:
    f.write("\n".join(out) + "\n")
os.chmod(dst, 0o644)
PY
  systemctl daemon-reload
  if systemctl start vault-helper-probe.service; then
    status="$(systemctl show -p ExecMainStatus --value vault-helper-probe.service)"
  else
    status=4
  fi
  case "$status" in
    0) PROBE_RESULT=on ;;
    3) PROBE_RESULT=off ;;
    *) PROBE_RESULT=none; journalctl -u vault-helper-probe.service -n 6 --no-pager -o cat 2>/dev/null | sed 's/^/install-vault:   probe: /' >&2 || true ;;
  esac
  systemctl reset-failed vault-helper-probe.service 2>/dev/null || true
  rm -f "$unit"
  systemctl daemon-reload
}
run systemctl daemon-reload
probe_sandbox
ALLOW_NO_SANDBOX=false
case "$PROBE_RESULT" in
  on) say "Chromium sandbox: active (allowNoSandbox=false)" ;;
  off) ALLOW_NO_SANDBOX=true
       say "Chromium sandbox: NOT available here (user namespaces are restricted); the helper will run Chromium with --no-sandbox (allowNoSandbox=true). Isolation then rests on the vault-helper account, the hardened unit and the allowed-hosts navigation limit." ;;
  none) warn "Chromium does not start in the helper unit, with or without its sandbox. Logins will fail until this is fixed: run 'journalctl -u vault-helper-probe.service' after 'systemctl start vault-helper-probe.service' (it was removed again), or see host/INSTALL.md. Continuing with allowNoSandbox=false." ;;
esac

# -------------------------------------------------------------------------------------------------- 5. configuration
# config.json: plugin_uid from the service user; allowed companies are added to the ones already there.
note_new /etc/vault/config.json
"$PY" -I - "$OPT/config.example.json" "$ETC/config.json" "$SVC_UID" "${COMPANIES[@]+"${COMPANIES[@]}"}" <<'PY'
import json, os, sys
example, target, uid = sys.argv[1], sys.argv[2], int(sys.argv[3])
cfg = json.load(open(target if os.path.exists(target) else example))
cfg["plugin_uid"] = uid
cfg.pop("plugin_group", None)          # earlier builds used a group; plugin.sock is a systemd socket with an ACL entry now
ids = list(cfg.get("allowed_company_ids", []))
for c in sys.argv[4:]:
    if c.lower() not in ids:
        ids.append(c.lower())
cfg["allowed_company_ids"] = ids
tmp = target + ".new"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o640)
os.replace(tmp, target)
PY
run chown root:vault "$ETC/config.json"

# helper.json: only what differs from the helper's defaults. The admin token reaches the unit as a credential (see the unit).
note_new /etc/vault/helper.json
"$PY" -I - "$ETC/helper.json" "$ALLOW_NO_SANDBOX" <<'PY'
import json, os, sys
target, allow = sys.argv[1], sys.argv[2] == "true"
cfg = json.load(open(target)) if os.path.exists(target) else {}
cfg.update({"socketGroup": "vault", "allowNoSandbox": allow,
            "adminTokenFile": "/run/credentials/vault-helper.service/helper-admin.token"})
tmp = target + ".new"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o640)
os.replace(tmp, target)
PY
run chown root:vault "$ETC/helper.json"

# Tokens: 32 random bytes, base64; kept on re-runs. helper.token is vaultd's (0640 root:vault); the admin token is the root
# CLI's (0600 root:root, handed to the helper unit as a credential).
new_token() { # mode owner dest
  if [ -s "$3" ]; then chmod "$1" "$3"; run chown "$2" "$3"; return 0; fi
  note_new "${3#"$R"}"
  head -c 32 /dev/urandom | base64 -w0 | put "$1" "$2" "$3"
}
new_token 0640 root:vault "$ETC/helper.token"
new_token 0600 root:root "$ETC/helper-admin.token"

# systemd credentials: root encrypts (host key), PID 1 decrypts for the unit. VAULT_CREDS_KEY=null is for --prefix tests only.
CREDS_KEY=host
if [ -n "$PREFIX" ] && [ -n "${VAULT_CREDS_KEY:-}" ]; then
  case "$VAULT_CREDS_KEY" in null|host) CREDS_KEY="$VAULT_CREDS_KEY" ;; *) die "VAULT_CREDS_KEY must be null or host" ;; esac
fi
if [ ! -e "$CRED/vault-helper.storekey" ]; then
  if [ -n "$PREFIX" ] && [ -z "${VAULT_CREDS_KEY:-}" ]; then
    echo "would run: head -c32 /dev/urandom | systemd-creds encrypt --with-key=$CREDS_KEY --name=vault-helper.storekey - /etc/credstore.encrypted/vault-helper.storekey"
  else
    head -c 32 /dev/urandom | systemd-creds encrypt --with-key="$CREDS_KEY" --name=vault-helper.storekey - "$CRED/vault-helper.storekey"
    chmod 0600 "$CRED/vault-helper.storekey"
    record "cred:vault-helper.storekey"
  fi
fi

if [ ! -e "$ETC/policy.json" ]; then
  note_new /etc/vault/policy.json
  put 0640 root:vault "$ETC/policy.json" < "$OPT/policy.example.json"
  POLICY_NEW=1
else
  POLICY_NEW=0
fi

# Audit log: vaultd appends to an existing file and never creates one. Mode 0600 vault:vault: vault-helper is in the group vault
# (it reads /etc/vault) and must not read the audit log; the vaultaudit ACL (read) is what rotation and any external log collector use.
# It comes before chattr +a, which freezes ACL and mode changes. vault-audit-rotate lifts the flag for its monthly swap.
if [ ! -e "$LOG/audit.jsonl" ]; then
  note_new /var/log/vault/audit.jsonl
  (umask 077; : > "$LOG/audit.jsonl")
  chmod 0600 "$LOG/audit.jsonl"
  run chown vault:vault "$LOG/audit.jsonl"
  run setfacl -m g:vaultaudit:rx "$LOG"
  run setfacl -d -m g:vaultaudit:r "$LOG"
  run setfacl -m g:vaultaudit:r "$LOG/audit.jsonl"
  run chattr +a "$LOG/audit.jsonl" || warn "could not set the append-only flag on the audit log (this file system may not support it)"
fi

INSTALL_ID=""
for f in "$VARLIB/vault/plugin-key.json" "$ETC/enrol.json"; do
  if [ -z "$INSTALL_ID" ] && [ -f "$f" ]; then
    INSTALL_ID="$("$PY" -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("installId",""))' "$f" 2>/dev/null || true)"
  fi
done
[[ "$INSTALL_ID" =~ ^inst-[0-9a-f]{24}$ ]] || INSTALL_ID="inst-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"

# -------------------------------------------------------------------------------------------------- 6. enrol, start
run systemctl enable vault-helper.service vaultd.socket vaultd.service vault-audit-rotate.timer

# enrol.json: the LAST step before the units start, so the 60 minutes of the code run from here and not from the start of a slow
# apt/Chromium install. Only the hash of the code is stored, never the code. A new code replaces the trusted plugin key (key
# rotation). vaultd never deletes this file (/etc is read-only to it): single use is enforced by the code hash it stores with the
# enrolled key.
if [ -n "$CODE" ]; then
  note_new /etc/vault/enrol.json
  printf '%s' "$CODE" | "$PY" -I -c '
import hashlib, json, os, re, sys, datetime
target, install_id, uid = sys.argv[1], sys.argv[2], int(sys.argv[3])
code = re.sub(r"[^A-Z0-9]", "", sys.stdin.read().upper())
exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)
rec = {"installId": install_id, "codeHash": hashlib.sha256(("pcvault-enrol:" + code).encode()).hexdigest(),
       "expiresAt": exp.strftime("%Y-%m-%dT%H:%M:%SZ"), "serviceUid": uid}
tmp = target + ".new"
with open(tmp, "w") as f:
    json.dump(rec, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o640)
os.replace(tmp, target)
' "$ETC/enrol.json" "$INSTALL_ID" "$SVC_UID"
  run chown root:vault "$ETC/enrol.json"
fi
CODE=""

run systemctl restart vault-helper.service
run systemctl restart vaultd.socket
run systemctl restart vaultd.service
run systemctl start vault-audit-rotate.timer
if [ -n "$PREFIX" ]; then
  echo "would run: wait for /run/vault/plugin.sock (up to 60 s)"
else
  for _ in $(seq 1 60); do [ -S /run/vault/plugin.sock ] && break; sleep 1; done
  [ -S /run/vault/plugin.sock ] || die "systemd did not create /run/vault/plugin.sock; see: journalctl -u vaultd.socket -u vaultd -n 30"
  systemctl is-active --quiet vault-helper.service || warn "vault-helper is not running; see: journalctl -u vault-helper -n 30"
fi

say "installed paperclip-vault ${VERSION}"
echo "fingerprint (sha256 of the host bundle): ${BUNDLE_SHA256}"
echo "install id: ${INSTALL_ID}"
if [ "$POLICY_NEW" -eq 1 ]; then
  echo "A starter /etc/vault/policy.json was written with placeholder agent ids: pin your agents' UUIDs to roles there (sudo -e /etc/vault/policy.json), then: sudo systemctl restart vaultd"
fi
if [ "${#COMPANIES[@]}" -eq 0 ] && [ "$FIRST" -eq 1 ]; then
  echo "No --company was given: allow a company with: sudo vaultctl company add <company-uuid>"
fi
echo "Waiting for the plugin to complete the enrolment (up to 60 minutes); nothing more to do here. Check the Install tab in Paperclip."
echo "Next: add a site with the Sites tab (it builds a 'sudo vault-site add ...' command), see https://github.com/tomRumi/paperclip-vault"
