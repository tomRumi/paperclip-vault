#!/usr/bin/env bash
# release.sh: build the release assets (publishes nothing).
#
#   scripts/release.sh --version 0.1.0 [--org <github account>] [--base-url URL] [--out DIR]
#
# Writes into --out (default ./dist, kept out of git):
#   paperclip-vault-host-<version>.tar.gz   /opt/vault content: vaultd, helper (with its production node_modules from
#                                           `npm ci --omit=dev --ignore-scripts`), bin, sbin, units, judge-tests, the example
#                                           configs, the install-time Chromium probe. Reproducible: sorted, mtime 0, owner 0,
#                                           gzip -n (the same sources and the same lock files give the same bytes)
#   install-vault.sh                        host/install/install-vault.sh with the version, the download URL, the bundle's
#                                           sha256 and the pinned Node (scripts/node-pin.env) filled in
#   paperclip-vault-plugin-<version>.tgz    the plugin directory (extracts to plugin/), its production dependencies installed
#                                           the same way, and src/release-pins.json filled in: {version, baseUrl,
#                                           installVaultSha256}. The working tree's release-pins.json is never touched.
#   SHA256SUMS                              all of the above
# The download URL defaults to https://github.com/<org>/paperclip-vault/releases/download/v<version>/ (<org> = --org,
# default tomRumi). file:// is accepted for tests; the installer itself only accepts it together with --prefix.
# Needs bash, tar, gzip, sha256sum, python3 and npm (network for `npm ci`, unless the npm cache has the packages).
set -euo pipefail
umask 022
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="" ORG="tomRumi" BASE_URL="" OUT="$HERE/dist"
die() { echo "release: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --org) ORG="${2:-}"; shift 2 ;;
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version X.Y.Z is required"
if [ -z "$BASE_URL" ]; then
  [[ "$ORG" =~ ^[A-Za-z0-9-]{1,39}$ ]] || die "--org must be a GitHub account or organisation name"
  BASE_URL="https://github.com/${ORG}/paperclip-vault/releases/download/v${VERSION}/"
fi
case "$BASE_URL" in */) ;; *) BASE_URL="$BASE_URL/" ;; esac
[[ "$BASE_URL" =~ ^(https|file)://[A-Za-z0-9._~/:-]*$ ]] || die "--base-url must be an https:// URL (file:// for tests)"
for c in tar gzip sha256sum python3 npm sed find; do command -v "$c" >/dev/null || die "missing command: $c"; done

# The Node the installer vendors on hosts without a root-owned Node >= 24.
NODE_VERSION="" NODE_X64_SHA256="" NODE_ARM64_SHA256=""
# shellcheck source=scripts/node-pin.env
. "$HERE/scripts/node-pin.env"
[[ "$NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "scripts/node-pin.env: bad NODE_VERSION"
[[ "$NODE_X64_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "scripts/node-pin.env: bad NODE_X64_SHA256"
[[ "$NODE_ARM64_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "scripts/node-pin.env: bad NODE_ARM64_SHA256"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Production dependencies from the lock file, no install scripts (nothing from the network runs on the builder).
install_deps() { # dir
  (cd "$1" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error)
  # node_modules/.bin holds symlinks (the installer refuses links in the bundle) and .package-lock.json is npm's cache of itself.
  rm -rf "$1/node_modules/.bin" "$1/node_modules/.package-lock.json"
  find "$1/node_modules" -name .bin -type d -prune -exec rm -rf {} +
  if find "$1" -type l | grep -q .; then die "symbolic links in $1 after npm ci"; fi
}

# Copy a directory without tests, caches and node_modules.
copy_tree() { # src dst [extra tar args...]
  local src="$1" dst="$2"; shift 2
  mkdir -p "$dst"
  tar -C "$src" --exclude='./node_modules' --exclude='./test' --exclude='./tests' --exclude='__pycache__' --exclude='*.pyc' "$@" -cf - . | tar -C "$dst" -xf -
}

normalize() { # dir: no write for group/other, no setuid bits, stable
  chmod -R u=rwX,go=rX "$1"
}

# --- the host bundle
B="$STAGE/paperclip-vault-host"
mkdir -p "$B"
H="$HERE/host"
copy_tree "$H/vaultd" "$B/vaultd"
copy_tree "$H/helper" "$B/helper"
copy_tree "$H/bin" "$B/bin"
copy_tree "$H/sbin" "$B/sbin"
copy_tree "$H/units" "$B/units"
copy_tree "$H/judge-tests" "$B/judge-tests"
[ ! -d "$H/sites.example" ] || copy_tree "$H/sites.example" "$B/sites.example"
mkdir -p "$B/install"
cp "$H/install/probe-chromium.mjs" "$B/install/"
cp "$H/config.example.json" "$H/policy.example.json" "$H/README.md" "$H/INSTALL.md" "$B/"
echo "$VERSION" > "$B/VERSION"
[ -f "$B/helper/package-lock.json" ] || die "host/helper/package-lock.json is missing"
install_deps "$B/helper"
chmod 0755 "$B"/bin/* "$B"/sbin/*
normalize "$B"
BUNDLE="paperclip-vault-host-${VERSION}.tar.gz"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - paperclip-vault-host | gzip -n -9 > "$OUT/$BUNDLE"
BUNDLE_SHA="$(sha256sum "$OUT/$BUNDLE" | cut -d' ' -f1)"

# --- the installer with its pins
INSTALLER="$OUT/install-vault.sh"
sed -e "s|__VERSION__|${VERSION}|g" -e "s|__BASE_URL__|${BASE_URL}|g" -e "s|__BUNDLE_SHA256__|${BUNDLE_SHA}|g" \
    -e "s|__NODE_VERSION__|${NODE_VERSION}|g" -e "s|__NODE_X64_SHA256__|${NODE_X64_SHA256}|g" -e "s|__NODE_ARM64_SHA256__|${NODE_ARM64_SHA256}|g" \
    "$H/install/install-vault.sh" > "$INSTALLER"
chmod 0755 "$INSTALLER"
if grep -q '__[A-Z0-9_]*__' "$INSTALLER"; then die "unfilled placeholder in $INSTALLER"; fi
bash -n "$INSTALLER" || die "syntax error in $INSTALLER"
INSTALLER_SHA="$(sha256sum "$INSTALLER" | cut -d' ' -f1)"

# --- the plugin, with the release pins inside the tarball only
P="$STAGE/plugin"
mkdir -p "$P"
cp -r "$HERE/plugin/src" "$HERE/plugin/scripts" "$P/"
cp "$HERE/plugin/package.json" "$HERE/plugin/package-lock.json" "$HERE/plugin/README.md" "$P/"
find "$P" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} +
python3 -I - "$P/src/release-pins.json" "$VERSION" "$BASE_URL" "$INSTALLER_SHA" <<'PY'
import json, os, sys
path, version, base, sha = sys.argv[1:5]
pins = {"comment": "Written by scripts/release.sh. The Install tab shows the one-line commands from these values.",
        "version": version, "baseUrl": base, "installVaultSha256": sha}
with open(path, "w") as f:
    json.dump(pins, f, indent=2)
    f.write("\n")
PY
install_deps "$P"
normalize "$P"
PLUGIN="paperclip-vault-plugin-${VERSION}.tgz"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - plugin | gzip -n -9 > "$OUT/$PLUGIN"

(cd "$OUT" && sha256sum "$BUNDLE" install-vault.sh "$PLUGIN" > SHA256SUMS)

cat <<EOF
release ${VERSION} built in ${OUT} (nothing published)
download URL: ${BASE_URL}
for the release notes:
  ${INSTALLER_SHA}  install-vault.sh
  ${BUNDLE_SHA}  ${BUNDLE}
  $(sha256sum "$OUT/$PLUGIN" | cut -d' ' -f1)  ${PLUGIN}
EOF
