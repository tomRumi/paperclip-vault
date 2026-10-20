#!/usr/bin/env bash
# test-all.sh: THE test command. `npm test` at the repository root runs this script; run it from anywhere.
#
#   bash scripts/test-all.sh
#
# Stages, in order (each prints PASS / FAIL / SKIP with its test counts; the exit status is non-zero if any stage failed):
#   vaultd unit tests        python3 -I -B -m unittest discover -s host/tests
#   judge prompt dry-run     host/judge-tests/score.py --dry-run
#   judge oracle             host/judge-tests/score.py --oracle        (must PASS: the scoring code and the scenarios agree)
#   plugin tests             plugin: npm test
#   helper tests             host/helper: npm test   (real headless Chromium against the fake login site and OAuth provider)
#   installer tests          python3 -I -B -m unittest discover -s tests/install
#   end to end               python3 -I -B -m unittest discover -s tests/e2e   (real vaultd + helper + plugin worker logic)
#   scrub grep               no CGNAT addresses, e-mail addresses, /home/<name>/ paths, real UUIDs or key/token patterns
#
# Before the stages: `npm ci --ignore-scripts` in plugin/ and host/helper/ when their node_modules are missing (committed lock
# files), and a check that the Chromium revision playwright-core wants is installed. Without it the run FAILS and says how to
# install it (in host/helper: npx playwright-core install chromium), unless SKIP_BROWSER=1, which skips the browser suites loudly.
#
# Environment: PLAYWRIGHT_BROWSERS_PATH (default ~/.cache/ms-playwright), SKIP_BROWSER=1, KEEP_SCRATCH=1 (keep the scratch
# directory and the per-stage logs). Needs no root. Writes only below one mktemp scratch directory (and node_modules, once);
# the unit tests also use short /tmp/<prefix>* directories for Unix sockets and remove them. The installer tests download
# the npm packages through npm (cache or network) while building a release.
# The suite is heavy (Chromium, `npm ci` twice): on a shared host run it as `flock <job lock> bash scripts/test-all.sh`.
set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/pcvault-test.XXXXXX")" || { echo "test-all: cannot create a scratch directory" >&2; exit 2; }
LOGS="$SCRATCH/logs"
mkdir -p "$LOGS"
cleanup() {
  if [ "${KEEP_SCRATCH:-0}" = 1 ]; then echo "scratch kept: $SCRATCH"; else rm -rf "$SCRATCH"; fi
}
trap cleanup EXIT
trap 'echo; echo "test-all: interrupted" >&2; exit 130' INT TERM

export TMPDIR="$SCRATCH" VAULT_TEST_SCRATCH="$SCRATCH" PYTHONDONTWRITEBYTECODE=1
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
SKIP_BROWSER="${SKIP_BROWSER:-0}"
[ "$SKIP_BROWSER" = 1 ] && export SKIP_BROWSER

NAMES=() RESULTS=() DETAILS=()
FAILED=0
record() { NAMES+=("$1"); RESULTS+=("$2"); DETAILS+=("$3"); [ "$2" = FAIL ] && FAILED=1; return 0; }

# ---- count extraction from a stage log -----------------------------------------------------------------------------------
count_unittest() {
  local ran skipped
  ran="$(sed -n 's/^Ran \([0-9]*\) tests\{0,1\} in .*/\1/p' "$1" | tail -1)"
  skipped="$(grep -aoE 'skipped=[0-9]+' "$1" | tail -1 | cut -d= -f2)"
  echo "${ran:-?} tests${skipped:+, $skipped skipped}"
}
count_node() {
  awk '/^ℹ tests /{t=$3} /^ℹ pass /{p=$3} /^ℹ fail /{f=$3} /^ℹ skipped /{s=$3}
       END{printf "%s tests, %s passed, %s failed, %s skipped", t+0, p+0, f+0, s+0}' "$1"
}
count_plain() { echo "$(tail -1 "$1" | cut -c1-100)"; }

# ---- running a stage -----------------------------------------------------------------------------------------------------
# run_stage <name> <counter function> <command...>: output goes to a log; on failure its tail is shown.
run_stage() {
  local name="$1" counter="$2"; shift 2
  local log="$LOGS/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').log" rc started="$SECONDS"
  printf '==> %s ...\n' "$name"
  "$@" >"$log" 2>&1
  rc=$?
  local detail; detail="$("$counter" "$log"), $((SECONDS - started))s"
  if [ "$rc" -eq 0 ]; then
    printf '    PASS  %s\n' "$detail"
    record "$name" PASS "$detail"
  else
    printf '    FAIL  (exit %s)  %s\n' "$rc" "$detail"
    echo "    ---- last 60 lines of the output ----"
    tail -60 "$log" | sed 's/^/    | /'
    echo "    -------------------------------------"
    record "$name" FAIL "exit $rc, $detail"
  fi
}

skip_stage() { # <name> <reason>
  printf '==> %s\n    SKIP  %s\n' "$1" "$2"
  record "$1" SKIP "$2"
}

# ---- prerequisites -------------------------------------------------------------------------------------------------------
need_tools() {
  local missing=0 t
  for t in python3 node npm; do command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; missing=1; }; done
  return "$missing"
}

install_deps() {
  local d
  for d in plugin host/helper; do
    if [ -d "$d/node_modules" ]; then
      echo "$d: node_modules present"
    else
      echo "$d: npm ci --ignore-scripts"
      (cd "$d" && npm ci --ignore-scripts --no-audit --no-fund) || return 1
    fi
  done
  echo "dependencies ready: plugin, host/helper"
}

# Is the Chromium revision that host/helper's playwright-core wants installed under PLAYWRIGHT_BROWSERS_PATH?
chromium_installed() {
  (cd host/helper && node --input-type=module -e "
    import fs from 'node:fs';
    import { chromium } from 'playwright-core';
    process.exit(fs.existsSync(chromium.executablePath()) ? 0 : 1);") >/dev/null 2>&1
}

print_chromium_help() {
  cat <<EOF
    Chromium is not installed under PLAYWRIGHT_BROWSERS_PATH=$PLAYWRIGHT_BROWSERS_PATH.
    Install the revision this repository's playwright-core wants (a download; not done by this script):
        cd host/helper && PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" npx playwright-core install chromium
    (a bare host also needs the system libraries: npx playwright-core install-deps chromium, as root)
    or run without the browser suites: SKIP_BROWSER=1 bash scripts/test-all.sh
EOF
}

# ---- scrub grep ----------------------------------------------------------------------------------------------------------
# Generic checks for anything that must not ship in a public repository, over every file except node_modules, dist, .git and
# this script (which has to spell the patterns out). Token and key findings are reported as file:line only, never the text.
scrub() {
  local list="$SCRATCH/scrub-files" bad=0 n out
  find . -type f -not -path '*/node_modules/*' -not -path '*/dist/*' -not -path './.git/*' -not -path '*/__pycache__/*' \
       -not -path './scripts/test-all.sh' -print0 >"$list"
  n="$(tr -cd '\0' <"$list" | wc -c)"
  g() { xargs -0 -a "$list" grep -I "$@" 2>/dev/null; }

  out="$(g -nE '(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)')"
  [ -n "$out" ] && { echo "CGNAT (100.64.0.0/10) address:"; echo "$out" | cut -c1-200; bad=1; }

  out="$(g -noE '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' \
        | grep -vE '(noreply@|@([a-z0-9-]+\.)*example\.(org|com|net|test)$|@localhost$|@placeholder(\.[a-z]+)?$)')"
  [ -n "$out" ] && { echo "e-mail address (only noreply and example.* / placeholder forms are allowed):"; echo "$out" | cut -c1-200; bad=1; }

  out="$(g -noE '/home/[A-Za-z0-9._-]+/' | grep -vE ':/home/(user|you|me|name|example|svc|vault|username|<[^>]*>)/$')"
  [ -n "$out" ] && { echo "/home/<name>/ path:"; echo "$out" | cut -c1-200; bad=1; }

  # a UUID is a placeholder when its first group is one character repeated (aaaaaaaa-0000-..., 11111111-1111-...)
  out="$(g -noE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | grep -vE ':([0-9a-fA-F])\1{7}-')"
  [ -n "$out" ] && { echo "non-placeholder UUID:"; echo "$out" | cut -c1-200; bad=1; }

  out="$(g -nE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' -e 'gh[pousr]_[A-Za-z0-9]{30,}' -e 'github_pat_[A-Za-z0-9_]{20,}' \
        -e 'sk-(or-v1-|ant-)?[A-Za-z0-9_-]{32,}' -e 'xox[abprs]-[A-Za-z0-9-]{10,}' -e 'AKIA[0-9A-Z]{16}' -e 'AIza[0-9A-Za-z_-]{35}' \
        -e 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}' | cut -d: -f1,2)"
  [ -n "$out" ] && { echo "private key or token pattern (file:line):"; echo "$out"; bad=1; }

  echo "scrub: $n files scanned, $([ "$bad" = 0 ] && echo 'no findings' || echo 'FINDINGS above')"
  return "$bad"
}
count_scrub() { tail -1 "$1" | sed 's/^scrub: //'; }

# ---- go ------------------------------------------------------------------------------------------------------------------
echo "paperclip-vault test suite  (scratch: $SCRATCH)"
PREREQ=1
if ! need_tools; then record "tools" FAIL "python3, node and npm are required"; PREREQ=0; fi
if [ "$PREREQ" = 1 ]; then
  run_stage "dependencies" count_plain install_deps
  [ "${RESULTS[${#RESULTS[@]}-1]}" = PASS ] || PREREQ=0
fi

BROWSER=1   # can the browser suites run?
if [ "$SKIP_BROWSER" = 1 ]; then
  BROWSER=0
  echo "!!  SKIP_BROWSER=1: the helper's browser tests and the end-to-end suite are SKIPPED, not run  !!"
elif [ "$PREREQ" = 1 ]; then
  printf '==> Chromium prerequisite\n'
  if chromium_installed; then
    printf '    PASS  found under %s\n' "$PLAYWRIGHT_BROWSERS_PATH"
    record "Chromium prerequisite" PASS "found"
  else
    printf '    FAIL  not installed\n'
    print_chromium_help
    record "Chromium prerequisite" FAIL "not installed"
    BROWSER=0
  fi
fi

if [ "$PREREQ" = 0 ]; then
  echo "test-all: prerequisites failed, no test stage was run"
else
  # test_helper_e2e.py drives the real helper and needs Chromium; every other vaultd test runs without it
  if [ "$BROWSER" = 1 ]; then VAULTD_PATTERN='test*.py'; else VAULTD_PATTERN='test_[!h]*.py'; fi
  run_stage "vaultd unit tests" count_unittest python3 -I -B -m unittest discover -s host/tests -p "$VAULTD_PATTERN"
  [ "$BROWSER" = 0 ] && echo "    (test_helper_e2e.py left out: it needs Chromium)"
  run_stage "judge prompt dry-run" count_plain python3 -I -B host/judge-tests/score.py --dry-run
  run_stage "judge oracle" count_plain python3 -I -B host/judge-tests/score.py --oracle
  run_stage "plugin tests" count_node bash -c 'cd plugin && npm test --silent'
  if [ "$BROWSER" = 1 ] || [ "$SKIP_BROWSER" = 1 ]; then
    # under SKIP_BROWSER=1 the suite itself skips its browser tests and counts them as skipped
    run_stage "helper tests" count_node bash -c 'cd host/helper && npm test --silent'
  else
    skip_stage "helper tests" "needs Chromium (not installed)"
  fi
  run_stage "installer tests" count_unittest python3 -I -B -m unittest discover -s tests/install
  if [ "$BROWSER" = 1 ]; then
    run_stage "end to end" count_unittest python3 -I -B -m unittest discover -s tests/e2e
  elif [ "$SKIP_BROWSER" = 1 ]; then
    skip_stage "end to end" "SKIP_BROWSER=1 (needs Chromium)"
  else
    skip_stage "end to end" "needs Chromium (not installed)"
  fi
  run_stage "scrub grep" count_scrub scrub
fi

# ---- summary -------------------------------------------------------------------------------------------------------------
echo
echo "================ summary ================"
for i in "${!NAMES[@]}"; do printf '  %-4s  %-26s %s\n' "${RESULTS[$i]}" "${NAMES[$i]}" "${DETAILS[$i]}"; done
echo "========================================="
if [ "$FAILED" = 0 ]; then
  if printf '%s\n' "${RESULTS[@]}" | grep -q SKIP; then echo "RESULT: PASS (with skipped stages: see SKIP above)"; else echo "RESULT: PASS"; fi
  exit 0
fi
echo "RESULT: FAIL"
exit 1
