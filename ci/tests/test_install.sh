#!/usr/bin/env bash
# Board for settings/install.sh. Installs into two temporary folders (the SDG_*
# overrides), never into a system path, and needs no root.
#
#   bash ci/tests/test_install.sh
#
# The contract under test: a missing dependency stops the installer BEFORE anything
# is copied, so a failed install leaves no half-active hooks behind.

set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
INSTALLER="${INSTALLER_UNDER_TEST:-$REPO/settings/install.sh}"
PASS=0
FAIL=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "PASS  $1"; else FAIL=$((FAIL + 1)); echo "FAIL  $1: got '$2', want '$3'"; fi; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/sdg-install.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# A PATH holding only what the installer uses, so gitleaks can be present or absent
# on purpose whatever this machine has installed.
bindir() {
  local d="$TMP/$1"; mkdir -p "$d"
  for t in bash sh jq dirname uname install mkdir id cat rm; do
    p=$(command -v "$t") && ln -sf "$p" "$d/$t"
  done
  p=$(command -v python3) && ln -sf "$p" "$d/python3"
  echo "$d"
}

run_install() { # <bindir> <home> <managed>
  env -i HOME="$TMP" PATH="$1" SDG_GUARDRAILS_HOME="$2" SDG_MANAGED_DIR="$3" \
    bash "$INSTALLER" > "$TMP/out" 2>&1
}

# --- no gitleaks: refused, nothing written
B=$(bindir nogl)
run_install "$B" "$TMP/home1" "$TMP/managed1"; rc=$?
check "no gitleaks: the installer fails" "$rc" 1
check "no gitleaks: the hooks folder was not created" "$([ -e "$TMP/home1" ] && echo yes || echo no)" no
check "no gitleaks: managed settings were not written" "$([ -e "$TMP/managed1/managed-settings.json" ] && echo yes || echo no)" no
check "no gitleaks: the output names gitleaks" "$(grep -c gitleaks "$TMP/out" | tr -d ' ')" 1

# --- gitleaks present (a stub): installed and verified
B=$(bindir withgl)
printf '#!/bin/sh\nexit 0\n' > "$B/gitleaks"; chmod +x "$B/gitleaks"
run_install "$B" "$TMP/home2" "$TMP/managed2"; rc=$?
check "all present: the installer succeeds" "$rc" 0
check "all present: managed settings written" "$([ -f "$TMP/managed2/managed-settings.json" ] && echo yes || echo no)" yes
check "all present: the secret-scan hook installed" "$([ -x "$TMP/home2/hooks/secret-scan.sh" ] && echo yes || echo no)" yes
check "all present: the parser helper installed" "$([ -f "$TMP/home2/hooks/_bash_command_parse.py" ] && echo yes || echo no)" yes

echo
echo "selftest: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
