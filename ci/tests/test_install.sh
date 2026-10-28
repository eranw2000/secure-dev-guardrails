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
for h in destructive-command-guard.py write-then-remote-guard.py chain-abort-guard.py shell-status-guard.py; do
  check "all present: $h installed" "$([ -f "$TMP/home2/hooks/$h" ] && echo yes || echo no)" yes
  check "all present: managed settings run $h on Bash through python3" "$(jq -r --arg c "python3 $TMP/home2/hooks/$h" '[.hooks.PreToolUse[] | select(.matcher == "Bash") | .hooks[] | select(.type == "command" and .command == $c)] | length' "$TMP/managed2/managed-settings.json")" 1
done

run_verify() { # <bindir> <home> <managed>
  env -i HOME="$TMP" PATH="$1" SDG_GUARDRAILS_HOME="$2" SDG_MANAGED_DIR="$3" \
    bash "$INSTALLER" --verify > "$TMP/vout" 2>&1
}

# --- --verify reads the REGISTRATIONS, not just the files
run_verify "$B" "$TMP/home2" "$TMP/managed2"; rc=$?
check "verify on a good install succeeds" "$rc" 0
check "verify names each Python hook as registered and running" "$(grep -c '^  ok   runs ' "$TMP/vout" | tr -d ' ')" 4
check "verify checks all ten registrations" "$(grep -c '^  ok   registered ' "$TMP/vout" | tr -d ' ')" 10

M="$TMP/managed2/managed-settings.json"
cp "$M" "$TMP/good.json"
jq --arg c "python3 $TMP/home2/hooks/chain-abort-guard.py" '.hooks.PreToolUse |= map(.hooks |= map(select(.command != $c)))' "$TMP/good.json" > "$M"
run_verify "$B" "$TMP/home2" "$TMP/managed2"; rc=$?
check "verify fails when a hook file is present but unregistered" "$rc" 1
check "verify names the missing registration" "$(grep -c 'MISS registration PreToolUse \[Bash\] python3 .*chain-abort-guard.py' "$TMP/vout" | tr -d ' ')" 1

jq --arg c "python3 $TMP/home2/hooks/shell-status-guard.py" --arg n "$TMP/home2/hooks/shell-status-guard.py" '.hooks.PreToolUse |= map(.hooks |= map(if .command == $c then .command = $n else . end))' "$TMP/good.json" > "$M"
run_verify "$B" "$TMP/home2" "$TMP/managed2"; rc=$?
check "verify fails when a Python hook is registered without python3" "$rc" 1

jq --arg c "python3 $TMP/home2/hooks/destructive-command-guard.py" '.hooks.PostToolUse += [{"matcher": "Bash", "hooks": [{"type": "command", "command": $c}]}] | .hooks.PreToolUse |= map(.hooks |= map(select(.command != $c)))' "$TMP/good.json" > "$M"
run_verify "$B" "$TMP/home2" "$TMP/managed2"; rc=$?
check "verify fails when a hook sits on the wrong event" "$rc" 1

cp "$TMP/good.json" "$M"
printf 'raise SystemExit(3)\n' > "$TMP/home2/hooks/write-then-remote-guard.py"
run_verify "$B" "$TMP/home2" "$TMP/managed2"; rc=$?
check "verify fails when a registered hook does not run cleanly" "$rc" 1
check "verify names the hook that did not run" "$(grep -c 'MISS runs     write-then-remote-guard.py' "$TMP/vout" | tr -d ' ')" 1

echo
echo "selftest: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
