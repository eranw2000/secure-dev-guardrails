#!/bin/bash
# Installs the secure-dev-guardrails hooks and the enterprise managed-settings policy so every
# developer's Claude Code runs the security/privacy hooks and cannot disable them.
#
# Run by IT / MDM with admin rights (the managed-settings path is root-owned by design). For a
# fleet, push this via your MDM (Jamf, Intune, Ansible) rather than asking each developer to run it.
#
# Usage:  sudo ./install.sh            # install/update
#         sudo ./install.sh --verify   # check installation without changing anything
#         sudo ./install.sh --uninstall

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# The two SDG_* variables exist for the installer's own test, which installs into a
# temporary folder. `sudo` drops them by default, so a real install uses the paths below.
GUARDRAILS_HOME="${SDG_GUARDRAILS_HOME:-/usr/local/share/secure-dev-guardrails}"

# OS-specific managed-settings location (highest precedence, non-overridable).
case "$(uname -s)" in
  Darwin) MANAGED_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux)  MANAGED_DIR="/etc/claude-code" ;;
  *)      echo "Unsupported OS for this installer. On Windows install to C:\\ProgramData\\ClaudeCode\\managed-settings.json" >&2; exit 1 ;;
esac
MANAGED_DIR="${SDG_MANAGED_DIR:-$MANAGED_DIR}"
MANAGED_FILE="$MANAGED_DIR/managed-settings.json"

# The interpreter the secret-scan hook will pick: the python3 on PATH, else
# /usr/bin/python3. Checked here with the same rule, and it must actually run.
hook_python() {
  command -v python3 2>/dev/null || { [ -x /usr/bin/python3 ] && echo /usr/bin/python3; } || true
}

# Everything the hooks need, checked BEFORE anything is copied or activated, so a
# failed check leaves the machine exactly as it was.
preflight() {
  local bad=0 py
  command -v jq >/dev/null 2>&1 || { echo "MISSING: jq (the hooks read their input with it)" >&2; bad=1; }
  command -v gitleaks >/dev/null 2>&1 || { echo "MISSING: gitleaks (the secret scan runs it on every commit and push)" >&2; bad=1; }
  py=$(hook_python)
  if [ -z "$py" ] || ! "$py" -c 'import sys' >/dev/null 2>&1; then
    echo "MISSING: a working python3 (tried ${py:-none})" >&2; bad=1
  fi
  if ! jq -e . "$REPO_DIR/settings/managed-settings.json" >/dev/null 2>&1; then
    echo "BROKEN: $REPO_DIR/settings/managed-settings.json is missing or not valid JSON" >&2; bad=1
  fi
  compgen -G "$REPO_DIR/standards/*" >/dev/null || { echo "MISSING: standards files under $REPO_DIR/standards" >&2; bad=1; }
  if [ "$bad" != 0 ]; then
    echo "Nothing was installed. Fix the items above and re-run." >&2
    exit 1
  fi
}

verify() {
  local ok=0
  echo "Guardrails home: $GUARDRAILS_HOME"
  for h in secret-scan.sh pii-in-logs.sh sensitive-file-context.sh dangerous-pattern-warn.sh; do
    if [ -x "$GUARDRAILS_HOME/hooks/$h" ]; then echo "  ok   hook $h"; else echo "  MISS hook $h"; ok=1; fi
  done
  for h in secret-scan-git.py _bash_command_parse.py _bash_write_targets.py _pii_bash_lines.py _shell_secret_argv.py; do
    if [ -f "$GUARDRAILS_HOME/hooks/$h" ]; then echo "  ok   helper $h"; else echo "  MISS helper $h"; ok=1; fi
  done
  if [ -f "$MANAGED_FILE" ]; then echo "  ok   managed settings at $MANAGED_FILE"; else echo "  MISS managed settings at $MANAGED_FILE"; ok=1; fi
  command -v jq >/dev/null 2>&1 && echo "  ok   jq present" || { echo "  MISS jq (hooks need it)"; ok=1; }
  command -v gitleaks >/dev/null 2>&1 && echo "  ok   gitleaks present" || { echo "  MISS gitleaks (every commit and push is blocked until it is installed)"; ok=1; }
  local py; py=$(hook_python)
  if [ -n "$py" ] && "$py" -c 'import sys' >/dev/null 2>&1; then echo "  ok   python3 at $py"; else echo "  MISS a working python3 (tried ${py:-none})"; ok=1; fi
  return $ok
}

require_root() {
  # A test install into two temporary folders needs no root; a real one always does.
  if [ -n "${SDG_GUARDRAILS_HOME:-}" ] && [ -n "${SDG_MANAGED_DIR:-}" ]; then return 0; fi
  [ "$(id -u)" -eq 0 ] || { echo "This action writes to root-owned system paths; re-run with sudo." >&2; exit 1; }
}

uninstall() {
  require_root
  rm -f "$MANAGED_FILE"
  rm -rf "$GUARDRAILS_HOME"
  echo "Removed managed settings and $GUARDRAILS_HOME."
}

case "${1:-}" in
  --verify) verify; exit $? ;;
  --uninstall) uninstall; exit 0 ;;
esac

require_root
preflight

# Install hooks + standards (standards are read by the hooks' sibling skills and CI).
mkdir -p "$GUARDRAILS_HOME/hooks" "$GUARDRAILS_HOME/standards"
install -m 0755 "$REPO_DIR/hooks/"*.sh "$GUARDRAILS_HOME/hooks/"
# The Python helpers the shell hooks call. Without secret-scan-git.py every commit and
# push is blocked, because a scan that did not run must never read as a clean one.
install -m 0644 "$REPO_DIR/hooks/"*.py "$GUARDRAILS_HOME/hooks/"
install -m 0644 "$REPO_DIR/standards/"* "$GUARDRAILS_HOME/standards/"

# Install managed settings last: this is the step that turns the hooks on.
mkdir -p "$MANAGED_DIR"
install -m 0644 "$REPO_DIR/settings/managed-settings.json" "$MANAGED_FILE"

echo "Installed. Verifying:"
verify || { echo "Verification reported missing items above." >&2; exit 1; }
echo
echo "Done. Claude Code will load these hooks on next launch and developers cannot override them."
