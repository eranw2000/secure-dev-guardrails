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
GUARDRAILS_HOME="/usr/local/share/secure-dev-guardrails"

# OS-specific managed-settings location (highest precedence, non-overridable).
case "$(uname -s)" in
  Darwin) MANAGED_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux)  MANAGED_DIR="/etc/claude-code" ;;
  *)      echo "Unsupported OS for this installer. On Windows install to C:\\ProgramData\\ClaudeCode\\managed-settings.json" >&2; exit 1 ;;
esac
MANAGED_FILE="$MANAGED_DIR/managed-settings.json"

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
  return $ok
}

require_root() {
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

# Install hooks + standards (standards are read by the hooks' sibling skills and CI).
mkdir -p "$GUARDRAILS_HOME/hooks" "$GUARDRAILS_HOME/standards"
install -m 0755 "$REPO_DIR/hooks/"*.sh "$GUARDRAILS_HOME/hooks/"
# The Python helpers the shell hooks call. Without secret-scan-git.py every commit and
# push is blocked, because a scan that did not run must never read as a clean one.
install -m 0644 "$REPO_DIR/hooks/"*.py "$GUARDRAILS_HOME/hooks/"
if compgen -G "$REPO_DIR/standards/*" >/dev/null; then
  install -m 0644 "$REPO_DIR/standards/"* "$GUARDRAILS_HOME/standards/"
else
  echo "ERROR: no standards files found under $REPO_DIR/standards; refusing a partial install." >&2
  exit 1
fi

# Install managed settings.
mkdir -p "$MANAGED_DIR"
install -m 0644 "$REPO_DIR/settings/managed-settings.json" "$MANAGED_FILE"

echo "Installed. Verifying:"
verify || { echo "Verification reported missing items above." >&2; exit 1; }
echo
echo "Done. Claude Code will load these hooks on next launch and developers cannot override them."
echo "If gitleaks was reported missing, install it now (brew install gitleaks / apt): until then every commit and push through Claude Code is blocked."
