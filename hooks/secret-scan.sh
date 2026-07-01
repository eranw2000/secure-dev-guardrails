#!/bin/bash
# Hard-block hook. Enforces SEC-SECRET-01 and SEC-SECRET-02.
#
# Wired as a PreToolUse hook on both Edit/Write and Bash:
#   - Edit/Write: scans the content about to be written for hardcoded credentials and blocks
#     the write before it lands. Also blocks creating credential-bearing files (.env, *.pem,
#     keys, service-account JSON).
#   - Bash: when the command is `git commit` or `git push`, runs gitleaks against the staged
#     changes (if gitleaks is installed) and blocks the commit/push on a finding. If gitleaks
#     is absent it warns instead of blocking, since CI is the backstop.
#
# Protocol: read JSON from stdin, emit JSON to stdout, exit 0. To block, emit decision:"block"
# + hookSpecificOutput.permissionDecision:"deny" (mirrors block-git-push-main.sh).
#
# Bypass for a genuine false positive: append #allow-secret to the command/edit is NOT honored
# here on purpose. Suppress via standards/baseline.yml (owner + expiry), so suppressions are
# auditable instead of inline and invisible.

set -u

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""')

# ---- secret value patterns (kept tight to limit false positives) ----
# The live patterns are the two greps in scan_text_for_secrets() below: a case-sensitive set of
# token signatures, and a case-insensitive assignment pattern (key-like name + quoted value of
# reasonable length, so prose and short values pass). Edit them there.

# grep -E lacks (?i); emulate by lowercasing a copy for the case-insensitive line.
scan_text_for_secrets() {
  local text="$1"
  local hit=""
  # Case-sensitive token patterns.
  if printf '%s' "$text" | grep -Eq '\-\-\-\-\-BEGIN ([A-Z]+ )?PRIVATE KEY\-\-\-\-\-|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[opsu]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|xapp-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{24,}|rk_live_[0-9A-Za-z]{24,}|sk-ant-[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9]{32,}|eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}'; then
    hit="token"
  fi
  # Case-insensitive assignment pattern.
  if printf '%s' "$text" | tr 'A-Z' 'a-z' | grep -Eq '(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?key|auth[_-]?token|password|passwd|pwd)["'"'"' ]*[:=]["'"'"' ]*[a-z0-9/+_=.-]{12,}'; then
    hit="${hit:+$hit,}assignment"
  fi
  printf '%s' "$hit"
}

# Filenames that must never be committed (SEC-SECRET-02). Example/sample/template variants pass.
forbidden_path() {
  local p="$1"
  local base
  base=$(basename "$p")
  case "$base" in
    *.example|*.sample|*.template|*.dist) return 1 ;;
  esac
  case "$base" in
    .env|.env.*) return 0 ;;
    *.pem|*.key|*.p12|*.pfx|*.keystore|*.jks) return 0 ;;
    id_rsa|id_dsa|id_ecdsa|id_ed25519) return 0 ;;
    *service-account*.json|*serviceaccount*.json|credentials.json|gcloud-*.json) return 0 ;;
  esac
  return 1
}

deny() {
  # $1 = short reason, $2 = detailed context.
  # A PreToolUse hook blocks ONLY via exit code 2 with the message on stderr. The stdout
  # {"decision":"block"} / permissionDecision form (without hookEventName) is NOT honored
  # for PreToolUse and fails OPEN. See https://code.claude.com/docs/en/hooks.md.
  { printf '%s\n\n%s\n' "$1" "$2"; } >&2
  exit 2
}

warn() {
  # Non-blocking advisory on a PreToolUse call. additionalContext is only honored when
  # hookSpecificOutput carries the matching hookEventName.
  jq -n --arg ctx "$1" '{ hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: $ctx } }'
  exit 0
}

case "$TOOL" in
  Edit|Write|MultiEdit)
    FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
    # Content differs by tool: Write uses .content, Edit uses .new_string, MultiEdit uses edits[].new_string.
    CONTENT=$(echo "$INPUT" | jq -r '
      ( .tool_input.content // empty ),
      ( .tool_input.new_string // empty ),
      ( .tool_input.edits[]?.new_string // empty )
    ' 2>/dev/null)

    if [ -n "$FILE_PATH" ] && forbidden_path "$FILE_PATH"; then
      deny \
        "Blocked (SEC-SECRET-02): writing a credential-bearing file ($(basename "$FILE_PATH")) into the repo." \
        "SEC-SECRET-02: files like .env, *.pem, *.key, keystores, and service-account JSON must never be committed. Put this path in .gitignore and load the value from a secret manager or injected env var at runtime. If this is a non-secret template, name it with a .example / .sample / .template suffix."
    fi

    if [ -n "$CONTENT" ]; then
      KINDS=$(scan_text_for_secrets "$CONTENT")
      if [ -n "$KINDS" ]; then
        deny \
          "Blocked (SEC-SECRET-01): the content being written looks like a hardcoded credential ($KINDS)." \
          "SEC-SECRET-01: hardcoded secrets are a Blocker. Move the value to a secret manager or an injected env var and read it at runtime. If this is a confirmed false positive (e.g. a public test key or a documented example), add an entry to standards/baseline.yml with an owner and expiry rather than committing the value."
      fi
    fi
    exit 0
    ;;

  Bash)
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
    [ -z "$COMMAND" ] && exit 0
    # Only act on commit / push.
    echo "$COMMAND" | grep -Eq 'git[[:space:]]+(commit|push)([[:space:]]|$)' || exit 0

    if command -v gitleaks >/dev/null 2>&1; then
      # Scan staged changes; gitleaks exits non-zero on a finding. The report quotes the
      # detected secret, so write it to a private temp file (600) and remove it on exit,
      # never a predictable world-readable /tmp path.
      GLOUT=$(mktemp "${TMPDIR:-/tmp}/gitleaks-hook.XXXXXX") || exit 0
      chmod 600 "$GLOUT"
      trap 'rm -f "$GLOUT"' EXIT
      if ! gitleaks protect --staged --no-banner >"$GLOUT" 2>&1; then
        REPORT=$(tail -c 2000 "$GLOUT")
        deny \
          "Blocked (SEC-SECRET-01): gitleaks found a secret in the staged changes." \
          "gitleaks flagged the staged diff before this $(echo "$COMMAND" | awk '{print $2}'). Remove the secret, rotate it if it was real, and re-stage. Report tail:\n$REPORT\nSuppress a confirmed false positive via standards/baseline.yml, not inline."
      fi
    else
      warn \
        "gitleaks is not installed, so the local secret pre-commit scan was skipped. The CI secret-scan gate still runs server-side and will block the merge if a secret slips through. Consider: brew install gitleaks."
    fi
    exit 0
    ;;

  *)
    exit 0
    ;;
esac
