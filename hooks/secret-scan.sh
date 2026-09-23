#!/bin/bash
# Hard-block hook. Enforces SEC-SECRET-01 and SEC-SECRET-02.
#
# Wired as a PreToolUse hook on both Edit/Write and Bash:
#   - Edit/Write: scans the content about to be written for hardcoded credentials and blocks
#     the write before it lands. Also blocks creating credential-bearing files (.env, *.pem,
#     keys, service-account JSON). That branch lives HERE and is unchanged.
#   - Bash: handed to hooks/secret-scan-git.py, which decides whether the command really
#     runs `git commit` or `git push` from the shared quote-aware parse rather than from a
#     regex, resolves WHICH repository, and scans the right subject in it: the index for a
#     commit, the index plus the worktree changes for `commit -a`, and the commits that
#     would leave for a push. See that file's header for why, and for the eight holes
#     review round A closed in it on 2026-09-11.
#
# This file keeps the registration, so settings.json needs no change: it names only
# secret-scan.sh, for both matchers.
#
# Protocol: read JSON from stdin. A PreToolUse hook BLOCKS only via exit code 2 with the
# message on stderr. The stdout {"decision":"block"} / permissionDecision form (without
# hookEventName) is NOT honored for PreToolUse and fails OPEN.
# See https://code.claude.com/docs/en/hooks.md.
#
# Bypass for a genuine false positive: append #allow-secret to the command/edit is NOT honored
# here on purpose. Suppress via standards/baseline.yml (owner,
# expiry and the repo's directory name), so suppressions are auditable instead of inline and
# invisible.

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
  # Case-insensitive assignment pattern, on the lines that are NOT reading the value from the
  # environment or a secret store. Measured over 120 real files: every false positive was
  # `api_key = os.environ.get("SOME_NAME")`, where the quoted variable NAME looks like a value.
  # The token signatures above still run over the whole text, so a real credential used as a
  # fallback on an env line is caught there rather than lost here.
  # The sed drops a FUNCTION NAME that directly follows = or : and precedes (, because
  # a call is code, not a literal: `secret = mapnodes.add_node(...)` blocked a test on
  # 2026-09-22. Unquoted literals still match. Board: hooks/tests/test_secret_scan_assignment.py.
  if printf '%s' "$text" \
      | grep -Ev 'os\.environ|os\.getenv|getenv\(|process\.env|Deno\.env|System\.getenv|GetEnvironmentVariable|dotenv|load_dotenv|config\(|settings\.|get_secret|SecretClient|KeyVault|secretsmanager' \
      | tr 'A-Z' 'a-z' \
      | sed -E 's/([:=])[[:space:]]*[a-z_][a-z0-9_.]*\(/\1(/g' \
      | grep -Eq '(api[_-]?key|secret([_-]?key)?|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?key|refresh[_-]?token|bearer[_-]?token|signing[_-]?key|encryption[_-]?key|session[_-]?secret|connection[_-]?string|password|passwd|pwd)["'"'"' ]*[:=]["'"'"' ]*[a-z0-9/+_=.-]{12,}'; then
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

# There is deliberately NO warn() helper any more. Every path in this hook either
# allows in silence or blocks with exit 2: a non-blocking advisory was the shape that
# let a missing scanner read as a clean scan (S4, 2026-09-11), and a dead fail-open
# helper sitting in a fail-closed hook is an invitation to reuse it.

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
          "SEC-SECRET-01: hardcoded secrets are a Blocker. Move the value to a secret manager or an injected env var and read it at runtime. If this is a confirmed false positive (e.g. a public test key or a documented example), add an entry to standards/baseline.yml with an owner, an expiry and repo: <directory name of the repo> rather than committing the value. The register REFUSES an entry that names no repo, because a path is not unique across the estate."
      fi
    fi
    exit 0
    ;;

  Bash)
    # The whole Bash branch is delegated. Two reasons it is not done here:
    #   - deciding whether a command runs git needs the shared quote-aware parse in
    #     hooks/_bash_command_parse.py, so `git -C <repo> commit`, `cd <dir> && git` and
    #     `bash -c "git ..."` all resolve to the right repository. A regex over the raw
    #     text missed all three, and read the hook process's own directory as the repo.
    #   - a commit and a push have DIFFERENT subjects. A commit's secret is in the index;
    #     a push's secret can be in a committed-but-unpushed commit while the index is
    #     empty, which the old single `--staged` scan reported as clean.
    #
    # `exec` replaces this shell, so the Python hook's exit code IS this hook's exit code
    # with no pipeline in the way. The here-string avoids a pipe, whose status would be
    # the last stage's rather than the work's.
    PY_HOOK="${0%/*}/secret-scan-git.py"
    [ -f "$PY_HOOK" ] || PY_HOOK="$HOME/.claude/hooks/secret-scan-git.py"
    if [ -f "$PY_HOOK" ]; then
      exec /usr/bin/python3 "$PY_HOOK" <<< "$INPUT"
    fi
    # The Python half is missing. BLOCK, exactly as a missing gitleaks binary does.
    # This used to warn and exit 0, on the reasoning that a missing hook file is a
    # harness problem rather than evidence of a secret. That reasoning is wrong about
    # the consequence: silence here is indistinguishable from a clean scan, which is
    # the one failure this hook exists to prevent, and nothing else checks the staged
    # change or the outgoing commits. Review round A, 2026-09-11 (S4).
    deny \
      "scanner error: secret-scan-git.py missing, so the git commit / push secret scan did NOT run. This is not a clean result." \
      "Nothing checked the staged change or the outgoing commits: this hook's write branch only sees the content of an Edit or a Write, never what is already staged or committed. Looked for it at $PY_HOOK and at \$HOME/.claude/hooks/secret-scan-git.py. Restore the file and re-run."
    ;;

  *)
    exit 0
    ;;
esac
