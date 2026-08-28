#!/bin/bash
# Warn / inject-context hook (non-blocking). Flags known-dangerous code patterns so the next
# turn reviews them, without blocking the edit (these need human judgment, hence Major/warn
# rather than Blocker/deny).
#
# Wired as a PostToolUse hook on Edit/Write. Reads the file on disk after the edit and greps
# for language-specific dangerous patterns (SEC-INJ, SEC-WEB-01, SEC-CRYPTO-01, SEC-PATH-01).
#
# Protocol: read JSON from stdin, emit hookSpecificOutput.additionalContext WITH
# hookEventName:"PostToolUse" (the field is required or the context is dropped), exit 0.
#
# All patterns use POSIX ERE only: [[:space:]] not \s, and (^|[^...]) boundaries not \b, so they
# behave the same under BSD (macOS) and GNU grep. A \s / \b here silently matches nothing on BSD.

set -u

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
[ -z "$FILE_PATH" ] && exit 0
[ -f "$FILE_PATH" ] || exit 0

# Only scan code we have rules for.
case "$FILE_PATH" in
  *.py|*.js|*.jsx|*.ts|*.tsx|*.mjs|*.cjs|*.java|*.cs) : ;;
  *) exit 0 ;;
esac

FINDINGS=""
add() { FINDINGS="${FINDINGS}\n  [$1] $2"; }

# --- cross-language ---
grep -Eqn 'verify[[:space:]]*=[[:space:]]*False|rejectUnauthorized[[:space:]]*:[[:space:]]*false|InsecureRequestWarning|TrustAllCerts|ServerCertificateValidationCallback[[:space:]]*=[[:space:]]*.*true' "$FILE_PATH" \
  && add "SEC-CRYPTO-01" "disabled TLS/certificate verification"
grep -Eqn '(^|[^A-Za-z0-9])(MD5|SHA1|DES|RC4)([^A-Za-z0-9]|$)|"ECB"|/ECB/|MessageDigest\.getInstance\("(MD5|SHA-1)"\)' "$FILE_PATH" \
  && add "SEC-CRYPTO-02" "weak crypto primitive (MD5/SHA1/DES/RC4/ECB)"

# --- SEC-WEB-04: the browser-facing switches, all of which are single-line and decidable ---
grep -Eqn 'CORS_ALLOW_ALL_ORIGINS[[:space:]]*=[[:space:]]*True|CORS_ORIGIN_ALLOW_ALL[[:space:]]*=[[:space:]]*True|Access-Control-Allow-Origin["'\'' :=]*\*|origin[[:space:]]*:[[:space:]]*["'\'']\*["'\'']' "$FILE_PATH" \
  && add "SEC-WEB-04" "wildcard CORS origin (never combine with credentials)"
grep -Eqn 'httponly[[:space:]]*=[[:space:]]*(False|false)|secure[[:space:]]*=[[:space:]]*(False|false)|SESSION_COOKIE_SECURE[[:space:]]*=[[:space:]]*False|CSRF_COOKIE_SECURE[[:space:]]*=[[:space:]]*False|CSRF_COOKIE_HTTPONLY[[:space:]]*=[[:space:]]*False|sameSite[[:space:]]*:[[:space:]]*["'\'']?[Nn]one' "$FILE_PATH" \
  && add "SEC-WEB-04" "cookie flag switched off (HttpOnly / Secure / SameSite)"
grep -Eqn 'csrf_exempt|CSRF_TRUSTED_ORIGINS[[:space:]]*=[[:space:]]*\[[[:space:]]*["'\'']\*|@csrf\.exempt' "$FILE_PATH" \
  && add "SEC-WEB-04" "request-forgery protection switched off for a route"

# --- SEC-SECRET-03: a credential on a command line lands in shell history and process listings ---
grep -Eqn '(subprocess|os\.system|execSync|Runtime\.getRuntime|ProcessBuilder).*(--password|--token|--api-key|--secret|--pass=|-p[[:space:]]+["'\'']?\$)' "$FILE_PATH" \
  && add "SEC-SECRET-03" "credential passed on a command line (use a file or an env var)"

# --- SEC-PATH-02: predictable temp file, or a world-writable mode ---
grep -Eqn 'tempfile\.mktemp[[:space:]]*\(|os\.chmod[^)]*0o?777|chmod[[:space:]]+777' "$FILE_PATH" \
  && add "SEC-PATH-02" "predictable temp name or world-writable mode"

# --- SEC-LOG-01: a secret-shaped VARIABLE handed to a log call. The name has to be an argument,
# --- not a word in a sentence, which is the mistake pii-in-logs made and had to be fixed for.
grep -Eqn '(logger?|logging|console|print|printf|System\.out)[[:space:]]*[.(].*[(,{=][[:space:]]*[A-Za-z_.]*(token|secret|password|passwd|api_key|apikey|credential)[[:space:]]*[),}]' "$FILE_PATH" \
  && add "SEC-LOG-01" "a credential-shaped variable passed to a log call"

case "$FILE_PATH" in
  *.py)
    grep -Eqn '(^|[^A-Za-z0-9_])(eval|exec)[[:space:]]*\(|pickle\.loads?[[:space:]]*\(|subprocess\.(call|run|Popen|check_output)\([^)]*shell[[:space:]]*=[[:space:]]*True|os\.system[[:space:]]*\(' "$FILE_PATH" \
      && add "SEC-INJ-02/03" "eval/exec/pickle/shell=True/os.system"
    # yaml.load without a safe Loader (emulate the negative lookahead with a second grep).
    if grep -En 'yaml\.load[[:space:]]*\(' "$FILE_PATH" | grep -Evq 'safe_load|Loader[[:space:]]*='; then
      add "SEC-INJ-03" "yaml.load without SafeLoader (use yaml.safe_load)"
    fi
    # torch.load without weights_only=True.
    if grep -En 'torch\.load[[:space:]]*\(' "$FILE_PATH" | grep -Evq 'weights_only[[:space:]]*=[[:space:]]*True'; then
      add "SEC-INJ-03" "torch.load without weights_only=True"
    fi
    grep -Eqn '(execute|executemany)[[:space:]]*\([[:space:]]*f["'\'']|(execute|executemany)\([^)]*%[^)]*%|cursor\.execute\([^)]*\.format\(' "$FILE_PATH" \
      && add "SEC-INJ-01" "SQL built by string formatting/concatenation"
    grep -Eqn 'open[[:space:]]*\([^)]*(request|input|argv|params)' "$FILE_PATH" \
      && add "SEC-PATH-01" "file path from untrusted input (check for traversal)"
    ;;
  *.js|*.jsx|*.ts|*.tsx|*.mjs|*.cjs)
    grep -Eqn '(^|[^A-Za-z0-9_])eval[[:space:]]*\(|new Function[[:space:]]*\(|child_process|\.exec[[:space:]]*\(|execSync[[:space:]]*\(' "$FILE_PATH" \
      && add "SEC-INJ-02" "eval/new Function/child_process exec"
    grep -Eqn 'innerHTML[[:space:]]*=|dangerouslySetInnerHTML|document\.write[[:space:]]*\(|insertAdjacentHTML' "$FILE_PATH" \
      && add "SEC-WEB-01" "untrusted data into innerHTML/dangerouslySetInnerHTML/document.write"
    grep -Eqn 'query[[:space:]]*\([[:space:]]*`[^`]*\$\{|query[[:space:]]*\([[:space:]]*["'\''][^"'\'']*["'\''][[:space:]]*\+|\.raw[[:space:]]*\(' "$FILE_PATH" \
      && add "SEC-INJ-01" "SQL built by template literal/concatenation"
    ;;
  *.java|*.cs)
    grep -Eqn 'ObjectInputStream|readObject[[:space:]]*\(|XMLDecoder|BinaryFormatter|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\([^)]*\+' "$FILE_PATH" \
      && add "SEC-INJ-02/03" "native deserialization / Runtime.exec / ProcessBuilder with concatenation"
    grep -Eqn 'createStatement[[:space:]]*\([[:space:]]*\)|executeQuery[[:space:]]*\([^)]*\+|"SELECT .*"[[:space:]]*\+' "$FILE_PATH" \
      && add "SEC-INJ-01" "SQL via Statement with string concatenation (use PreparedStatement)"
    ;;
esac

[ -z "$FINDINGS" ] && exit 0
FINDINGS=$(printf '%b' "$FINDINGS")

jq -n --arg file "$FILE_PATH" --arg f "$FINDINGS" '{
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    additionalContext: ("DANGEROUS-PATTERN WARNING in " + $file + " (standards/security-standards.md):" + $f + "\n\nThese are Major-band patterns that need judgment, not automatic blocks. Confirm the input is trusted or switch to the safe alternative named in the standard (parameterized queries, argument-vector exec, a sanitizer, AES-GCM, path containment check). If it is a genuine false positive, note why.")
  }
}'
exit 0
