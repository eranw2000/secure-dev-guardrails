#!/bin/bash
# Warn / inject-context hook (non-blocking). Flags known-dangerous code patterns so the next
# turn reviews them, without blocking the edit (these need human judgment, hence Major/warn
# rather than Blocker/deny).
#
# Wired as a PostToolUse hook on Edit/Write. Reads the file on disk after the edit and greps
# for language-specific dangerous patterns (SEC-INJ, SEC-WEB-01, SEC-CRYPTO-01, SEC-PATH-01,
# SEC-AUTH-03, SEC-API-02).
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
# A bare `verify=False` is a TLS switch on an HTTP call and a token switch on a decode call, and
# one line cannot carry which. So a `decode(` line is left to SEC-AUTH-03 below and this rule
# reads the rest, or the token bypass gets reported as a certificate problem with the wrong fix.
{ grep -Eqn 'rejectUnauthorized[[:space:]]*:[[:space:]]*false|InsecureRequestWarning|TrustAllCerts|ServerCertificateValidationCallback[[:space:]]*=[[:space:]]*.*true' "$FILE_PATH" \
  || grep -Ev 'decode[[:space:]]*\(' "$FILE_PATH" | grep -Eq 'verify[[:space:]]*=[[:space:]]*False'; } \
  && add "SEC-CRYPTO-01" "disabled TLS/certificate verification"
grep -Eqn '(^|[^A-Za-z0-9])(MD5|SHA1|DES|RC4)([^A-Za-z0-9]|$)|"ECB"|/ECB/|MessageDigest\.getInstance\("(MD5|SHA-1)"\)' "$FILE_PATH" \
  && add "SEC-CRYPTO-02" "weak crypto primitive (MD5/SHA1/DES/RC4/ECB)"

# --- SEC-AUTH-03: a token check switched OFF. Only the explicit switches are matched, never the
# absence of a check, because an absence has no line to match and guessing at it produces the
# noise that gets a hook switched off. The claim-check half of the rule is confirmed at review.
# `algorithms` needs a left boundary: without one, a denylist NAMED insecure_algorithms reads
# as an accepted list. `decode(...verify=False)` is the legacy PyJWT switch, a real bypass on
# 1.x, and it is claimed here so SEC-CRYPTO-01 above does not label it a certificate problem.
grep -Eqn 'verify_signature["'\'']?[[:space:]]*[:=][[:space:]]*(False|false)|decode[[:space:]]*\([^)]*verify[[:space:]]*=[[:space:]]*(False|false)|(^|[^A-Za-z0-9_])["'\'']?algorithms["'\'']?[[:space:]]*[:=][[:space:]]*\[[^]]*["'\''](none|None|NONE)["'\'']|["'\'']alg["'\''][[:space:]]*:[[:space:]]*["'\'']none["'\'']|RequireSignedTokens[[:space:]]*=[[:space:]]*false|ValidateIssuerSigningKey[[:space:]]*=[[:space:]]*false|SignatureValidator[[:space:]]*=|parseClaimsJwt[[:space:]]*\(|\.unsecured[[:space:]]*\(' "$FILE_PATH" \
  && add "SEC-AUTH-03" "unsigned or unverified token path (verify_signature off, legacy verify=False, none in the accepted algorithm list, an unsigned-JWT parse, or a .NET signature validator replaced or switched off)"
grep -Eqn 'Validate(Issuer|Audience|Lifetime)[[:space:]]*=[[:space:]]*false|verify_(aud|exp|iss|nbf)["'\'']?[[:space:]]*[:=][[:space:]]*(False|false)|["'\'']?ignoreExpiration["'\'']?[[:space:]]*[:=][[:space:]]*true|allow_expired[[:space:]]*=[[:space:]]*True' "$FILE_PATH" \
  && add "SEC-AUTH-03" "token claim check switched off (issuer, audience, or expiry)"

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
    # SEC-API-02: fields = "__all__" in the Meta block that belongs to a serializer or model form.
    # The awk program keeps a stack of class and def scopes by indentation, so the Meta has to be
    # a direct child of a class whose bases name one of those base classes. A class header
    # wrapped over several lines is read as one header. The name ModelSerializer also matches
    # HyperlinkedModelSerializer.
    awk '
      function push(level, header,   k) {
        n++; lvl[n] = level
        if (header ~ /^[ \t]*class[ \t]+Meta[ \t]*[:(]/) k = "meta"
        else if (header ~ /^[ \t]*class[ \t]/ && header ~ /(ModelSerializer|ModelForm)/) k = "model"
        else k = "other"
        kind[n] = k
      }
      /^[ \t]*$/ || /^[ \t]*#/ { next }
      {
        match($0, /^[ \t]*/); level = RLENGTH
        if (cont) { header = header " " $0; if ($0 ~ /:[ \t]*(#.*)?$/) { cont = 0; push(clevel, header) }; next }
        while (n > 0 && level <= lvl[n]) n--
        if ($0 ~ /^[ \t]*(class|def|async[ \t]+def)[ \t]/) {
          if ($0 ~ /:[ \t]*(#.*)?$/) push(level, $0); else { cont = 1; clevel = level; header = $0 }
          next
        }
        if ($0 ~ /^[ \t]*fields[ \t]*=[ \t]*["'\'']__all__["'\'']/ && n >= 2 && kind[n] == "meta" && kind[n-1] == "model") found = 1
      }
      END { exit !found }' "$FILE_PATH" \
      && add "SEC-API-02" "serializer or model form with fields = \"__all__\" (list the fields explicitly)"
    # SEC-API-02: request data unpacked into a Django manager call or a class constructor.
    grep -Eqn '\.objects\..*(create|update)[[:space:]]*\([^)]*(\*\*[[:space:]]*request\.|defaults[[:space:]]*=[[:space:]]*request\.)' "$FILE_PATH" \
      && add "SEC-API-02" "request data passed whole to a model manager call (bind an allowlist of fields)"
    grep -En '(^|[^A-Za-z0-9_.])([a-z_][A-Za-z0-9_]*\.)*[A-Z][A-Za-z0-9_]*[[:space:]]*\([^)]*\*\*[[:space:]]*request\.' "$FILE_PATH" \
      | grep -Evq '(Response|Error|Exception|Dict|Counter|ChainMap|Namespace|Tuple)[[:space:]]*\([^)]*\*\*[[:space:]]*request\.' \
      && add "SEC-API-02" "request data unpacked into a class constructor (bind an allowlist of fields)"
    ;;
  *.js|*.jsx|*.ts|*.tsx|*.mjs|*.cjs)
    grep -Eqn '(^|[^A-Za-z0-9_])eval[[:space:]]*\(|new Function[[:space:]]*\(|child_process|\.exec[[:space:]]*\(|execSync[[:space:]]*\(' "$FILE_PATH" \
      && add "SEC-INJ-02" "eval/new Function/child_process exec"
    grep -Eqn 'innerHTML[[:space:]]*=|dangerouslySetInnerHTML|document\.write[[:space:]]*\(|insertAdjacentHTML' "$FILE_PATH" \
      && add "SEC-WEB-01" "untrusted data into innerHTML/dangerouslySetInnerHTML/document.write"
    grep -Eqn 'query[[:space:]]*\([[:space:]]*`[^`]*\$\{|query[[:space:]]*\([[:space:]]*["'\''][^"'\'']*["'\''][[:space:]]*\+|\.raw[[:space:]]*\(' "$FILE_PATH" \
      && add "SEC-INJ-01" "SQL built by template literal/concatenation"
    # SEC-API-02: the whole request body in a model write written on one line: a create, a
    # two-argument create or update whose fields option is not a list of string literals, a
    # filter-and-update whose second argument is the body, a Prisma data object, a constructor,
    # and a body copied onto a document and saved in one expression.
    grep -En '[A-Z][A-Za-z0-9_$]*\.(create|insertMany|bulkCreate|build)[[:space:]]*\([[:space:]]*((req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?[[:space:]]*\)|\{[[:space:]]*\.\.\.[[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?([^.A-Za-z_]|$))' "$FILE_PATH" \
      | grep -Evq '(^|[^A-Za-z0-9_$.])(Object|Array|Promise|Reflect|JSON|Math|Map|Set|WeakMap|WeakSet|Date|Number|String|Symbol|Proxy)\.(create|insertMany|bulkCreate|build|update)[[:space:]]*\(' \
      && add "SEC-API-02" "request body passed whole to a model create (bind an allowlist of fields)"
    grep -En '[A-Z][A-Za-z0-9_$]*\.(create|update|bulkCreate|build)[[:space:]]*\([[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?[[:space:]]*,[[:space:]]*\{.*\}[[:space:]]*\)' "$FILE_PATH" \
      | grep -Ev '(^|[^A-Za-z0-9_$.])(Object|Array|Promise|Reflect|JSON|Math|Map|Set|WeakMap|WeakSet|Date|Number|String|Symbol|Proxy)\.(create|insertMany|bulkCreate|build|update)[[:space:]]*\(' \
      | grep -Evq 'fields[[:space:]]*:[[:space:]]*\[[[:space:]]*(("[^"]*"|'\''[^'\'']*'\'')[[:space:]]*,?[[:space:]]*)*\]' \
      && add "SEC-API-02" "request body passed to a model write whose fields option is not a literal list (list the allowed fields)"
    grep -Eqn '[A-Z][A-Za-z0-9_$]*\.(findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany)[[:space:]]*\(.*,[[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?[[:space:]]*[,)]' "$FILE_PATH" \
      && add "SEC-API-02" "request body used as the whole update document (bind an allowlist of fields)"
    grep -Eqn '\.(create|update|createMany|updateMany|upsert)[[:space:]]*\([[:space:]]*\{.*(data|create|update)[[:space:]]*:[[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?([^.A-Za-z_]|$)' "$FILE_PATH" \
      && add "SEC-API-02" "request body passed whole as Prisma write data (bind an allowlist of fields)"
    grep -En 'new[[:space:]]+[A-Z][A-Za-z0-9_$]*[[:space:]]*\([[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?[[:space:]]*\)' "$FILE_PATH" \
      | grep -Evq 'new[[:space:]]+([A-Za-z0-9_$]*Error|URLSearchParams|URL|RegExp|Function|Map|Set|WeakMap|WeakSet|Date|Blob|File|Response|Request|Headers|FormData|Buffer|Promise|Proxy|Array|Object|String|Number|Boolean|Symbol|BigInt|ArrayBuffer|SharedArrayBuffer|DataView|[A-Za-z0-9]*Array|TextEncoder|TextDecoder|Event|CustomEvent|MessageEvent|Worker|WebSocket|EventSource|AbortController|ReadableStream|WritableStream|TransformStream|DOMParser|Image|Audio|Notification)[[:space:]]*\(' \
      && add "SEC-API-02" "model constructed from the whole request body (bind an allowlist of fields)"
    grep -Eqn '(\.set[[:space:]]*\([[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?[[:space:]]*\)|Object\.assign[[:space:]]*\([^,]+,[[:space:]]*(req|request|ctx\.request)\.body([[:space:]]+as[[:space:]]+[A-Za-z0-9_$.<>]+)?[[:space:]]*\))[[:space:]]*\.save[[:space:]]*\(' "$FILE_PATH" \
      && add "SEC-API-02" "request body copied onto a document and saved (copy the allowed fields only)"
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
    additionalContext: ("DANGEROUS-PATTERN WARNING in " + $file + " (standards/security-standards.md):" + $f + "\n\nThese need judgment rather than an automatic block. Read the band from the rule itself in standards/security-standards.md, because it is not the same for every pattern above: SEC-AUTH-03 and SEC-CRYPTO-01 are Blockers, most of the rest are Major. Confirm the input is trusted or switch to the safe alternative the standard names (parameterized queries, argument-vector exec, a sanitizer, AES-GCM, a path containment check, and for a token: verify the signature with a pinned algorithm list, then check issuer, audience, expiry and intended type). If it is a genuine false positive, note why.")
  }
}'
exit 0
