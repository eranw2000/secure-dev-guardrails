#!/bin/bash
# Hard-block hook. Enforces PRIV-LOG-01 (no personal data in logs/traces/analytics).
#
# Wired as a PreToolUse hook on Edit/Write. Scans the content about to be written for a logging
# call on the same line as a personal-data pattern, and blocks the write before it lands.
#
# This is deliberately a line-level co-occurrence heuristic: a log/print/trace/analytics call
# AND a PII signal on the same line. Cross-line and indirect cases (logging a variable that
# holds PII) are out of scope for a hook and belong to the privacy-review skill and CI.
#
# To keep false positives low enough that the hook stays enabled, the numeric-shape patterns are
# precise: card numbers must pass a Luhn check, and SSN / phone shapes must sit next to a
# matching context word. Email addresses are blocked on sight. A personal-data field NAME in a
# log call only WARNS (stdout JSON, exit 0), because a name cannot tell a value from a count.
#
# Blocking: a PreToolUse hook blocks ONLY via exit code 2 with the reason on stderr. The stdout
# {"decision":"block"} / permissionDecision form (without hookEventName) is NOT honored for
# PreToolUse and fails OPEN. See https://code.claude.com/docs/en/hooks.md.
#
# There is NO suppression route for this hook. The waiver register at
# standards/baseline.yml is read by the semgrep reporter in security-scan.sh (the
# claude-release-workflow pack) and by nothing else, so an entry there has no effect here,
# and an entry naming only a `fingerprint` waives nothing anywhere. This hook used to point a
# reader at both. Rewrite the line, or narrow the pattern below and say why in the commit.

set -u

INPUT=$(cat)
# Without jq, or with input jq cannot read, the tool name would come back empty and
# every call would be allowed unchecked. That is a check that never ran, so block.
if ! command -v jq >/dev/null 2>&1; then
  printf '%s\n' "privacy check error: jq is not installed, so this check could not read the tool call. This is not a clean result. Install jq (a command you run yourself with \`! brew install jq\`, or your package manager, runs outside this hook) and re-run." >&2
  exit 2
fi
if ! TOOL=$(printf '%s' "$INPUT" | jq -er '.tool_name // ""' 2>/dev/null); then
  printf '%s\n' "privacy check error: the hook input is not readable JSON, so this check could not run. This is not a clean result." >&2
  exit 2
fi
case "$TOOL" in Edit|Write|MultiEdit|Bash) : ;; *) exit 0 ;; esac

# Bash is covered because a heredoc (`cat > f <<EOF`) writes a file without ever touching
# Edit/Write, which left this hook trivially bypassable. The command text carries the payload,
# so scanning it catches the same content by the same rules.
CONTENT=$(echo "$INPUT" | jq -r '
  ( .tool_input.content // empty ),
  ( .tool_input.new_string // empty ),
  ( .tool_input.edits[]?.new_string // empty ),
  ( .tool_input.command // empty )
' 2>/dev/null)
[ -z "$CONTENT" ] && exit 0

# PRIV-LOG-01 governs code that RUNS. A markdown document does not run, so it holds no logging
# call and nothing written into one can reach a log, a trace or an analytics sink. Scanning them
# anyway is what blocked an ordinary project CLAUDE.md paragraph on 2026-09-08, for quoting the
# very command shape this hook had refused a minute earlier. That was the fifth recorded false
# positive and the SECOND where the blocked text was documentation of the block itself, which is
# the cry-wolf shape the global rules name: a guard that refuses the sentence describing the
# guard teaches the next reader to reach for the bypass.
#
# The narrowing is deliberately conservative, because a guard that fails open is worse than one
# that cries wolf. The destination must be KNOWN and must be prose. A write whose destination
# cannot be determined is still scanned, so "cannot tell" is never treated as permission.
#
# What this deliberately does NOT cover, so the boundary is stated rather than discovered: a
# fenced code block inside a markdown file is no longer scanned. That is intentional; it still
# does not execute, and the same content IS scanned at the moment somebody writes it into a
# source file, which is the point where it becomes code.
PROSE_EXT='(md|markdown|mdx|rst)'

# Every path a Bash command redirects INTO. Only > and >> count. A file-descriptor duplication
# (2>&1) is not a destination, and neither is /dev/*. Prints one path per line, or nothing.
bash_redirect_targets() {
  printf '%s' "$1" \
    | grep -oE '(^|[^0-9A-Za-z_&>])>>?[[:space:]]*("[^"]+"|'"'"'[^'"'"']+'"'"'|[^[:space:];|&<>()]+)' \
    | sed -E 's/^[^>]*>>?[[:space:]]*//' \
    | tr -d "\"'" \
    | grep -v '^&' \
    | grep -v '^/dev/'
}

# True only when EVERY destination this call writes to is a prose document, and there is at
# least one. Anything else, including an undeterminable destination, returns false and the
# content is scanned as before.
dest_is_prose_only() {
  local fp targets t n=0
  case "$TOOL" in
    Write|Edit|MultiEdit)
      fp=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
      [ -n "$fp" ] || return 1
      printf '%s' "$fp" | tr 'A-Z' 'a-z' | grep -Eq "\.${PROSE_EXT}\$"
      return $?
      ;;
    Bash)
      targets=$(bash_redirect_targets "$CONTENT")
      [ -n "$targets" ] || return 1
      while IFS= read -r t; do
        [ -n "$t" ] || continue
        n=$((n+1))
        printf '%s' "$t" | tr 'A-Z' 'a-z' | grep -Eq "\.${PROSE_EXT}\$" || return 1
      done <<TARGETS
$targets
TARGETS
      [ "$n" -gt 0 ]
      return $?
      ;;
  esac
  return 1
}

dest_is_prose_only && exit 0

# Logging / sink call names across Python, JS/TS, Java, C#, plus common analytics. POSIX ERE
# only (no \s / \b), so it behaves the same under BSD and GNU grep.
#
# A CALL, not a word. Two forms, and the difference between them is the fix for a measured
# false positive.
#
# Some of these names are also ordinary English: log, print, trace, track, capture, span. For
# those the name must be followed by an opening parenthesis, because "it prints a note" hit the
# bare alternative and blocked a write.
#
# The receiver form is the one that bit on 2026-08-30. Allowing any "." after the name turned
# the full stop at the end of an English sentence into a method call, so a comment reading
# "The intake ... Every invitation" was taken for a logging call. The dot must therefore be
# followed IMMEDIATELY by an identifier character, and the discriminator is exactly the
# whitespace a sentence puts after its full stop.
LOG_RECEIVER='(log|logger|logging|console|tracer|analytics|Debug|Console|System\.(out|err))\.[A-Za-z_]'
LOG_BAREWORD='(log|logger|logging|console|print|println|printf|trace|tracer|span|analytics|track|capture|addBreadcrumb|setExtra|setContext)[[:space:]]*\('
LOG_CALL="(${LOG_RECEIVER})|(${LOG_BAREWORD})"

PII_EMAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
PII_SSN='[0-9]{3}-[0-9]{2}-[0-9]{4}'
# Explicit personal-data field names. Checked case-insensitively against the CODE view of the
# line (see code_view below), never the raw text: a field name inside a quoted sentence is
# English, not a field. "300 emails/month" and "blank on my phone" both blocked writes.
# Bounded on both sides. Unbounded, this matched any word CONTAINING one of these. Both false
# positives measured on 2026-08-30 were that: two ordinary words that merely start with the
# four letters of the electronic-post field name, one meaning a folder and one meaning the
# thing that sends. A left boundary of [^a-z0-9] rather than [^a-z0-9_] is deliberate, so
# user_email and row_phone still count; the right side allows "_" for the same reason, which
# is what keeps phone_number a hit. Plurals are spelled out rather than left to the substring.
PII_FIELD='(^|[^a-z0-9])(ssn|social_?security|e?mails?|phones?|passports?|credit_?cards?|card_?numbers?|cvv|dates?_?of_?birth|dob|home_?address(es)?|geo_?locations?|ip_?address(es)?)([^a-z0-9]|$)'
# Context words that must be near a numeric shape for it to count as SSN / phone.
SSN_CTX='(ssn|social)'
PHONE_CTX='(phone|tel|mobile|cell|whatsapp)'

# Strip the BODY of every quoted string, keeping any {...} interpolation, so what is left is
# code. A field name surviving this is a real reference (user.email, email=..., f"{user.email}");
# one that does not survive was a word in a sentence. A literal VALUE is judged on the raw line
# instead, because an address or a card number inside a string is a genuine finding.
code_view() {
  # 1. An interpolation is code, so lift it OUT of its string: {x} becomes " x ", which closes
  #    the surrounding quote before it and reopens after.
  # 2. A quoted string containing a SPACE is prose, so drop it. One with no space is a token,
  #    almost always a dict key or a field name, so keep it. That single distinction is what
  #    separates row["phone_number"] from "blank on my phone".
  # 3. A JavaScript template literal is a string too. Leaving backticks out of this list meant
  #    the prose inside them reached the field test intact, which is the second false positive
  #    measured on 2026-08-30.
  # 4. A quoted token ending in ':' is a print LABEL, never a field name. Rule 2 keeps a
  #    space-free token because a dict key looks like that, but 'user_email:' is the caption on
  #    a value, not the value. Measured 2026-09-09: 'mail_scope_present:' and 'MAIL_SEND_PRESENT:'
  #    each blocked a line whose only printed value was a boolean.
  #
  # 2026-09-22: a WALKER, not a chain of sed passes. The old rule 1 lifted EVERY {...} on the
  # line, including a brace that is code (a dict or set comprehension), and the quotes it added
  # re-paired the real ones, so a quoted sheet name ended up outside any string and read as a
  # field. Tenth recorded false positive. Now each string is found whole, quote to quote, and
  # only an interpolation INSIDE a string is lifted; a brace in code is left as code.
  printf '%s' "$1" | awk '
  {
    line = $0; n = length(line); out = ""; i = 1
    while (i <= n) {
      ch = substr(line, i, 1)
      if (ch == "\"" || ch == "\047" || ch == "`") {
        j = i + 1
        while (j <= n) { c = substr(line, j, 1); if (c == "\\") { j += 2; continue }; if (c == ch) break; j++ }
        if (j > n) { out = out substr(line, i); break }
        body = substr(line, i + 1, j - i - 1)
        if (ch != "`" && body ~ /^[^ \t]*:$/) {
          out = out " "
        } else if (body ~ /[ \t]/) {
          out = out " "; rest = body
          while (match(rest, /\{[^{}]*\}/)) {
            out = out " " substr(rest, RSTART + 1, RLENGTH - 2) " "
            rest = substr(rest, RSTART + RLENGTH)
          }
        } else {
          out = out substr(line, i, j - i + 1)
        }
        i = j + 1; continue
      }
      out = out ch; i++
    }
    print out
  }'
}

# A SCREAMING_SNAKE identifier is a setting or a constant NAME, in every language this hook
# reads. A setting name is configuration, not a person: `MAIL_CLIENT_SECRET`,
# `ALLOW_EMAIL_ADDRESSES`, `EMAIL_BACKEND` and `NOTIFY_EMAIL` each carry a field word inside a
# name that can never hold somebody's address. Remove those tokens before the FIELD-NAME test
# only; every VALUE test still reads the raw line, so a real address, card or phone on the same
# line is caught exactly as before, and any lowercase reference (`user.email`, `row["phone"]`)
# is untouched, which is what keeps `print("EMAIL", user_email)` blocked.
#
# At least one underscore is required, so a bare `EMAIL` still counts. That is the minimum that
# covers the measured cases and nothing more.
#
# Measured 2026-09-11 over a real set of projects: 319 lines hold a logging call AND a field word.
# This rule changes the verdict on ONE of them, and that one is a false positive
# (`"... but NOTIFY_EMAIL is unset; not emailing"`). So it is narrow by measurement, not by hope.
#
# Third recorded instance of this false-positive class in three days (2026-09-09 label case,
# and twice on 2026-09-11: a boolean settings switch, and a print of this very setting name),
# which is what promotes it from a recorded candidate to a fixed rule.
#
# THE ACCEPTED RISK, stated rather than discovered: a data record whose KEY is all caps, such as
# `print(row["PHONE_NUMBER"])` reading a spreadsheet column, now passes. It cannot be told apart
# from `os.environ.get("MAIL_SENDER_MAILBOX")` by shape alone, and the measurement above found
# zero instances of it in the estate, against three false positives in three days.
settings_view() {
  printf '%s' "$1" | sed -E 's/[A-Z][A-Z0-9]*(_[A-Z0-9]+)+/ /g'
}

# A line that is only a comment is documentation, not a call that runs. The global CLAUDE.md
# already exempts code comments and docstrings from the writing checks for the same reason, and
# a comment cannot leak anything at runtime. Covers //, #, *, --, and the /** and */ delimiters.
is_comment_only() {
  printf '%s' "$1" | grep -Eq '^[[:space:]]*(//|#|\*|/\*|\*/|--)'
}

# Luhn check: return 0 if the digit string is a valid Luhn number (real card numbers are).
luhn_ok() {
  local n="$1" sum=0 alt=0 i d first
  [ ${#n} -ge 13 ] && [ ${#n} -le 16 ] || return 1
  # A run of ONE repeated digit is never a card, and all-zeros passes Luhn trivially (sum 0).
  # Measured 2026-09-09: a placeholder id of 32 zeros was reported as card-in-log twice in one
  # session, once on the control line of a check and once on the test written to prove that wrong.
  first=${n:0:1}
  [ -z "$(printf '%s' "$n" | tr -d "$first")" ] && return 1
  for (( i=${#n}-1; i>=0; i-- )); do
    d=${n:$i:1}
    if [ "$alt" -eq 1 ]; then d=$((d * 2)); [ "$d" -gt 9 ] && d=$((d - 9)); fi
    sum=$((sum + d)); alt=$((1 - alt))
  done
  [ $((sum % 10)) -eq 0 ]
}

# Does the line hold a Luhn-valid 13-16 digit card number (allowing space/dash separators)?
line_has_card() {
  local line="$1" cand digits
  # Pull candidate runs: a digit, then 11-17 digit/space/dash chars, then a digit.
  while IFS= read -r cand; do
    [ -n "$cand" ] || continue
    digits=$(printf '%s' "$cand" | tr -cd '0-9')
    luhn_ok "$digits" && return 0
  done <<EOF
$(printf '%s' "$line" | grep -oE '[0-9][0-9 -]{11,17}[0-9]')
EOF
  return 1
}

# A quoted literal that is an operand of a membership or equality test is a NEEDLE, not a value
# reaching the sink: what the call prints is the True or False the test returns. Strip those
# operands before the VALUE tests only. A line that mixes such a test with a real value keeps the
# real value, so this fails closed. Measured 2026-09-09: an is-it-present check on a mail address,
# whose only output was a boolean, was refused as email-in-log.
predicate_view() {
  printf '%s' "$1" | sed -E \
    -e 's/("[^"]*"|'"'"'[^'"'"']*'"'"')[[:space:]]+(not[[:space:]]+)?in[[:space:]]/ /g' \
    -e 's/(==|!=)[[:space:]]*("[^"]*"|'"'"'[^'"'"']*'"'"')/ /g' \
    -e 's/("[^"]*"|'"'"'[^'"'"']*'"'"')[[:space:]]*(==|!=)/ /g'
}

# An aggregate prints a NUMBER or a BOOLEAN, never the record it counted. A query chain that ends
# in an argument-less .count() or .exists() is replaced by a placeholder before the FIELD-NAME
# test only, so a filter argument that names a personal field inside it is not read as that field
# reaching the sink. Measured 2026-09-13: a one-off shell diagnostic that printed how many staff
# rows carry an address was refused, with nothing but an integer on its output.
#
# Deliberately narrow. Only ONE level of parentheses per call is recognised, so a chain holding a
# nested call (a Q object, a function inside the filter) is left alone and scanned as before: the
# rule fails closed on any shape it cannot read. A count WITH an argument (str.count("@")) is not
# an aggregate of records and is not matched. Every VALUE test still reads the raw line, so a
# literal address inside the filter is still caught.
#
# 2026-09-15: a YES/NO call is the same kind of result. An argument-less call named enabled,
# disabled, configured, is_<x> or has_<x> returns a boolean, so a receiver that happens to be
# named after a field word is not that field reaching the sink. Measured: a one-off send script
# printing whether its mail module was switched on was refused, with only True or False on its
# output. Eighth recorded false positive of this hook, and the same class as count/exists, so it
# widens that list rather than adding a new view. Still scanned: the same names WITH an argument,
# any other method on a field (lower(), strip() return the value), and isolate() and the like,
# because is_ and has_ need their underscore.
#
# 2026-09-15, later: a QUOTED LITERAL that is the only argument of .count() is a NEEDLE, not a
# value. `text.count('<anything>')` prints how many times the literal occurs, so the literal is
# emptied before the aggregate rule and the field test; the RECEIVER is untouched, so a field
# receiver (`user.<field>.count('x')`) and an unquoted argument (`text.count(user_<field>)`)
# still block. Measured: a script widening a CSS selector printed how often an input-type
# selector naming the field word occurred in a stylesheet, and was refused with only an integer
# on its output. Ninth recorded false positive, same class as count/exists and the predicate
# needles above, so it extends this view rather than adding a new one.
#
# 2026-09-23: a LENGTH and a COUNTED GENERATOR are numbers too. `len(<expr>)` and
# `sum(1 for ...)` print how many, never which, so the field word inside them is not that field
# reaching the sink. Measured: four count-only diagnostics refused in one session while measuring
# a contact provider, each printing lengths of field lists and status codes. Tenth recorded false
# positive, same class, so it widens this view. Same limits: one level of parentheses only (a
# nested call is scanned as before), a `sum` of anything but a literal 1 is scanned, and a real
# field beside the aggregate still blocks.
aggregate_view() {
  printf '%s' "$1" | sed -E \
    -e 's/(^|[^A-Za-z0-9_.])len\([^()]*\)/\1 0 /g' \
    -e 's/(^|[^A-Za-z0-9_.])sum\([[:space:]]*1[[:space:]]+for[[:space:]][^()]*\)/\1 0 /g' \
    -e "s/\\.count\\(('[^']*'|\"[^\"]*\")\\)/.count(0)/g" \
    -e 's/[A-Za-z_][A-Za-z0-9_.]*(\([^()]*\)(\.[A-Za-z_][A-Za-z0-9_]*)*)*\.(count|exists|enabled|disabled|configured|is_[A-Za-z0-9_]+|has_[A-Za-z0-9_]+)\(\)/ 0 /g'
}

# A short quoted token that is a DIRECT argument of a print or logging call, followed by a comma,
# is the caption on the value after it, never a field. A string literal handed straight to the
# sink cannot read anything; only a token used as a KEY can, and a key always sits one level
# deeper, inside a nested call or a subscript (d.get("x"), getattr(u, "x", None), row["x"]).
# So this tracks bracket depth and clears a caption only when the innermost open bracket is the
# sink call's own "(" and the token follows that "(" or a ",".
#
# THE RULE, NOT THE INSTANCE. This is the third caption false positive: 2026-09-09 a caption
# ending in ':', 2026-09-13 a caption as the FIRST argument, 2026-09-14 captions in the MIDDLE of
# an argument list (print(f, 'rows', n, '<field word>', k, ...), a count-only diagnostic). The
# 2026-09-13 version matched the first argument only, so the next shape walked straight past it.
#
# Still scanned, deliberately: a lone quoted word with no comma after it (the last argument), a
# token inside any nested call, subscript or brace, and an f-string or any prefixed string. The
# value after the caption is scanned. Quotes are skipped as a unit, so a bracket inside a string
# does not move the depth.
label_view() {
  printf '%s' "$1" | awk '
  function is_sink(s) {
    sub(/[ \t]+$/, "", s)
    return (s ~ /(^|[^A-Za-z0-9_])(print|println|printf|console\.[A-Za-z_]+|(log|logger|logging)\.[A-Za-z_]+)$/)
  }
  {
    line = $0; n = length(line); out = ""; depth = 0; i = 1
    while (i <= n) {
      ch = substr(line, i, 1)
      if (ch == "(") { depth++; kind[depth] = is_sink(substr(line, 1, i - 1)) ? "sink" : "other"; out = out ch; i++; continue }
      if (ch == "[" || ch == "{") { depth++; kind[depth] = "other"; out = out ch; i++; continue }
      if (ch == ")" || ch == "]" || ch == "}") { if (depth > 0) depth--; out = out ch; i++; continue }
      if (ch == "\"" || ch == "\047") {
        j = i + 1
        while (j <= n) { c = substr(line, j, 1); if (c == "\\") { j += 2; continue }; if (c == ch) break; j++ }
        if (j > n) { out = out substr(line, i); break }
        body = substr(line, i + 1, j - i - 1)
        p = out; sub(/[ \t]+$/, "", p); prev = substr(p, length(p), 1)
        rest = substr(line, j + 1); sub(/^[ \t]+/, "", rest); nxt = substr(rest, 1, 1)
        if (depth > 0 && kind[depth] == "sink" && (prev == "(" || prev == ",") && nxt == "," \
            && length(body) > 0 && body !~ /[ \t{}]/) {
          out = out " "
        } else {
          out = out substr(line, i, j - i + 1)
        }
        i = j + 1; continue
      }
      out = out ch; i++
    }
    print out
  }'
}

# An address on a TOP-LEVEL domain reserved for testing (RFC 2606 / 6761: .example, .test,
# .invalid, .localhost) cannot belong to anybody, because no such mailbox can exist. Removed
# before the VALUE test only. Deliberately the reserved TLDs and NOT example.com: the board's own
# must-block control uses an example.com address as its stand-in for a real one, and widening
# past what was measured would flip it. Measured 2026-09-18: an invented test-fixture address on
# `mail.example`, printed to check whether a name guard accepted it, was refused as email-in-log.
reserved_view() {
  printf '%s' "$1" | sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(example|test|invalid|localhost)([^A-Za-z0-9.-]|$)/ \2/g'
}

# A FILE PATH is a name on disk, not a person's field, so a path-like word is removed before the
# FIELD-NAME test only: a word holding a "/", and a word ending in a data-file extension. A word
# holding "{" or "(" is kept, so an interpolated field inside a path (`f"/data/{u.<field>}"`) is
# still lifted out by code_view and still blocks. Measured 2026-09-18: a `cmp` of two CSV files
# whose NAME carried the field word was refused, with `echo` printing only a fixed status word.
path_view() {
  printf '%s' "$1" | sed -E \
    -e 's#[^[:space:]"'"'"'(){}]*/[^[:space:]"'"'"'(){}]*# #g' \
    -e 's#[A-Za-z0-9_.-]+\.(csv|tsv|md|py|json|jsonl|xlsx|xls|txt|log|html|sql|yaml|yml)([^A-Za-z0-9]|$)# \2#g'
}

# A Bash line can hold several commands joined by ; && || or |, and those are separate
# statements. Measured 2026-09-22: an address passed as an ARGUMENT to one command and a
# print(...) in the next, on one line, was refused as email-in-log. So a Bash command is cut
# into shell clauses first. Quotes and heredoc bodies are never cut (see _pii_bash_lines.py),
# so a log call stays with its own argument. If the splitter fails, the whole command is
# scanned as before: a failure can only make this stricter.
SCAN="$CONTENT"
if [ "$TOOL" = "Bash" ]; then
  SPLIT=$(printf '%s' "$CONTENT" | python3 "$(dirname "$0")/_pii_bash_lines.py" 2>/dev/null) && [ -n "$SPLIT" ] && SCAN="$SPLIT"
fi

# Real newlines, printed with %s. A flagged line is source text, so a backslash in it is text:
# printf %b read `\c` as "stop here" and cut every later line out of the message.
NL='
'
HITS=""
add_hit() { HITS="${HITS}${NL}  $1: $2"; }
WARNS=""
add_warn() { WARNS="${WARNS}${NL}  $1: $2"; }

while IFS= read -r line; do
  is_comment_only "$line" && continue
  echo "$line" | grep -Eq "$LOG_CALL" || continue
  lc=$(printf '%s' "$line" | tr 'A-Z' 'a-z')
  # Name tests read this; value tests read the raw line.
  cv=$(code_view "$line" | tr 'A-Z' 'a-z')
  # Context for the SSN and phone shapes. A field ACCESS (`user.phone`, `row["phone"]`) is left
  # out: it is the name test's job and only warns, so it must not turn an unrelated number on
  # the same line into a value that blocks. A caption or a bare word still counts.
  ctx=$(printf '%s' "$cv" | sed -E -e 's/\[[^]]*\]/ /g' -e 's/[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+/ /g')

  # VALUE tests first. Each one sees an actual piece of personal data on the line, so each
  # one BLOCKS.
  # Email: unambiguous, block on sight.
  pv=$(reserved_view "$(predicate_view "$line")")
  if echo "$pv" | grep -Eq "$PII_EMAIL"; then add_hit "email-in-log" "$line"; continue; fi
  # Card: only a Luhn-valid number counts (ignores order numbers, timestamps, ids).
  if line_has_card "$line"; then add_hit "card-in-log" "$line"; continue; fi
  # SSN shape, but only next to an SSN context word.
  if echo "$line" | grep -Eq "$PII_SSN" && echo "$ctx" | grep -Eq "$SSN_CTX"; then add_hit "ssn-in-log" "$line"; continue; fi
  # Phone shape, but only next to a phone context word.
  if echo "$ctx" | grep -Eq "$PHONE_CTX" && echo "$line" | grep -Eq '\+?[0-9][0-9 .()-]{7,}[0-9]'; then add_hit "phone-in-log" "$line"; continue; fi

  # NAME test last, and it only WARNS (2026-09-23). A field word in a print cannot tell
  # the value from a count, a yes/no or a label, and ten one-shape patches never closed that:
  # replayed on 2026-09-23, 51 of the 122 lines this test ever blocked still blocked, about 30
  # of them false. The views below still trim the obvious non-fields so the warning stays rare.
  # Nested calls, not a pipe: `code_view` reads its ARGUMENT, so piping into it hands it an
  # empty string and every test then matches nothing.
  # reserved_view here too: the address's own host (`mail.example`) holds a field word.
  fv=$(code_view "$(label_view "$(aggregate_view "$(settings_view "$(path_view "$(reserved_view "$line")")")")")" | tr 'A-Z' 'a-z')
  if echo "$fv" | grep -Eq "$PII_FIELD"; then add_warn "pii-field-in-log" "$line"; fi
done <<EOF
$SCAN
EOF

if [ -n "$HITS" ]; then
  {
    echo "Blocked (PRIV-LOG-01): personal data appears to be written to a log/trace/analytics call."
    echo "Log a stable surrogate (hashed or tokenized id) instead of the raw identifier. Flagged line(s):"
    printf '%s\n' "$HITS"
    echo "If a flagged line is not actually personal data, rewrite it so the identifier is not the thing logged. There is no waiver for this check: the register at standards/baseline.yml is read only by the semgrep reporter in the release security scan, so an entry there does not suppress this block."
  } >&2
  exit 2
fi

# A warn on PreToolUse must be stdout JSON carrying hookEventName; stderr on exit 0 is dropped.
# The lines go in on stdin, not as an argument, so a huge line cannot exceed ARG_MAX. If jq still
# fails, a fixed warning goes out instead, so the warning is never dropped in silence.
if [ -n "$WARNS" ]; then
  printf '%s' "$WARNS" | jq -Rs '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      additionalContext: ("PRIV-LOG-01 WARNING (not blocked): a print or log call names a personal-data field. Check that what reaches the output is a count, a yes/no or a label, not the value itself. If it is the value, log a surrogate (hashed or tokenized id) instead. Line(s):" + .)
    }
  }' 2>/dev/null \
  || printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"PRIV-LOG-01 WARNING (not blocked): a print or log call names a personal-data field, and the flagged line could not be quoted. Check what the call prints."}}'
fi

exit 0
