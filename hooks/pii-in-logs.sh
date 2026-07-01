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
# matching context word. Email addresses and explicit PII field names are blocked on sight.
#
# Blocking: a PreToolUse hook blocks ONLY via exit code 2 with the reason on stderr. The stdout
# {"decision":"block"} / permissionDecision form (without hookEventName) is NOT honored for
# PreToolUse and fails OPEN. See https://code.claude.com/docs/en/hooks.md.
#
# Suppress a confirmed false positive via standards/baseline.yml (owner + expiry), not inline.

set -u

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""')
case "$TOOL" in Edit|Write|MultiEdit) : ;; *) exit 0 ;; esac

CONTENT=$(echo "$INPUT" | jq -r '
  ( .tool_input.content // empty ),
  ( .tool_input.new_string // empty ),
  ( .tool_input.edits[]?.new_string // empty )
' 2>/dev/null)
[ -z "$CONTENT" ] && exit 0

# Logging / sink call names across Python, JS/TS, Java, C#, plus common analytics. POSIX ERE
# only (no \s / \b), so it behaves the same under BSD and GNU grep.
LOG_CALL='(logger?|log|logging|console|print|println|printf|System\.(out|err)|Console\.(Write|WriteLine)|Debug\.|trace|tracer|span\.(set_attribute|setAttribute)|analytics|track|capture|addBreadcrumb|setExtra|setContext)'

PII_EMAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
PII_SSN='[0-9]{3}-[0-9]{2}-[0-9]{4}'
# Explicit personal-data field names. Checked case-insensitively via a lowercased copy.
PII_FIELD='(ssn|social_?security|e?mail|phone|passport|credit_?card|card_?number|cvv|date_?of_?birth|dob|home_?address|geo_?location|ip_?address)'
# Context words that must be near a numeric shape for it to count as SSN / phone.
SSN_CTX='(ssn|social)'
PHONE_CTX='(phone|tel|mobile|cell|whatsapp)'

# Luhn check: return 0 if the digit string is a valid Luhn number (real card numbers are).
luhn_ok() {
  local n="$1" sum=0 alt=0 i d
  [ ${#n} -ge 13 ] && [ ${#n} -le 16 ] || return 1
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

HITS=""
add_hit() { HITS="${HITS}\n  $1: $2"; }

while IFS= read -r line; do
  echo "$line" | grep -Eq "$LOG_CALL" || continue
  lc=$(printf '%s' "$line" | tr 'A-Z' 'a-z')

  # Email: unambiguous, block on sight.
  if echo "$line" | grep -Eq "$PII_EMAIL"; then add_hit "email-in-log" "$line"; continue; fi
  # Explicit PII field name in a log call: the developer named the field.
  if echo "$lc" | grep -Eq "$PII_FIELD"; then add_hit "pii-field-in-log" "$line"; continue; fi
  # Card: only a Luhn-valid number counts (ignores order numbers, timestamps, ids).
  if line_has_card "$line"; then add_hit "card-in-log" "$line"; continue; fi
  # SSN shape, but only next to an SSN context word.
  if echo "$line" | grep -Eq "$PII_SSN" && echo "$lc" | grep -Eq "$SSN_CTX"; then add_hit "ssn-in-log" "$line"; continue; fi
  # Phone shape, but only next to a phone context word.
  if echo "$lc" | grep -Eq "$PHONE_CTX" && echo "$line" | grep -Eq '\+?[0-9][0-9 .()-]{7,}[0-9]'; then add_hit "phone-in-log" "$line"; continue; fi
done <<EOF
$CONTENT
EOF

if [ -n "$HITS" ]; then
  {
    echo "Blocked (PRIV-LOG-01): personal data appears to be written to a log/trace/analytics call."
    echo "Log a stable surrogate (hashed or tokenized id) instead of the raw identifier. Flagged line(s):"
    printf '%b\n' "$HITS"
    echo "If a flagged line is not actually personal data, suppress it by fingerprint in standards/baseline.yml with an owner and expiry."
  } >&2
  exit 2
fi

exit 0
