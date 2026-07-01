#!/bin/bash
# Warn / inject-context hook (non-blocking). Supports the judgment-call privacy and security
# rules that a regex cannot decide.
#
# Wired as a PostToolUse hook on Edit/Write. When the edited file lives on an auth, crypto,
# payment, or personal-data path, it injects the relevant standards snippet so the next turn
# reviews the change against the right rules. The edit already happened; this is a reminder,
# not a block (mirrors dual-viewport-reminder.sh).
#
# Protocol: read JSON from stdin, emit JSON with hookSpecificOutput.additionalContext, exit 0.

set -u

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
[ -z "$FILE_PATH" ] && exit 0

LOWER=$(printf '%s' "$FILE_PATH" | tr 'A-Z' 'a-z')
CTX=""

case "$LOWER" in
  *auth*|*login*|*session*|*oauth*|*token*|*permission*|*authoriz*|*rbac*|*acl*|*middleware*)
    CTX="${CTX}AUTH/ACCESS path edited ($FILE_PATH). Check SEC-WEB-02 (object-level authorization, not just authentication) and PRIV-ACC-01 (personal-data access restricted to roles that need it). Confirm the change does not widen who can reach a resource or weaken an authz check.\n\n" ;;
esac
case "$LOWER" in
  *crypto*|*encrypt*|*cipher*|*hash*|*secret*|*signing*|*jwt*|*keystore*)
    CTX="${CTX}CRYPTO path edited ($FILE_PATH). Check SEC-CRYPTO-01 (no disabled TLS verification), SEC-CRYPTO-02 (no MD5/SHA-1/DES/ECB/static-IV; use AES-GCM and a slow KDF for passwords), SEC-CRYPTO-03 (no custom crypto).\n\n" ;;
esac
case "$LOWER" in
  *payment*|*billing*|*checkout*|*charge*|*invoice*|*stripe*|*paypal*|*card*)
    CTX="${CTX}PAYMENT path edited ($FILE_PATH). Do not store PAN/CVV (PRIV special-category/financial). Confirm tokenization and that no cardholder data lands in logs (PRIV-LOG-01) or fixtures (PRIV-ANON-01).\n\n" ;;
esac
case "$LOWER" in
  *user*|*account*|*profile*|*customer*|*subscriber*|*member*|*contact*|*person*|*patient*|*pii*|*gdpr*|*privacy*)
    CTX="${CTX}PERSONAL-DATA path edited ($FILE_PATH). Check the privacy rules: PRIV-MIN-01 (only fields needed for the purpose), PRIV-RET-01/02 (retention period + reachable deletion path), PRIV-RIGHTS-01 (the new data is reachable by access/portability/opt-out flows), PRIV-LOG-01 (no PII in logs). If you added a new personal-data store, confirm the deletion path and subject-rights tooling know about it.\n\n" ;;
esac

[ -z "$CTX" ] && exit 0
CTX=$(printf '%b' "$CTX")

jq -n --arg ctx "$CTX" '{ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: ("SECURITY/PRIVACY CONTEXT (standards/security-standards.md, standards/privacy-standards.md):\n\n" + $ctx + "These are judgment-call rules. Review the change against them and raise anything uncertain rather than assuming it is fine.") } }'
exit 0
