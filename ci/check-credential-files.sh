#!/bin/bash
# SEC-SECRET-02: reject credential-bearing files. Used by the pre-commit local hook and runnable
# standalone. Receives candidate file paths as arguments (pre-commit passes staged files).
set -u
rc=0
for f in "$@"; do
  base=$(basename "$f")
  case "$base" in
    *.example|*.sample|*.template|*.dist) continue ;;
  esac
  case "$base" in
    .env|.env.*|*.pem|*.key|*.p12|*.pfx|*.keystore|*.jks|id_rsa|id_dsa|id_ecdsa|id_ed25519)
      echo "Blocked credential file (SEC-SECRET-02): $f"; rc=1 ;;
    *service-account*.json|*serviceaccount*.json|credentials.json)
      echo "Blocked credential file (SEC-SECRET-02): $f"; rc=1 ;;
  esac
done
exit $rc
