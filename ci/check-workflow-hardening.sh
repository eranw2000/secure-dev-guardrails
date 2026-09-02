#!/bin/bash
# SEC-CI-01 / SEC-CI-02: workflow hardening. Reads GitHub Actions workflow files and reports
# actions pinned to a moving reference, and workflows that never narrow GITHUB_TOKEN.
#
# Receives workflow file paths as arguments. With no arguments it reads
# .github/workflows/*.yml and *.yaml under the current directory.
#
# Exit 0 when every file passes, 1 when any check fails. The caller decides whether a failure
# blocks: the reusable workflow wraps this in its own `pin_actions` dial, which defaults to
# warn, and pre-commit runs it without blocking, because a commit is recoverable.
#
# What it reads, measured rather than assumed:
#   - A reference counts when the line's first token is `uses:`, optionally after a `- `. A
#     `uses:` inside a `#` comment is NOT reported, and neither is one quoted inside a `run:`
#     block, because in both cases the line starts with something else. A line inside a `run:`
#     block that itself begins with `uses:` would be reported; that shape is rare, and a false
#     report is the safe direction for a checker whose job is to notice an unpinned reference.
#   - It does not parse YAML, so a workflow disabled by being commented out wholesale still has
#     its steps read.
#
# What it deliberately does NOT judge: SEC-CI-03 and SEC-CI-04. Whether a checkout is of
# untrusted code, and whether an expression carries attacker-controlled text, are data-flow
# questions. Those two rules are review-time and security-standards.md says so.
set -u

rc=0
files=("$@")
if [ ${#files[@]} -eq 0 ]; then
  while IFS= read -r f; do files+=("$f"); done < <(
    find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort
  )
fi
[ ${#files[@]} -eq 0 ] && { echo "no workflow files, skipping"; exit 0; }

# An accepted-risk entry in standards/baseline.yml suppresses one finding. Same register the
# rest of the pack uses, so a waiver is recorded, owned and dated rather than achieved by
# deleting the check. A guard with no waiver route is removed by whoever meets it late in the
# day, so this route has to work rather than merely be cited.
#
# It follows the register's own match precedence: rule_id must match AND the path glob must
# match the workflow file. One optional key is added for this rule, `action:`, which narrows a
# waiver to a single reference; an entry without it waives the whole file. An entry past its
# `expires` date does not suppress anything, so a forgotten waiver reopens the finding instead
# of hiding it forever. The baseline-freshness job fails the build on that same expiry.
#
# waived <workflow-file> <action-without-version>
waived() {
  [ -f standards/baseline.yml ] || return 1
  awk -v file="$1" -v action="$2" -v today="$(date +%Y-%m-%d)" '
    function strip(v,   q) {
      sub(/^[ \t]*-?[ \t]*[A-Za-z_]+:[ \t]*/, "", v)
      sub(/[ \t]*#.*$/, "", v)
      q = sprintf("%c", 39)
      gsub(/"/, "", v); gsub(q, "", v)
      sub(/[ \t]+$/, "", v)
      return v
    }
    function glob_ok(   pat) {
      if (pathv == "") return 0
      if (file == pathv) return 1
      pat = pathv
      gsub(/\./, "\\.", pat)
      gsub(/\*\*/, "\001", pat)
      gsub(/\*/, "[^/]*", pat)
      gsub(/\001/, ".*", pat)
      return (file ~ ("^" pat "$"))
    }
    function decide() {
      if (rulev != "SEC-CI-01") return
      if (!glob_ok()) return
      if (actv != "" && actv != action) return
      if (expiry != "" && expiry < today) return
      found = 1
    }
    /^[ \t]*-[ \t]*rule_id:/ { decide(); rulev=""; pathv=""; actv=""; expiry="";
                               rulev = strip($0); next }
    /^[ \t]*rule_id:/ { rulev  = strip($0); next }
    /^[ \t]*path:/    { pathv  = strip($0); next }
    /^[ \t]*action:/  { actv   = strip($0); next }
    /^[ \t]*expires:/ { expiry = strip($0); next }
    END { decide(); exit found ? 0 : 1 }
  ' standards/baseline.yml
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue

  # SEC-CI-01: every `uses:` resolves to a 40-character commit SHA, a container digest, or a
  # path local to this repository.
  while IFS= read -r line; do
    ref=$(printf '%s\n' "$line" | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]]*(#.*)?$//' | tr -d "\"'")
    [ -z "$ref" ] && continue
    case "$ref" in
      ./*|.github/*) continue ;;                       # local action or local reusable workflow
      docker://*@sha256:*) continue ;;                 # container pinned by digest
      \$\{\{*) continue ;;                             # computed at run time, not a static pin
    esac
    version=${ref##*@}
    if printf '%s' "$version" | grep -qE '^[0-9a-f]{40}$'; then
      continue
    fi
    if waived "$f" "${ref%%@*}"; then
      echo "$f: waived by standards/baseline.yml (SEC-CI-01): $ref"
      continue
    fi
    echo "$f: not pinned to a commit SHA or digest (SEC-CI-01): $ref"
    rc=1
  done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]' "$f" | sed 's/^[0-9]*://')

  # SEC-CI-02: the workflow narrows GITHUB_TOKEN somewhere, and never widens it to everything.
  if grep -qE '^[[:space:]]*permissions:[[:space:]]*(write-all|read-all)[[:space:]]*$' "$f"; then
    echo "$f: blanket token scope (SEC-CI-02): permissions: write-all/read-all"
    rc=1
  elif ! grep -qE '^[[:space:]]*permissions:' "$f"; then
    echo "$f: no permissions block, so GITHUB_TOKEN keeps the repository default (SEC-CI-02)"
    rc=1
  fi
done

exit $rc
