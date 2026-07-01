# The three-ring model

No single mechanism keeps programmers from violating security and privacy standards. Skills are
advisory and a developer can ignore them. Hooks are deterministic but only fire inside Claude
Code. Neither reaches a developer who edits in a plain editor and pushes. So this system uses
three rings, and the enforcement comes from combining them.

## Ring 1: Claude Code layer (fast feedback, shift-left)
Skills and hooks that run while the developer writes code in Claude Code.
- Skills (advisory, deep): `privacy-review`, `threat-model`, `dependency-review`,
  `secrets-remediation`, plus the security/privacy enhancements to `code-review`,
  `security-review`, `spec-review`, `architect`.
- Hooks (deterministic, immediate): `secret-scan.sh` and `pii-in-logs.sh` hard-block the
  unambiguous violations; `sensitive-file-context.sh` and `dangerous-pattern-warn.sh` inject
  guidance on judgment calls.

What this ring buys: the cheapest possible catch, at the moment of writing, with the safe
alternative named inline. What it does not buy: a guarantee, because it depends on the developer
using Claude Code.

## Ring 2: enterprise managed settings (non-bypassable locally)
`settings/managed-settings.json` installed to the OS managed-policy path takes precedence over
user and project settings and cannot be disabled by a developer. This turns the Ring-1
hard-block hooks from "advisory on my machine" into org policy. Pushed via MDM, not per-developer
opt-in.

What this ring buys: a developer using Claude Code cannot turn the hard blocks off. What it does
not buy: coverage of developers who do not use Claude Code at all.

## Ring 3: server-side backstop (the real gate)
`ci/security-privacy.yml` and `.pre-commit-config.yaml` run the same checks server-side:
gitleaks, semgrep (org rules + OWASP packs), the PII net, and SCA. Wired to branch protection as
a Required check, a failing run blocks the merge regardless of how the code was written. This is
the only ring that does not depend on the developer's tooling.

What this ring buys: the actual enforcement boundary. Nothing merges past it.

## How they reinforce each other
- A secret typed in Claude Code is blocked at Ring 1 before it is written.
- A secret pasted in a plain editor is caught at Ring 3 (and at pre-commit if installed) before
  merge.
- The same standards (`standards/`) and the same rule IDs (SEC-*, PRIV-*) drive all three, so a
  developer sees one consistent vocabulary and one severity taxonomy everywhere.
- `baseline.yml` is the single place to record an accepted risk or false positive, honored by
  all three rings, with an owner and an expiry so suppressions cannot rot.

## The honest limit
None of this "ensures" correctness on its own. The hooks catch the unambiguous cases; the
skills surface the judgment calls; CI blocks the merge. Whether a field is "needed for the
purpose" or a destination is an "approved processor" is a human decision (the DPO, the security
team) that the tooling raises but does not settle. Sell the system as defense in depth with a
hard gate, not as a guarantee that removes the human.
