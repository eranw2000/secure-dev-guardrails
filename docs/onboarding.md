# Developer onboarding

What the security and privacy guardrails are, and what you need to do.

## What runs, and when

1. **While you code in Claude Code.** Hooks check your edits in real time. Two of them hard-block
   (they stop the edit): writing a hardcoded secret or a credential file, and writing personal
   data into a log line. Two of them warn (the edit proceeds, with guidance): editing an
   auth/crypto/payment/personal-data file, and using a dangerous code pattern.
2. **Before you commit (any editor).** If you have pre-commit installed, gitleaks and semgrep run
   on your staged changes. Install once per clone: `pipx install pre-commit && pre-commit
   install`.
3. **In CI, on every PR.** The same checks run server-side and block the merge if they fail.
   This runs whether or not you used Claude Code, so there is no way around it by switching
   editors.

## What you should do

- Never put a secret in code. Read it from the secret manager or an injected env var. If there
  is no easy path for a secret you need, ask the platform team to provision one rather than
  hardcoding it.
- Never log personal data (email, phone, SSN, card number, precise location, an IP tied to a
  user). Log a hashed or tokenized id when you need to correlate.
- When you add a store of personal data, wire it into deletion and subject-rights from the
  start. A store the deletion job does not know about breaks a legal obligation silently.
- Use synthetic data in fixtures and seeds. Never real customer data.

## When something fires

- **A hook blocked your edit.** It names the rule (SEC-* or PRIV-*) and the fix. Apply the fix.
  If it is a genuine false positive, do not work around it inline; add an entry to
  `standards/baseline.yml` with your name and an expiry, and say why it is safe.
- **A secret leaked anyway.** Treat it as a live incident. Run the `secrets-remediation` skill or
  follow its playbook: rotate the credential first (assume it is compromised), then remove and
  scrub. Removing the file is not enough; rotation is what closes the exposure.
- **CI failed on a security/privacy check.** Read the finding, fix it, push again. If you believe
  it is wrong, the baseline.yml route (with security-team sign-off) is how to suppress it, not a
  force-merge.

## The standards

The full rules are in `standards/security-standards.md` (SEC-*) and
`standards/privacy-standards.md` (PRIV-*). Severity bands are in
`standards/severity-taxonomy.md`. Every tool cites these IDs, so when you see "PRIV-LOG-01" you
can look up exactly what it means.

## The reviews you can run

- `privacy-review`, data-protection pass over your branch (GDPR + CCPA).
- `dependency-review`, CVEs, licenses, and supply-chain risk in dependencies you changed.
- `threat-model`, design-time STRIDE + LINDDUN before you build a new surface.
- `spec-review` / `code-review` / `security-review`, the existing reviews, now with the
  security/privacy lens added.
