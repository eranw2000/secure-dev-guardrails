# Org Security Guidance (read by the security-guidance plugin)

This file is what the `security-guidance` plugin loads as the org policy (place it at the
user, project, or project-local tier as documented by the plugin). Keep it short. It points at
`security-standards.md` for the full rule text; here we tell the reviewer what your organization
cares about most and how to band findings.

## Priorities for your organization

1. Live credentials in a diff (SEC-SECRET-01/02) are always a Blocker. Treat any
   high-entropy string near a key-like name as a credential until proven otherwise.
2. Authorization on data endpoints (SEC-WEB-02). This is a web/SaaS company holding EU and US
   personal data; object-level authz failures are Blockers because they are also privacy
   breaches (cross-cite PRIV-ACC-01).
3. Injection (SEC-INJ-01..03) and disabled TLS verification (SEC-CRYPTO-01) are Blockers.

## Banding

Use the four bands in `severity-taxonomy.md` (Blocker / Major / Nit / Question). Decide the
band by production consequence and reachability, not by raw CVSS. A scary pattern in dead or
test-only code is a Nit or a Question, not a Blocker.

## Suppressions

Respect `baseline.yml`. An inline `# nosec RULE-ID: reason` (or the language-appropriate lint
comment) suppresses a single line, but only when it names the rule and gives a reason. A bare
ignore comment does not suppress.

## Languages

Python, JavaScript/TypeScript, Java/C#. When you spot a dangerous pattern, name the
language-specific safe alternative from `security-standards.md` rather than a generic "sanitize
input".

## What not to do

Do not claim a clean review "ensures" the code is secure. State what you checked and what you
could not see from the diff. Raise cross-file concerns (auth bypass, SSRF, IDOR) as Questions
when you cannot trace them within the changed files.
