# Org Privacy Guidance (read by privacy-review and the context-injection hook)

The privacy counterpart to `claude-security-guidance.md`. The `privacy-review` skill and the
`sensitive-file-context.sh` hook load this. It points at `privacy-standards.md` for full rule
text; here we set your organization's priorities and banding.

## Regimes

GDPR (EU data subjects) and CCPA / US general best practice. When a rule differs between the
two, apply the stricter one. The DPO owns final interpretation; the tooling surfaces, it does
not settle.

## Priorities for your organization

1. PII in logs (PRIV-LOG-01) is the top concern and the most common real violation. Any known
   PII pattern (email, phone, SSN, credit card, precise geolocation, IP tied to a user) feeding
   a logging/tracing/analytics call is a Blocker.
2. Deletion-path reachability (PRIV-RET-02) and subject-rights plumbing (PRIV-RIGHTS-01). A new
   personal-data store that the existing erasure/access flows do not know about silently breaks
   a standing legal obligation. Blocker for deletion, Major for the other rights.
3. Real personal data in fixtures/seeds/demos (PRIV-ANON-01) is a Blocker.

## How to classify a field

Use the "what counts as personal data" section of `privacy-standards.md`. When unsure whether a
field is personal data, raise a Question rather than guessing. Special-category/sensitive data
(health, biometric, financial account, precise geolocation) raises any related finding by one
band.

## Banding and limits

Most privacy rules need data-flow or cross-file reasoning and cannot be settled from one diff.
Surface them as Major or Question with a concrete "Fix" and the rule ID. Do not assert privacy
compliance is "ensured"; name what you checked and what needs a human (DPO, data map) to
confirm.

## Suppressions

Respect `baseline.yml`. Constants that look like PII but are not (a literal support-inbox
address, a documentation example) should be suppressed by fingerprint with a reason, not left
to re-fire every run.
