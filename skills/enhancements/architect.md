# Enhancement: architect, privacy-by-design defaults and default threat models

## What it is today
`architect` walks an 11-area design decision tree, including a "Security and privacy" area
(authn/authz, sensitive-data handling, threat model) and a coverage matrix that forces every
`NFR-SEC-*` / `NFR-PRIV-*` to a decision or an open question. It is solid when REQUIREMENTS.md
already names the security/privacy NFRs. It is weaker when REQUIREMENTS is vague about personal
data, because then there are no NFR-PRIV-* lines to trace and the gap goes unnoticed.

## Change 1: force PII classification even when REQUIREMENTS is silent
Add a precondition to the "Security and privacy" design area: before designing, classify what
personal data the system will touch, using the "what counts as personal data" section of
`standards/privacy-standards.md`. If the system touches personal data and REQUIREMENTS named no
`NFR-PRIV-*`, the architect generates the missing privacy requirements rather than proceeding.
A design over personal data with zero privacy NFRs is a gap, not a clean state.

## Change 2: privacy-by-design defaults
When the design touches personal data, apply these defaults unless a requirement overrides them,
and record each as a decision (D-N) so it is traceable:
- Data minimization: store only fields with a stated purpose (PRIV-MIN-01).
- Retention + deletion from day one: every personal-data store gets a retention period and is
  wired into the deletion/erasure path (PRIV-RET-01/02) and the subject-rights flows
  (PRIV-RIGHTS-01). Designing the deletion path after the store exists is how PRIV-RET-02 gets
  silently broken.
- Surrogate logging: log hashed/tokenized IDs, never raw identifiers (PRIV-LOG-01).
- Encryption at rest + least-privilege access for personal data (PRIV-ACC-01).
- Approved-processor-only egress for personal data (PRIV-XFER-01).

## Change 3: invoke a default threat model per domain
When the design introduces a new attack surface, run (or reference) the `threat-model` skill so
STRIDE + LINDDUN produce explicit `NFR-SEC-*` / `NFR-PRIV-*` lines that flow into the coverage
matrix. Provide a per-domain starting point so the model is not blank:
- Web/API endpoint -> OWASP Top 10 as the STRIDE seed; LINDDUN focus on disclosure + linkability.
- Data store of personal data -> LINDDUN focus on retention/minimization/transfer compliance.
- Third-party integration -> transfer (PRIV-XFER) + SSRF (SEC-WEB-03) as the seeds.

## Change 4: tighten the precondition gate
The skill already refuses to write SPEC.md until all 11 areas are visited and the coverage
matrix is complete. Add: if the system touches personal data, SPEC.md is not written until there
is at least one `NFR-PRIV-*` decision covering retention/deletion and one covering PII-in-logs.
This makes the privacy floor non-skippable at design time, which is where it is cheapest to get
right.
