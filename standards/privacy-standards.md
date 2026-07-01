# Privacy Standards (GDPR + CCPA)

The canonical privacy policy. This is the half that the existing security tooling does not
cover. Each rule has a stable ID (`PRIV-*`) that findings anchor to. Bands refer to
`severity-taxonomy.md`. Legal basis notes point to the GDPR/CCPA concept, not legal advice;
the company DPO owns interpretation.

## What counts as personal data

Treat as personal data any value that identifies a natural person or can be linked to one:

- Direct identifiers: name, email, phone, government ID (SSN, passport), full address.
- Online identifiers: IP address, device ID, cookie ID, precise geolocation.
- Account identifiers: username tied to a real person, customer ID.
- Special-category (GDPR Art. 9) and sensitive (CCPA): health, biometric, genetic, racial or
  ethnic origin, political/religious belief, sexual orientation, precise geolocation,
  financial account numbers. These raise any related finding by one band.

Pseudonymized data (a random ID that maps to a person via a separate table) is still personal
data. Truly anonymized data (no reasonable path back to a person) is not.

## Rules

### Logging and observability

- **PRIV-LOG-01 (Blocker):** No personal data written to logs, traces, metrics labels, or
  analytics events. This is the most common real-world violation. Log a stable surrogate
  (hashed or tokenized ID) when you need correlation, never the raw identifier.
- **PRIV-LOG-02 (Major):** No personal data in error messages, exception payloads, or crash
  reports shipped to a third-party error tracker.

### Data minimization and purpose limitation

- **PRIV-MIN-01 (Major):** Collect and store only the fields needed for the stated purpose. A
  new column/field holding personal data needs a purpose. "Might be useful later" is not one.
- **PRIV-MIN-02 (Major):** Personal data collected for one purpose is not reused for an
  unrelated purpose without a new legal basis (GDPR purpose limitation; CCPA notice at
  collection).

### Retention and deletion

- **PRIV-RET-01 (Major):** Every store of personal data has a defined retention period and a
  mechanism that deletes or anonymizes it when the period ends (TTL, scheduled job, or
  lifecycle policy). A new personal-data store with no retention story is a Major finding.
- **PRIV-RET-02 (Blocker):** A deletion path exists for the data subject's right to erasure
  (GDPR Art. 17) and CCPA right to delete. A new personal-data store that cannot be reached by
  the deletion path is a Blocker, because it silently breaks an existing legal obligation.
- **PRIV-RET-03 (Major):** Backups and replicas are covered by the retention and deletion
  story, or an explicit, documented exception with a re-deletion-on-restore note.

### Access and security of personal data

- **PRIV-ACC-01 (Blocker):** Personal data at rest is encrypted, and access is restricted to
  the roles that need it. A new endpoint exposing personal data without object-level authz is a
  Blocker (this overlaps `SEC-WEB-02`; cite both).
- **PRIV-ACC-02 (Major):** Access to special-category/sensitive data is audit-logged (who read
  what, when), and the audit log itself contains no raw personal data beyond the subject
  reference.

### Transfers and third parties

- **PRIV-XFER-01 (Major):** Personal data sent to a third party goes only to a contracted
  processor/sub-processor on the approved list. A new outbound integration that ships personal
  data to an unlisted destination is a Major finding (Question if the destination's status is
  unknown).
- **PRIV-XFER-02 (Major):** Cross-border transfer of EU personal data has a documented transfer
  mechanism (adequacy, SCCs). A new region/endpoint outside the approved set is flagged.

### Consent and notice

- **PRIV-CONSENT-01 (Major):** Processing that requires consent (non-essential cookies,
  marketing, special-category data) checks for a recorded consent before it runs. No consent
  record, no processing.
- **PRIV-CONSENT-02 (Major):** Tracking/analytics that fires before a consent decision (GDPR)
  or without a notice-at-collection (CCPA) is a finding.

### Subject rights plumbing

- **PRIV-RIGHTS-01 (Major):** New personal-data stores are reachable by the existing
  access/portability (GDPR Art. 15/20) and opt-out (CCPA) flows, not just deletion. A store the
  subject-rights tooling does not know about cannot satisfy a request.

### Anonymization and test data

- **PRIV-ANON-01 (Blocker):** No real personal data in test fixtures, seed data, demos, or
  committed sample files. Use synthetic data. (Matches the project anonymize-PII-fixtures rule.)
- **PRIV-ANON-02 (Nit):** When anonymizing for analytics, prefer aggregation/bucketing over
  reversible pseudonymization; keep the numbers and grouping, fake the identifiers.

## Hook coverage map

- Hard-block: PRIV-LOG-01 where the pattern is unambiguous (a known PII regex feeding a logging
  call), via `pii-in-logs.sh`. Also PRIV-ANON-01 secret-scan-adjacent fixture checks.
- Warn / inject: PRIV-MIN, PRIV-RET, PRIV-XFER, PRIV-CONSENT context injection when editing
  files under personal-data paths (`sensitive-file-context.sh`).
- Review-skill and CI territory: everything needing data-flow or cross-file reasoning
  (retention story, deletion-path reachability, subject-rights plumbing, transfer destinations).
  This is what `privacy-review` exists to do.

## A note on the limits of automation

Most privacy rules cannot be decided from a single diff. Whether a field is "needed for the
purpose" or whether a destination is an approved sub-processor is a judgment the tooling can
surface but not settle. The hooks catch the unambiguous cases (PII in logs, real data in
fixtures); the `privacy-review` skill raises the judgment calls as Major or Question; the DPO
and CI baseline settle them. Do not claim the automation "ensures" privacy compliance on its
own.
