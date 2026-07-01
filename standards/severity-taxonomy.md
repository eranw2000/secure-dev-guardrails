# Severity Taxonomy

Every finding from every ring (hooks, skills, CI) uses these four bands. The bands match
the ones `spec-review` already emits, so a developer sees one consistent vocabulary whether
the finding came from a local hook, a review skill, or a CI job.

## Bands

### Blocker
A real defect with a stated production consequence. Merge must not proceed until it is fixed
or an owner files a time-boxed exception in `baseline.yml`.

Examples: a live credential in the diff, PII written to a log sink, missing authorization on
an endpoint that returns personal data, a dependency with a known critical CVE and a reachable
call path.

Enforcement: hard-block at the hook layer where the check is unambiguous (secrets, PII in
logs), and a failing CI gate in all cases.

### Major
A genuine weakness that should be fixed before release but is not an immediate breach. It
needs a human decision, not an automatic block.

Examples: a SQL query built by string concatenation behind a parameterized-looking helper,
broad CORS, a retention period longer than the stated policy, a missing data-deletion path
for a new personal-data store.

Enforcement: warn at the hook layer; flagged by review skills; CI reports but can be
configured to warn rather than fail, per the company's rollout stage.

### Nit
A small correctness or hygiene issue with no production consequence on its own. Worth fixing,
never worth blocking.

Examples: an overly broad log line that is not PII but is noisy, a TODO left next to a
security-relevant branch, an inconsistent error message.

### Question
The reviewer cannot tell from the diff whether something is a problem. Needs author input.

Examples: "Is this field considered personal data under the company classification?",
"Where is this token rotated?", "Is this third party a contracted sub-processor?".

## Finding format

Every tool emits findings in this shape so they aggregate cleanly:

```
[BAND] RULE-ID  file:line
  Observation: what was found, in one or two sentences.
  Consequence: the production/compliance impact (required for Blocker and Major).
  Fix: the concrete change to make.
  Anchor: the standards rule or requirement ID this maps to.
```

`RULE-ID` is one of the IDs defined in `security-standards.md` (SEC-*) or
`privacy-standards.md` (PRIV-*), or a requirement ID (`NFR-SEC-*`, `NFR-PRIV-*`) when the
finding comes from `spec-review` or `architect`.

## Mapping to CVSS / regulatory weight

The bands are workflow bands, not risk scores. When a SEC finding carries a CVSS score, record
it in the finding body, but the band is still decided by production consequence and reachability,
not by the raw score. A critical CVSS in dead code is a Nit; a medium CVSS on an exposed auth
path is a Blocker.
