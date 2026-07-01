# Enhancement: spec-review, deepen the security/privacy pass

## What it is today
`spec-review` checks a feature branch against REQUIREMENTS.md, SPEC.md, and OpenSpec artifacts,
and writes COMMENTS.md with severity bands. Its step-5 "standard hazards pass" includes one
security line: "Security: injection, missing authz, secrets in code or logs." Privacy is only
implied. There is no required trace of security/privacy requirements to code.

## Change 1: require an explicit NFR-SEC-* / NFR-PRIV-* trace
Today an NFR can be satisfied by "a named mechanism present and plausible." Strengthen this for
security and privacy NFRs: every `NFR-SEC-*` and `NFR-PRIV-*` in scope must be traced to the
specific code that implements it, and a silent gap is a Blocker (matching how `architect`
already refuses to drop these in its coverage matrix). Add to step 4:

```
For each in-scope NFR-SEC-* and NFR-PRIV-*: locate the implementing code (not just a plausible
mechanism). If the requirement names a control (authz check, encryption, retention job, consent
gate, deletion path) and the code does not implement it, that is a Blocker, not a Question.
Cross-cite the SEC-*/PRIV-* rule from standards/.
```

## Change 2: add a PII data-flow check to the hazards pass
Replace the single "Security" hazard line with a security line and a privacy line:

```
- Security: injection (SEC-INJ-*), missing object-level authz (SEC-WEB-02), secrets in code or
  logs (SEC-SECRET-*, SEC-LOG-01), disabled TLS verification (SEC-CRYPTO-01).
- Privacy (data flow): trace each new personal-data field from entry to storage to logs to any
  outbound call. Flag PII written to logs/analytics (PRIV-LOG-01), a new personal-data store
  with no reachable deletion path (PRIV-RET-02), personal data sent to an unlisted destination
  (PRIV-XFER-01), and real PII in fixtures (PRIV-ANON-01).
```

## Change 3: cite the standards vocabulary
Anchors are already required. Add SEC-* and PRIV-* rule IDs (from `standards/`) to the list of
valid anchors in the Stance section, so a security/privacy finding cites the rule, not just
"security principle."

## Why keep it in spec-review rather than only in privacy-review
`spec-review` is the gate the team already runs before a PR, and it has the spec in hand, which
is exactly what is needed to tell whether a security/privacy requirement was actually met.
`privacy-review` does the deeper standalone data-protection pass; this enhancement makes sure
spec-review does not approve a branch that silently dropped an NFR-SEC/NFR-PRIV requirement.
