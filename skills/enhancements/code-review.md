# Enhancement: code-review, add a security + privacy lens

## What it is today
The `code-review` skill runs several parallel agents over a PR (CLAUDE.md compliance, obvious
bugs, git-history context, prior comments, comment-guidance), confidence-scores findings, and
posts the high-confidence ones. None of the agents is a dedicated security or privacy lens.

## The change
Add one more parallel agent: a security + privacy lens, pointed at the org standards. It runs
alongside the existing agents and feeds the same confidence-scoring and posting pipeline, so it
needs no change to the orchestration, only one more agent prompt.

## Drop-in agent prompt
Add this as an additional agent in the parallel set:

```
You are the security + privacy lens for this PR. Read:
- standards/security-standards.md (rules SEC-*)
- standards/privacy-standards.md (rules PRIV-*)
- standards/severity-taxonomy.md (bands)

Review the diff, and read the repository files a check below needs even when the diff does not
touch them: the `.dockerignore`, an existing THREAT-MODEL.md, the tests for the changed code,
container and deployment settings. Report findings only about behavior the diff changes. For
each issue, emit a finding in the taxonomy format with the SEC-* or PRIV-* rule ID, the band,
the file:line, the production/compliance consequence, and the fix.

Priorities (your organization holds EU + US personal data):
1. Hardcoded secrets (SEC-SECRET-01/02) and PII in logs/analytics (PRIV-LOG-01), Blockers.
2. Object-level authorization on data endpoints (SEC-WEB-02 / PRIV-ACC-01), Blockers.
3. Injection and disabled TLS verification (SEC-INJ-*, SEC-CRYPTO-01), Blockers.
4. Retention/deletion reachability for new personal-data stores (PRIV-RET-02), Blocker.

Three checks that look at the whole change rather than one line:
- If the diff touches a surface listed in SEC-DES-01 (authentication, sessions, authorization
  or IAM, cryptography, infrastructure or networking, an agent, a connected server, file
  upload, command execution, deserialization), ask for the THREAT-MODEL.md that covers it. Say
  which surface it touched.
- If the diff changes authentication, authorization, sessions or an input path, look for a
  test that attacks it (SEC-TEST-01). The test must assert the refusal the code defines (a
  rejected status, an exception, an error result or a false return) and no protected data
  returned. For a write, it must also assert that the protected state did not change and that
  no side effect such as a message or a payment happened. A test that only checks nothing
  crashed does not count.
- If the diff touches a Dockerfile, compose file or container setting, check SEC-CTR-01 to 03:
  nothing secret in the image, its build context or its build instructions, a production base
  image pinned by `@sha256:` digest, and the least the running container needs.

Raise cross-file concerns you cannot confirm from the diff as Questions, not assertions. Do not
claim the PR is secure or compliant; report what you checked.
```

## Confidence threshold note
The skill filters findings below an 80 confidence score. Security/privacy Blockers (secrets,
PII in logs, missing authz on a data endpoint) should not be silently dropped by that gate.
Either exempt SEC-SECRET-*, PRIV-LOG-01, SEC-WEB-02, and PRIV-RET-02 findings from the
confidence filter, or post them as a separate "must-confirm" section even when below threshold.
A false negative on a leaked secret is worse than a false positive.

## Why this is an enhancement, not a replacement
The deep security work (cross-file taint, commit-time tracing) lives in the `security-review`
plugin and the `privacy-review` skill. This lens is the fast, in-PR catch so obvious issues get
flagged in the same review the team already runs, not in a separate step they might skip.
