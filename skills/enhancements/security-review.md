# Enhancement: point your security-review capability at these standards, and add privacy

This is a drop-in spec, not a bundled skill. It assumes you already have some security-review
capability: a security-review skill, or a third-party plugin such as the `security-guidance`
plugin (installed separately, not part of this pack). If you have none, run this pack's
`privacy-review` and `threat-model` skills plus the hooks and CI, and skip this file.

## What a typical security-review tool does
A security-review skill or plugin usually flags code vulnerabilities (injection, SSRF, IDOR,
secrets, unsafe deserialization) via some mix of pattern warnings on Edit/Write, an LLM diff
review, and a commit-time reviewer. It reads a policy/guidance file. It usually has no
privacy/PII coverage. The three changes below make it band findings by your rule IDs and add the
privacy half.

## Change 1: point its policy at the org standard
If your tool reads an org policy/guidance file, install `standards/claude-security-guidance.md`
from this repo at the tier it reads (user, project, or project-local, per the tool's docs). That
makes it band findings by your organization's priorities and the SEC-* rule IDs instead of its
generic defaults. No code change, just the policy file in place.

## Change 2: extend the pattern set for your stack
If the tool has a pattern layer, add the language-specific patterns from
`hooks/dangerous-pattern-warn.sh` and `ci/semgrep/security.yml` so Python/JS/Java get the same
coverage the rest of the guardrails enforce (yaml.load without SafeLoader, torch.load without
weights_only, Statement concatenation in Java, child_process exec in JS, etc.). Keep the IDs
aligned to SEC-* so a developer sees one vocabulary.

## Change 3: add the privacy layer
Most security-review tools do not look for personal data. Two options, in order of preference:

1. **Pair it with `privacy-review`.** Keep your security tool as the security engine and run the
   `privacy-review` skill for the data-protection half. This is the cleaner split: security and
   privacy are different disciplines with different reviewers, and `privacy-review` already
   produces a banded, PRIV-*-anchored report. The `pii-in-logs.sh` hook gives the real-time
   PRIV-LOG-01 catch that mirrors a real-time security catch.

2. **Extend the tool's policy** with the PRIV-LOG-01 patterns so its inline layer also flags PII
   in logs. Use this if you want a single tool surface and are willing to widen what your
   security tool covers. Point it at `standards/claude-privacy-guidance.md` as well.

## Verification
After installing the policy file, edit a file with a hardcoded `AKIA...` key and confirm the
tool bands it as a Blocker citing SEC-SECRET-01 (not a generic message). Then confirm the chosen
privacy path (privacy-review run, or extended patterns) flags a `logger.info(user.email)` line
as PRIV-LOG-01.
