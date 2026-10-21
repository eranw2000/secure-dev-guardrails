---
model: opus
name: secrets-remediation
description: Guided playbook for when a secret has leaked into the repo or git history (rotate, remove, scrub, verify), and for hardening so it does not recur. Use when a secret scan fired, when the user says "a key got committed", "we leaked a secret", "rotate this credential", "scrub git history", "remove secret from history", or after secret-scan / gitleaks blocks a commit. Detection without remediation just creates panic; this is the remediation half.
---

# Secrets Remediation

A leaked secret is a live incident, not a lint finding. The order matters: rotate first
(assume it is already compromised), then remove, then scrub history, then verify and harden.
Anchored to SEC-SECRET-01/02 in `standards/security-standards.md`.

## First principle

Treat any secret that reached the repo (even briefly, even on a branch, even if "no one saw
it") as compromised. Git history, forks, clones, CI logs, and caches may already hold it.
Removing the file does not un-leak the value. Rotation is the only thing that actually closes
the exposure.

## Optional: a narrow, value-free planning pass on a second model family

**When the Codex CLI is set up, this skill can ask an OpenAI model for a planning
pass, and it delegates less than the other three security skills because of the
subject matter.** Read `~/.claude/skills/_shared/codex-delegation.md` and follow it,
then apply the boundary below.

**NEVER send the secret anywhere.** Sending content to an external service
publishes it, and it may be cached or indexed after any later deletion. So none
of the following ever enters a brief, a prompt, an output path or a log:

- the secret value, or any fragment of it, including the fragment step 3 greps for
- the output of `git log -p`, `git show`, `gitleaks -v` or any command that
  prints the matched line
- the contents of a credential file (`.env`, `*.pem`, a key, a token store)
- the repository itself, when the leaked value is still live in its history

**What is NOT delegated, and must run here.** Rotation, removal, the history
scrub, the push, and the verification. Those write, they destroy, and they touch
live credentials. They run under your machine's own guards, and Codex runs in a
sandbox where none of those guards exist. The scope search at step 3 is a `git
log` with a known answer shape; it needs no model at all.

**What IS delegated: a value-free planning pass.** Describe the leak in the
abstract, meaning the KIND of credential, the system it grants access to, what
that access can do, where it reached (local branch, shared remote, fork, CI), and
the repository's stack. Ask for the rotation order and its dependencies, the full
blast radius including places a copy may have travelled to, what else to check,
who must be told, and the hardening that stops a recurrence (step 7). No value,
no history, no file contents.

    python3 ~/.claude/skills/_shared/codex_delegate.py \
      --repo <a path with no secret in it, or omit --repo entirely> \
      --prompt-file <value-free brief> \
      --out <a folder outside the repo>/SECRETS-PLAN-codex.md --label secrets-plan

**Before running it, re-read the brief and confirm by eye that it carries no
value.** This is the one delegation where a mistake cannot be taken back.

**Fail loud.** If it did not run, say so with the runner's exit reason and
continue on Claude. Rotation is time-critical and never waits on a second
opinion.
Exit 15 means the user set `CODEX_REVIEW=off`: no retry, continue on Claude, and
say `Codex review: off (CODEX_REVIEW=off)` in the report.
## Process

### 1. Identify and classify the secret
What is it (API key, DB password, private key, OAuth client secret, signing key), which system
it grants access to, and what that access can do. This sets the urgency and who must be told.

### 2. Rotate first
Generate a new credential in the issuing system and deploy it through the secret manager / env
var path, not the repo. Invalidate the old one. Do this before touching git history; while the
old value is valid, the leak is live. If rotation needs another team or a vendor, open that
request now and note the window during which the old credential is still active.

### 3. Confirm the leak scope in history
Find every commit and branch that contains the value:
- `git log -p -S '<fragment>' --all` to find commits that introduced or removed it.
- `gitleaks detect --source . -v` for a full-history scan.
Record whether it reached a shared remote (origin), a fork, or only the local branch. A
push to a shared remote widens the blast radius and usually means the value is already public
to anyone with repo access.

### 4. Remove from the working tree and ignore the path
Delete the secret from the file, replace it with a runtime lookup (env var / secret manager),
and add the path (or pattern) to `.gitignore` so it cannot return. If it was a credential file
(.env, *.pem, key), this is SEC-SECRET-02.

### 5. Scrub history (only after rotation)
Rewriting history is disruptive and does not substitute for rotation. Do it to stop the value
from sitting in clones and to pass scanners going forward:
- Prefer `git filter-repo` (`git filter-repo --replace-text <patterns.txt>` or
  `--invert-paths --path <file>`). `git filter-branch` is deprecated and slow.
- This rewrites SHAs. Coordinate: every collaborator must re-clone or hard-reset; open PRs may
  need rebasing. On shared branches, agree a window before force-pushing.
- For a fork-heavy or public repo, history scrubbing cannot reach existing forks/clones. The
  rotation in step 2 is what protects you; treat scrubbing as cleanup, not containment.

### 6. Verify
- `gitleaks detect --source . -v` returns clean.
- The old credential is confirmed invalid (try it, or confirm with the issuing system).
- The app runs on the rotated credential from the secret manager, not the repo.
- CI secret-scan passes on the rewritten history.

### 7. Harden so it does not recur
- Add the pattern to `standards/baseline.yml` only if it is a confirmed false positive, never to
  hide a real secret.
- Confirm the pre-commit gitleaks hook and the Claude Code `secret-scan.sh` hook are installed.
- If the value lived in code because there was no easy secret path, that missing path is the
  real root cause; note it as a follow-up (provision a secret manager entry, document the env
  var).

### 8. Record the incident
Short write-up: what leaked, which system, when introduced, when rotated, blast radius (local /
shared / public), and the follow-ups. The security team owns the record; you draft it.

## Guardrails

- Never print the leaked secret value in your output, a commit message, a log, or the incident
  note. Refer to it by name and a short fingerprint.
- Rotation comes before history rewriting. Do not let "we scrubbed it" stand in for "we rotated
  it".
- History rewriting on a shared branch is coordinated, never a surprise force-push.
- If you cannot rotate (no access), say so explicitly and escalate; do not mark the incident
  closed on removal alone.
