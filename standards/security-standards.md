# Security Standards

The canonical security policy. Hooks enforce a subset of these deterministically, review
skills check all of them, and CI mirrors the hook subset plus the SAST rules. Each rule has a
stable ID (`SEC-*`) that findings anchor to. Bands refer to `severity-taxonomy.md`, and
`framework-mapping.md` ties every rule here to its NIST SSDF task, OWASP Top 10 2025 category
and CWE.

Scope languages: Python, JavaScript/TypeScript, Java/C#.

## Secrets and credentials

- **SEC-SECRET-01 (Blocker):** No hardcoded credentials in source, config, or test fixtures.
  This covers API keys, passwords, private keys, connection strings with embedded passwords,
  cloud access keys, and signed tokens. Secrets come from a secret manager or injected env
  vars at runtime, never from the repo.
- **SEC-SECRET-02 (Blocker):** No `.env`, `*.pem`, `*.key`, `id_rsa`, `*.p12`, `*.keystore`,
  or service-account JSON committed to git. These belong in `.gitignore` and a secret store.
- **SEC-SECRET-03 (Major):** No secrets passed on a command line where they land in shell
  history or process listings. Use files or env vars.

## Injection

- **SEC-INJ-01 (Blocker):** No SQL built by string concatenation or f-strings/template
  literals with untrusted input. Use parameterized queries or a query builder that
  parameterizes. Applies to raw drivers and ORM `.raw()` / `createQueryBuilder().where(string)`
  escape hatches.
- **SEC-INJ-02 (Blocker):** No OS command built from untrusted input passed to a shell. Use
  argument-vector APIs (`subprocess.run([...], shell=False)`, `child_process.execFile`,
  `ProcessBuilder` with a list). Never `shell=True` / `exec(string)` on user data.
- **SEC-INJ-03 (Major):** No untrusted input into `eval`, `exec`, `Function()`, `pickle.load`,
  `yaml.load` (use `yaml.safe_load`), Java/C# native deserialization of untrusted bytes,
  `torch.load(weights_only=False)`, or templating engines with autoescape disabled.

## Web and API surface

- **SEC-WEB-01 (Major):** No raw assignment of untrusted data to `innerHTML`,
  `dangerouslySetInnerHTML`, `document.write`, or equivalent. Use text nodes or a sanitizer.
- **SEC-WEB-02 (Blocker):** Every endpoint that returns or mutates non-public data performs an
  authorization check that ties the request identity to the specific resource (object-level
  authz), not just authentication. Guards against IDOR.
- **SEC-WEB-03 (Major):** No SSRF-prone fetches: user-supplied URLs are validated against an
  allowlist and resolved hosts are checked against internal ranges before the request.
- **SEC-WEB-04 (Major):** CORS, CSRF, and cookie flags are explicit. No wildcard CORS with
  credentials; state-changing routes are CSRF-protected; cookies set `HttpOnly`, `Secure`,
  `SameSite`.

## Crypto and transport

- **SEC-CRYPTO-01 (Blocker):** No disabled TLS verification (`verify=False`,
  `rejectUnauthorized: false`, trust-all `TrustManager`, `ServicePointManager` bypass) on any
  path that leaves the host.
- **SEC-CRYPTO-02 (Major):** No weak or broken primitives for security purposes: MD5/SHA-1 for
  integrity or signatures, DES/3DES/RC4, ECB mode, hardcoded IVs, or a static salt for password
  hashing. Use AES-GCM (or a vetted library default) and a slow KDF (argon2/scrypt/bcrypt) for
  passwords.
- **SEC-CRYPTO-03 (Major):** No custom crypto. Use the platform/library primitive.

## Files, paths, and access

- **SEC-PATH-01 (Major):** No path built from untrusted input without canonicalization and a
  containment check (guard against `../` traversal).
- **SEC-PATH-02 (Nit):** Temp files are created with safe permissions and unpredictable names.

## Logging and error handling (security side; privacy side is in PRIV-LOG)

- **SEC-LOG-01 (Major):** No secrets, tokens, or full request bodies logged. (PII in logs is
  covered by `PRIV-LOG-01`.)
- **SEC-ERR-01 (Nit):** No stack traces or internal detail returned to clients in production
  error responses.

## Dependencies and supply chain

- **SEC-DEP-01 (Blocker):** No dependency with a known critical CVE on a reachable path. A
  critical CVE in unreachable code is downgraded per the taxonomy.
- **SEC-DEP-02 (Major):** New dependencies are pinned (lockfile committed) and come from the
  official registry. No install from an arbitrary URL or VCS ref without review.
- **SEC-DEP-03 (Question):** A new dependency that duplicates existing functionality prompts a
  "do we need this" question rather than an automatic finding.

## CI and pipeline

The build system is code that runs with credentials, so it is in scope on the same footing as
the application. These rules are written for GitHub Actions because that is what `ci/` ships;
the same four questions apply to any pipeline, and Azure DevOps or GitLab wording differs only
in the key names.

- **SEC-CI-01 (Major):** Every action, reusable workflow and container a pipeline calls is
  pinned to a full 40-character commit SHA, or for a container to an `@sha256:` digest, with the
  human-readable version in a trailing comment. A tag is a moving reference: whoever can push to
  the action's repository can repoint `v4` at different code, and every workflow trusting that
  tag runs it on the next build without anyone approving a diff. A path local to the repository
  needs no pin, because it is already covered by review of that repository. When you bump a pin,
  change the SHA and the comment in the same edit, or the comment becomes a lie about what runs.
- **SEC-CI-02 (Major):** Every workflow declares `permissions:` explicitly and narrows the build
  token to what the job needs, which for most jobs is `contents: read`. Raise it on the single
  job that needs more, never at the top of the file. `write-all` and `read-all` are not scopes,
  they are the absence of one. A workflow with no `permissions:` block inherits a repository
  default that the file cannot show you, so the file stops being readable as a security
  statement.
- **SEC-CI-03 (Blocker):** No workflow both runs untrusted code and holds credentials. In
  practice that means a `pull_request_target` or `workflow_run` workflow must not check out a
  fork's head and then run its build, test, install or lint steps, because each of those
  executes code from the pull request with the base repository's secrets and write token
  available. Split it: an unprivileged workflow builds the untrusted code, a privileged one acts
  on the result.
- **SEC-CI-04 (Major):** No untrusted expression interpolated directly into a `run:` block. A
  pull request title, branch name, or issue body is attacker-controlled text, and an expression
  is substituted into the script before the shell parses it, so the text becomes commands. Bind
  the value to an `env:` variable and reference the variable, which the shell treats as data.

## Who checks each rule

Every rule below has exactly one owner. Nothing is left to "somebody will notice". Reviewed
2026-08-28, when four rules moved from having no owner into the warning hook and the rest were
assigned explicitly, and again on 2026-09-02 when the four CI rules were added with owners in
the same edit.

**Blocked by a hook (2).** `secret-scan.sh` refuses the write.

- SEC-SECRET-01, SEC-SECRET-02.

**Warned by a hook (11).** `dangerous-pattern-warn.sh` reads the file after the write and
reports; `sensitive-file-context.sh` adds the relevant rules when the path is an auth, crypto,
payment or personal-data one.

- SEC-INJ-01, SEC-INJ-02, SEC-INJ-03, SEC-WEB-01, SEC-WEB-04, SEC-CRYPTO-01, SEC-CRYPTO-02,
  SEC-PATH-01, SEC-PATH-02, SEC-LOG-01, SEC-SECRET-03.

**Checked by the CI workflow (2).** `ci/check-workflow-hardening.sh` reads the repository's
own workflow files. The `workflow-hardening` job runs it, and pre-commit runs it on a workflow
file you touch. It reports; whether it blocks is the `pin_actions` dial, which defaults to warn
for the reason recorded in the job's own comment. An accepted action goes in
`standards/baseline.yml` with an owner and an expiry, and the checker reports it as waived.

- SEC-CI-01, SEC-CI-02.

**Owned by the `dependency-review` skill (3).** A manifest change is not a single-line pattern,
so no hook attempts it. Run the skill when a manifest or lockfile changes.

- SEC-DEP-01, SEC-DEP-02, SEC-DEP-03.

**Review-time only (6), and each for a stated reason.** A single-file regex cannot decide these
without lying, so they belong to `security-review`, `code-reviewer` and a human.

- SEC-WEB-02, object-level authorization. Whether a route checks that this caller owns this
  record is a fact about several files at once.
- SEC-WEB-03, requests to internal addresses. Deciding this needs the origin of the value, which
  is a data-flow question.
- SEC-CRYPTO-03, hand-rolled cryptography. Recognising that a loop is a cipher is not a pattern
  match.
- SEC-ERR-01, internal detail in a client-facing error. Whether a string reaches a user depends
  on the framework's error handling, not on the line.
- SEC-CI-03, untrusted code running with credentials. `pull_request_target` is legitimate on its
  own and dangerous only in combination with a checkout of the fork's head and a step that
  executes it, so the finding lives in the relationship between three parts of the file.
- SEC-CI-04, an untrusted expression reaching a shell. Which context values an attacker controls
  depends on the trigger, and a workflow that already routes the value through `env:` reads
  almost identically to one that does not. A pattern match here produces noise, and a check that
  cries wolf gets switched off.

**What no owner would mean.** A rule with no owner is not a standard, it is a wish. If a rule is
added below, add it to one of these four groups in the same edit.
