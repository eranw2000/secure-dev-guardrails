# Security Standards

The canonical security policy. Hooks enforce a subset of these deterministically, review
skills check all of them, and CI mirrors the hook subset plus the SAST rules. Each rule has a
stable ID (`SEC-*`) that findings anchor to. Bands refer to `severity-taxonomy.md`.

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

## Hook coverage map

Which rules the deterministic local hooks enforce, and how:

- Hard-block: SEC-SECRET-01, SEC-SECRET-02 (`secret-scan.sh`).
- Warn / inject: SEC-INJ-01..03, SEC-WEB-01, SEC-CRYPTO-01..02, SEC-PATH-01
  (`dangerous-pattern-warn.sh`), plus context injection on auth/crypto files
  (`sensitive-file-context.sh`).
- Everything else is review-skill and CI territory (semgrep rulesets, SCA), because it needs
  cross-file reasoning a single-file regex hook cannot do safely.
