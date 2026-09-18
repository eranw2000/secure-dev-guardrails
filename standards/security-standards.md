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
- **SEC-WEB-03 (Major):** A server-side request to a URL that came from outside is sent only
  after every one of these holds:
  - The scheme is `http` or `https`.
  - The host is on an allowlist. Where the product genuinely has to reach any host, every
    address the name resolves to is outside the loopback, private, link-local, carrier-grade
    NAT and unique-local ranges, and is not a cloud metadata address (`169.254.169.254`,
    `fd00:ec2::254`, `metadata.google.internal`).
  - The request goes to the address that was checked, so a second DNS answer cannot swap in an
    internal one between the check and the call.
  - Redirects are off, or each hop is checked the same way before it is followed.
  - The response has a size cap and a timeout.
  - The outgoing URL is rebuilt from the parts that were checked, never the original string,
    because two URL parsers can read one string as two different hosts.
- **SEC-WEB-04 (Major):** CORS, CSRF, and cookie flags are explicit. No wildcard CORS with
  credentials; state-changing routes are CSRF-protected; cookies set `HttpOnly`, `Secure`,
  `SameSite`.

## Authentication and sessions

`SEC-WEB-02` asks whether this caller may touch this record. These ask the question underneath
it: whether the caller is who they claim to be, and how long that claim stays good. They are
separate failures, and a system can pass one while failing the other. Where a password is
stored is `SEC-CRYPTO-02`; these rules cover the scheme around it.

- **SEC-AUTH-01 (Blocker):** Every route that is not deliberately public authenticates the
  caller server-side before any handler logic runs. Deliberately public means somebody decided
  it and the decision is visible in the code. A route left open because nobody added the
  decorator reads exactly like one that is open on purpose, which is why the default has to be
  deny and the exception has to be the thing that is written down.
- **SEC-AUTH-02 (Blocker):** No home-grown authentication scheme. Use the platform's
  authentication, an established library, or an identity provider: OpenID Connect where you need
  authentication, or SAML where enterprise federation is required. OAuth 2.x on its own is an
  authorization framework and authenticates nobody, so an access token is not evidence of who the
  caller is and must not be accepted as a login. Password verification, token issuing, session
  handling and multi-step login are all places where a mistake is silent: the happy path works,
  and the flaw shows up only when somebody attacks it. Which primitive hashes the password is
  SEC-CRYPTO-02's finding and not this one, so a weak hash inside a hand-written verifier is
  reported once under each rule for its own reason, never twice for the same one.
- **SEC-AUTH-03 (Blocker):** A SELF-CONTAINED token, meaning one the server validates from
  the token itself rather than by looking it up (a JWT, or any signed claim-bearing equivalent),
  is not trusted until its signature, issuer, audience, expiry and intended type have all been
  checked. Decoding is not verifying: every JWT library ships a call that reads the claims
  without checking the signature, one keyword away from the call that checks it. Pin the
  algorithms you accept rather than reading them from the token's own header, and reject `none`.
  Intended type means the token says what it is for, through a `typ` header, a purpose claim, or
  a separate signing key per purpose, and the endpoint checks it, because an access token
  replayed where a refresh token belongs passes every other check on this list. An OPAQUE token,
  a random identifier the server looks up, carries no claims to check and is governed by
  SEC-AUTH-04 instead.
- **SEC-AUTH-04 (Major):** A session ends. Set an absolute lifetime and an idle timeout, issue a
  new session identifier whenever privilege changes (at login, and at any elevation), and
  invalidate server-side on logout and on password change. Write both values down with the reason
  they were chosen: a lifetime of a hundred years satisfies every word of this rule and none of
  its point, so what a reviewer checks is the recorded value against the sensitivity of what the
  session reaches, never that some value exists. A session that expires only in the cookie has not
  expired: the value still works for anyone who kept a copy.
- **SEC-AUTH-05 (Major):** Repeated authentication failures are rate-limited or locked out, per
  account and per source, with the threshold written down beside the reason it was chosen; a
  limit of a billion a day meets the words and not the rule. Per source means whatever identifies
  the caller in your deployment, normally the client address after whichever proxy header you
  actually trust, and the rule is to say which, because behind a load balancer the wrong choice
  rate-limits the balancer. The counter lives where every process serving logins can read it: an
  in-process counter is per worker, so four workers hand an attacker four times the attempts, and
  the limit you measured against one process is not the limit that ships. A limiter at the edge or
  in the identity provider satisfies this rule, and where it runs is part of the answer, because a
  limit nobody can point at is not one.
- **SEC-AUTH-06 (Major):** A failed login does not reveal which half failed. Login,
  registration and password reset return the same response, and take a similar time, whether or
  not the account exists. It reads like a small thing and is banded as a real one, because a list
  of valid accounts is the input to credential stuffing rather than the attack itself, and the
  taxonomy reserves Nit for a finding with no production consequence of its own.

## API design

`SEC-WEB-02` decides which record a caller may touch. These rules cover the rest of an API's
contract: which operations the caller may run, which fields it may write and read, how much it
may ask for at once, and whether the same request can take effect twice.

- **SEC-API-01 (Blocker):** Every privileged operation checks the caller's role or permission
  on the server, in the handler or in a guard attached to its route. Privileged means an admin
  action, a change to a role or a permission, a bulk or export endpoint, or anything that acts
  across accounts or tenants. A hidden button or an unlisted URL is not a check. Routes under an
  admin or internal prefix deny by default and grant by name.
- **SEC-API-02 (Blocker):** A write binds an explicit allowlist of the fields the client may
  set. Never hand the whole request body to a model constructor, an ORM create or update call,
  or a form or serializer that includes every eligible model field (`fields = "__all__"`).
  Fields the server owns, such as ids, owner, role, permissions, balance, price, status and
  audit timestamps, are set by server code only. Prefer `fields` to `exclude`: an allowlist keeps a
  field added to the model later out of the client's reach until somebody lists it.
- **SEC-API-03 (Major):** A response is built from an explicit field list or a response
  schema, never by serializing a whole model or ORM object, so a field added to the model later
  is not sent until somebody lists it. Password hashes, tokens, internal flags and other users'
  data stay on the server, and filtering happens on the server rather than in the client.
- **SEC-API-04 (Major):** Every endpoint has a rate limit sized to its cost, tighter on
  unauthenticated routes and on expensive ones: search, export, file processing, calls to an AI
  model, and anything that sends an email or a text message. Requests also have a maximum body
  size and a timeout. Write the chosen values down with their reason, and keep the counter where
  every process serving the endpoint reads it, the same way SEC-AUTH-05 does for login.
- **SEC-API-05 (Major):** List endpoints paginate by default and clamp a client-supplied page
  size to a server maximum. The same applies to batch sizes, the number of ids accepted in one
  request, and query depth or complexity on a GraphQL endpoint. A client that asks for a million
  rows gets the maximum.
- **SEC-API-06 (Major):** A state-changing request that can arrive more than once, such as a
  signed webhook, a payment callback or a retried client call, takes effect once. A signed
  request is verified exactly as its signature scheme specifies, with the provider's or a vetted
  library's verification call; for an HMAC over the request body, that means the raw bytes as
  received and a constant-time comparison. Where the scheme carries a timestamp, a request
  outside a short window is rejected. An action with a real-world effect (charging, sending,
  provisioning) records the event id or an idempotency key and treats a repeat as a no-op.

## Crypto and transport

- **SEC-CRYPTO-01 (Blocker):** No disabled TLS verification (`verify=False`,
  `rejectUnauthorized: false`, trust-all `TrustManager`, `ServicePointManager` bypass) on any
  path that leaves the host.
- **SEC-CRYPTO-02 (Major):** No weak or broken primitives for security purposes: MD5/SHA-1 for
  integrity or signatures, DES/3DES/RC4, ECB mode, hardcoded IVs, or a static salt for password
  hashing. Use AES-GCM (or a vetted library default) and a slow KDF (argon2/scrypt/bcrypt) for
  passwords.
- **SEC-CRYPTO-03 (Major):** No custom crypto. Use the platform/library primitive.

## Data stores

- **SEC-DB-01 (Major):** The application connects to its database with an account that holds
  only what the running service needs. Never the superuser or owner login (`postgres`, `root`,
  `sa`, a cloud administrator). Schema changes run under a separate migration account that the
  running service does not hold, a component that only reads gets a read-only account, and the
  database port is reachable only from the hosts that use it.

## Files, paths, and access

- **SEC-PATH-01 (Major):** No path built from untrusted input without canonicalization and a
  containment check (guard against `../` traversal).
- **SEC-PATH-02 (Nit):** Temp files are created with safe permissions and unpredictable names.
- **SEC-UPLOAD-01 (Major):** An uploaded file is accepted only when:
  - Its type is on an allowlist and its content matches that type (read the first bytes; the
    extension and the client's `Content-Type` are both chosen by the sender).
  - Its size is capped while it streams in, not measured after it has landed.
  - It is stored under a name the server generates, outside any directory the web server
    serves or runs as code, and within a per-user storage quota.
  - It is served back with `Content-Disposition: attachment` and
    `X-Content-Type-Options: nosniff`, or from a separate domain, so an uploaded page cannot
    run as your site.
  - An archive is unpacked with every entry's final path checked to sit inside the target
    directory, links refused, and caps on the number of entries and the total unpacked size.
    In Python, pass `filter="data"` to `tarfile` extraction and `shutil.unpack_archive`.

## Logging and error handling (security side; privacy side is in PRIV-LOG)

- **SEC-LOG-01 (Major):** No secrets, tokens, or full request bodies logged. (PII in logs is
  covered by `PRIV-LOG-01`.)
- **SEC-LOG-02 (Major):** A value from outside reaches a log only as a field of a structured
  logger, or with carriage returns, line feeds and other control characters escaped, so a user
  cannot write a line that looks like a real event. Security events (sign-in success and
  failure, a permission refused, a role or credential change, an export of personal data)
  carry who (an account id, never the person's details), what, the target, the outcome, a UTC
  timestamp and a request id, which is what SEC-RUN-01 needs to find them.
- **SEC-ERR-01 (Nit):** No stack traces or internal detail returned to clients in production
  error responses.

## Dependencies and supply chain

- **SEC-DEP-01 (Blocker):** No dependency with a known critical CVE on a reachable path. A
  critical CVE in unreachable code is downgraded per the taxonomy.
- **SEC-DEP-02 (Major):** New dependencies are pinned (lockfile committed) and come from the
  official registry. No install from an arbitrary URL or VCS ref without review.
- **SEC-DEP-03 (Question):** A new dependency that duplicates existing functionality prompts a
  "do we need this" question rather than an automatic finding.
- **SEC-DEP-04 (Blocker):** A dependency carrying a CVE listed in CISA's Known Exploited
  Vulnerabilities catalogue is treated as urgent whatever its CVSS score. A score is a guess
  about how bad a flaw could be; a KEV listing is a statement that somebody is exploiting it
  now, and CISA sets a remediation date rather than the person triaging it. On a reachable path
  it is a Blocker. Off one it drops to Major and cannot be closed silently: record the KEV due
  date, whether the entry is flagged as used in ransomware, and the dated reason, because
  "unreachable" is a judgement about today's code and the next refactor does not re-check it.
  Confirm the entry actually applies to the version in the lockfile, since a KEV entry names a
  vendor and a product rather than a package on your registry.
- **SEC-DEP-05 (Blocker):** No package name enters a manifest, a lockfile, an install command or
  an import until it has been confirmed on the registry it will be installed from, and confirmed
  to be the project the author meant. A coding assistant writes plausible names for packages that
  were never published, and attackers publish malicious packages under exactly the names
  assistants tend to invent, so the install that should have failed succeeds and runs their
  code. A name that is not on the registry is a Blocker. A name that exists but was first
  published within the last 90 days, or that is one edit away from a well-known package, is a
  Question for a person: new packages are often fine, and a new package whose name came from a
  model is the exact shape of the attack. `ci/check-package-exists.py` answers the existence
  and age questions by asking PyPI and npm directly, sends a name installed from another
  registry to a person to confirm there, and exits 2, never 0, when a registry does not
  answer. The near-miss question is asked by a person at `dependency-review` step 6.

## Runtime and detection

Everything above asks whether the code is right. These ask a different question: if it were
attacked anyway, would anyone see it. The question belongs at design time, because a signal
that was never designed in cannot be added by looking harder at a log that does not carry it.

**What this pack deliberately does not cover.** Continuous container-level detection, meaning
container escape, cryptomining, reverse shells and anomalous process execution, needs a runtime
protection platform and somebody watching it. This pack assumes neither, and a rule that
assumes a security operations team you do not have is a wish rather than a standard. Those
remain out of scope, and the three rules below are the part that works without them.

- **SEC-RUN-01 (Major):** For each abuse path the threat model names, say what signal would
  show it happening and where that signal would be visible. A threat with no observable signal
  is not a gap to hide: record it as a residual risk, so the next person knows the blindness is
  known rather than accidental.
- **SEC-RUN-02 (Major):** An alert nobody has ever fired is not an alert. Trigger a
  representative event and confirm it appears where SEC-RUN-01 said it would. Detection is the
  one control whose failure mode is silence, so it is the one that most needs a firing test.
- **SEC-RUN-03 (Major):** Know the retention window of the log you are relying on, and check it
  against how long an intrusion typically sits before anyone looks. Evidence that has already
  rotated away is not evidence, and the moment you need it is the worst moment to discover the
  window was seven days.

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
assigned explicitly, again on 2026-09-02 when the four CI rules were added with owners in the
same edit, again on 2026-09-03 for the six authentication rules, again on 2026-09-16 for
the six API design rules, again on 2026-09-18 for SEC-DEP-05, and again the same day for
SEC-UPLOAD-01, SEC-LOG-02 and SEC-DB-01.

**Blocked by a hook (2).** `secret-scan.sh` refuses the write.

- SEC-SECRET-01, SEC-SECRET-02.

**Warned by a hook (12).** `dangerous-pattern-warn.sh` reads the file after the write and
reports; `sensitive-file-context.sh` adds the relevant rules when the path is an auth, crypto,
payment or personal-data one.

- SEC-INJ-01, SEC-INJ-02, SEC-INJ-03, SEC-WEB-01, SEC-WEB-04, SEC-CRYPTO-01, SEC-CRYPTO-02,
  SEC-PATH-01, SEC-PATH-02, SEC-LOG-01, SEC-SECRET-03, SEC-API-02.

`SEC-API-02` is also checked by the semgrep rules in `ci/semgrep/security.yml`, which read the
structure of a Python, JavaScript or TypeScript file: a serializer or model form with
`fields = "__all__"` in its `Meta`, request data unpacked into a Django manager call or a class
constructor, a loop that copies request data onto an object, a request body passed whole to a
model create, update, constructor or Prisma write, and a body copied onto a document that is then
saved. A write that passes a `fields` list of string literals meets the rule.

**Checked by the CI workflow (2).** `ci/check-workflow-hardening.sh` reads the repository's
own workflow files. The `workflow-hardening` job runs it, and pre-commit runs it on a workflow
file you touch. It reports; whether it blocks is the `pin_actions` dial, which defaults to warn
for the reason recorded in the job's own comment. An accepted action goes in
`standards/baseline.yml` with an owner and an expiry, and the checker reports it as waived.

- SEC-CI-01, SEC-CI-02.

**Owned by the `dependency-review` skill (5).** A manifest change is not a single-line pattern,
so no hook attempts it. Run the skill when a manifest or lockfile changes. Its step 2b runs
`ci/check-kev.py` over the advisory ids the SCA tool reported, which is the mechanical half of
SEC-DEP-04; deciding reachability stays with the reviewer. Its step 1b runs
`ci/check-package-exists.py` over every added name, which is the review-time half of SEC-DEP-05.
The write-time half is `claude-security-guidance.md`, which tells the assistant to run the same
script before it writes a new name, because that is the moment the name is invented.

- SEC-DEP-01, SEC-DEP-02, SEC-DEP-03, SEC-DEP-04, SEC-DEP-05.

**Owned by the `threat-model` skill (3).** Detection is designed, not noticed, so these are
asked at step 5b while the system is still on paper and the answers become `NFR-SEC` lines the
architect can carry. No hook and no scanner can ask them: whether a signal exists is a fact
about the running system and its logging, not about a line of code.

- SEC-RUN-01, SEC-RUN-02, SEC-RUN-03.

**Review-time only (20), and each for a stated reason.** Each is decided by reading how several
parts of the code fit together, so they belong to `security-review`, `code-reviewer` and a human.

- SEC-WEB-02, object-level authorization. Whether a route checks that this caller owns this
  record is a fact about several files at once.
- SEC-AUTH-03, a token accepted without its checks. The hook and the semgrep rule catch a
  check switched OFF, which is the mechanical half, in the same way step 2b of
  `dependency-review` is the mechanical half of the known-exploited rule. They cannot catch the
  half that matters more: a check that was never written has no line to match, so whether the
  issuer, audience and intended type are actually verified is settled by reading the code. The
  owner is the reviewer, and the patterns are an assist.
- SEC-AUTH-01, authentication on every non-public route. The finding is a route with no check,
  and a pattern cannot tell that apart from a route that is public on purpose. It needs the
  route table read against whatever the project treats as its public list.
- SEC-AUTH-02, a home-grown authentication scheme. The same shape as the hand-rolled
  cryptography rule two entries down: recognising that a function is a login flow somebody
  wrote themselves is not a pattern match.
- SEC-AUTH-04, session lifetime and rotation. Three separate absences (no absolute lifetime, no
  rotation on privilege change, no server-side invalidation), and an absence has no line to
  match on. Framework defaults decide most of it, so the answer lives in configuration the
  file under review usually does not contain.
- SEC-AUTH-05, lockout on repeated failures. Also an absence, and the part that is present, a
  counter, looks identical whether it is per process or shared. Which one it is depends on the
  store behind it.
- SEC-AUTH-06, account enumeration. The finding is that two responses differ, so it is a
  comparison between branches rather than a property of either, and timing is not in the text
  at all.
- SEC-API-01, function-level authorization. Settled by reading the route table against the
  permission model, because the check usually lives in a decorator, a middleware or a router
  file rather than beside the handler.
- SEC-API-03, the shape of a response. Settled by reading what each response is built from,
  which is often a serializer shared with the write path and declared in another file.
- SEC-API-04, rate limits, body size and timeouts. Settled by reading the limiter and server
  configuration, which sits in middleware, a gateway or the hosting platform.
- SEC-API-05, page and batch size. Settled by reading the pagination settings together with
  each list endpoint's query.
- SEC-API-06, a request taking effect twice. Settled by reading the signature check together
  with the store that records event ids, which sit in different files.
- SEC-WEB-03, requests to internal addresses. Whether a URL came from outside is a data-flow
  question, and most of the rule (address checks, pinning, redirects, caps) lives in a helper
  the request goes through. The semgrep rules follow a request value into `requests`, `httpx`,
  `urllib`, `fetch`, `axios`, `got` and Node's `http` within one function, and the hook reports
  the same flow written on one line. Both stay quiet when the value passes through a function
  whose name says it allows, validates or checks, so a reviewer reads that helper. The owner is
  the reviewer, and the patterns are an assist.
- SEC-UPLOAD-01, uploaded files. Type checks, streaming caps, generated names and where the
  file is served from sit in the upload view, the storage setting and the web server together.
  The archive half is mechanical: semgrep and the hook report Python `tarfile` extraction and
  `shutil.unpack_archive` with no `filter`, or with `filter="fully_trusted"`. The owner is the
  reviewer, and the patterns are an assist.
- SEC-LOG-02, forged log lines and security-event fields. Whether a logger escapes control
  characters is a property of its configuration, and whether an event carries its fields is
  settled by reading the event against the list in the rule.
- SEC-DB-01, the database account. The account is usually named in an environment variable or
  a secret store, so the file under review rarely shows it. The hook reports the shape that does
  show it: a connection string or a Django setting that logs in as `postgres`, `root`, `sa` or
  `admin`. The migration split and read-only accounts are settled by reading the deployment.
  The owner is the reviewer, and the pattern is an assist.
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
