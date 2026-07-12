---
model: fable
name: dependency-review
description: Review the dependencies a branch adds or changes for known CVEs, license compliance, supply-chain risk, and unnecessary additions, across Python (pip/Poetry), JS/TS (npm/pnpm), and Java/C# (Maven/Gradle/NuGet). Produces DEPENDENCY-COMMENTS.md anchored to SEC-DEP-* rules. Use when a PR touches a manifest or lockfile, or when the user says "dependency review", "check dependencies", "SCA", "supply chain", "are these packages safe", "license check".
---

# Dependency / Supply-Chain Review

You check what a change pulls into the supply chain. Anchored to SEC-DEP-01/02/03 in
`standards/security-standards.md` and banded per `standards/severity-taxonomy.md`.

## Inputs

1. The diff, focused on manifests and lockfiles: `requirements*.txt`, `pyproject.toml`,
   `poetry.lock`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `pom.xml`,
   `build.gradle*`, `*.csproj`, `packages.lock.json`.
2. The available SCA tools: `pip-audit`, `npm audit` / `pnpm audit`, OWASP dependency-check,
   `osv-scanner` if present. Run what is installed; if none is, say so and fall back to checking
   versions against the OSV/GitHub advisory data you can reach.

## Process

### 1. Diff the dependency set
List every added, removed, and version-changed dependency, direct and transitive where the
lockfile shows it. Separate direct adds (a human chose them) from transitive churn (pulled by a
direct change).

### 2. Known vulnerabilities (SEC-DEP-01)
Run the SCA tool for each ecosystem present. For each finding, record the advisory ID
(CVE/GHSA/OSV), the affected version, the fixed version, and whether the vulnerable code path is
reachable from this project. Band by reachability and impact, not raw score: a critical CVE on a
reachable path is a Blocker; the same in an unused transitive dep is a Major or Nit. Always name
the fixed version in the fix.

### 3. Pinning and provenance (SEC-DEP-02)
Are new dependencies pinned with a committed lockfile? Do they come from the official registry,
or from an arbitrary git ref / URL / tarball (supply-chain risk)? An unpinned or
unofficial-source dependency is a Major.

### 4. License compliance
Check each new dependency's license against the company allowlist. Copyleft (GPL/AGPL) in a
proprietary product, or a missing/unknown license, is a Major or Question depending on the
company policy. State the license you found.

### 5. Necessity and footprint (SEC-DEP-03)
Does a new dependency duplicate something already in the tree or in the standard library? Is it
a large dependency added for a tiny need? Raise as a Question ("do we need this, or can we use
X already present?"), not an automatic finding.

### 6. Typosquat / integrity smell
Flag names that are near-misses of popular packages, brand-new packages with very low download
counts pulled as direct deps, or a maintainer/scope change on an existing dep. These are
Questions that ask for a human look.

### 7. Write DEPENDENCY-COMMENTS.md

```markdown
# DEPENDENCY REVIEW, <project>

**Branch:** <branch>
**Reviewed at:** <YYYY-MM-DD HH:MM>
**Ecosystems:** <python|node|java|dotnet present>
**Verdict:** BLOCK | APPROVE WITH FIXES | APPROVE

## Dependency changes
- ADD <name>@<version> (direct), license <x>, <one line on why>
- CHANGE <name> <old> -> <new>
- (transitive churn summarized)

## Blockers
### B-1: <name>@<version>, <CVE/GHSA>
- **Rule:** SEC-DEP-01
- **Advisory:** <id>, affects <range>, fixed in <version>
- **Reachable:** yes/no/unknown, with the call path if known.
- **Fix:** upgrade to <version> (or remove / replace).

## Majors / Questions
(pinning, license, necessity, typosquat smell)

## Limits
Which ecosystems had no SCA tool available, so were checked only by version lookup.
```

### 8. Verdict
- **BLOCK**: a known-vulnerable dependency on a reachable path with a fix available.
- **APPROVE WITH FIXES**: Majors (unpinned, license, non-reachable CVE).
- **APPROVE**: clean, with the limits section naming any ecosystem not fully scanned.

## Guardrails

- Do not upgrade dependencies yourself unless the user asks; recommend the target version.
- Name the fixed version for every CVE; "upgrade it" without a version is not a fix.
- Band by reachability, not by CVSS alone. Say when reachability is unknown.
- Respect `baseline.yml` for accepted advisories (with owner + expiry).
