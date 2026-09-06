#!/usr/bin/env python3
"""Regression tests for the SEC-AUTH-03 detections, both tools, both directions.

    python3 ci/tests/test_sec_auth_03_detections.py

Why this file exists. An earlier version of the semgrep rules was invalid YAML, which
would have broken every rule in the file rather than only the new ones, and a manual
one-shot run was the only thing that caught it. A detection with no committed test is
a detection nobody will notice going quiet.

Two traps this runner is built around, both of which produced a clean-looking pass while
checking nothing:

  1. semgrep skips this directory if you hand it the directory. Its default ignore list
     covers `tests/`, and it also honours .gitignore, which matters because this repository
     can sit inside a home directory that is itself a git working tree. Both produce
     `scanned: []` with zero findings, which reads exactly like a clean sheet. So the runner
     passes every fixture as an explicit path, passes --no-git-ignore, and fails outright if
     the scanned list comes back empty or short.

  2. A missing tool must not silently pass. If semgrep is absent the run says so and
     exits non-zero, because "no findings" and "no scanner" look identical in a log.

Expectations are per tool, because the two tools genuinely differ. semgrep parses, so it
can tell archive.verify from jwt.verify. The hook greps a line and cannot. That is
recorded in the two sec_auth_03_ast_only fixtures rather than smoothed over.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
PACK = HERE.parent.parent
RULES = PACK / "ci" / "semgrep" / "security.yml"
HOOK = PACK / "hooks" / "dangerous-pattern-warn.sh"
RULE_ID = "SEC-AUTH-03"

# Fixtures semgrep is run over. Which LINES it must report is not written here: it is
# derived from the `EXPECT SEC-AUTH-03` markers in the fixtures themselves, so a case
# added to a fixture is a case this test starts requiring, with nothing to keep in step.
#
# Per-line, not per-file, and that distinction is the whole point. A per-file boolean was
# the first version and it was too coarse: deleting one of the five Python patterns left
# the file still reported by the other four, so the mutation survived and the suite stayed
# green while the rule had a hole in it.
SEMGREP_FILES = [
    "sec_auth_03_bad.py",
    "sec_auth_03_good.py",
    "sec_auth_03_bad.js",
    "sec_auth_03_good.js",
    "sec_auth_03_ast_only.js",
    "sec_auth_03_ast_only.py",
]
MARKER = "EXPECT " + RULE_ID

# fixture -> must the shell hook report SEC-AUTH-03 in it?
HOOK_EXPECT = {
    "sec_auth_03_bad.py": True,
    "sec_auth_03_good.py": False,
    "sec_auth_03_bad.js": True,
    "sec_auth_03_good.js": False,
    "sec_auth_03_bad.cs": True,
    "sec_auth_03_good.cs": False,
    # the hook cannot parse, so it over-matches on both of these on purpose. See the fixtures.
    "sec_auth_03_ast_only.js": True,
    "sec_auth_03_ast_only.py": True,
    # One case per file. The hook reports per file, so these are the only way a narrowed
    # pattern shows up as red rather than hiding behind a sibling case in the same fixture.
    "sec_auth_03_hook_alg_not_first.js": True,
    "sec_auth_03_hook_quoted_alg.js": True,
    "sec_auth_03_hook_prop_assign.js": True,
    "sec_auth_03_hook_claims_off.cs": True,
}

failures: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label}  (got {got!r}, want {want!r})")
    if not ok:
        failures.append(label)


def run_semgrep() -> None:
    print("semgrep")
    if shutil.which("semgrep") is None:
        print("  FAIL semgrep is not installed, so these rules were not exercised at all.")
        failures.append("semgrep missing")
        return
    # Explicit file paths, never the directory: see trap 1 in the module docstring.
    targets = [str(FIX / n) for n in SEMGREP_FILES]
    proc = subprocess.run(
        ["semgrep", "--config", str(RULES), "--no-git-ignore", "--json", "--quiet", *targets],
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  FAIL semgrep produced no JSON. stderr: {proc.stderr.strip()[:300]}")
        failures.append("semgrep output")
        return

    errors = data.get("errors", [])
    check("the rule file parses (no semgrep errors)", len(errors), 0)
    for e in errors[:3]:
        print(f"       {str(e)[:200]}")

    scanned = {Path(p).name for p in data.get("paths", {}).get("scanned", [])}
    if not scanned:
        print("  FAIL semgrep scanned nothing, so every result below is vacuous.")
        failures.append("semgrep scanned nothing")
        return
    check("every expected fixture was scanned",
          sorted(n for n in SEMGREP_FILES if n in scanned), sorted(SEMGREP_FILES))

    # What the fixtures ask for, read out of the fixtures.
    want_lines: dict[str, set[int]] = {}
    for name in SEMGREP_FILES:
        marked = {
            i for i, line in enumerate((FIX / name).read_text().splitlines(), start=1)
            if MARKER in line
        }
        want_lines[name] = marked
    total_marked = sum(len(v) for v in want_lines.values())
    check("the fixtures actually carry markers to check against", total_marked > 0, True)

    got_lines: dict[str, set[int]] = {n: set() for n in SEMGREP_FILES}
    for r in data["results"]:
        if RULE_ID in r["check_id"]:
            got_lines.setdefault(Path(r["path"]).name, set()).add(r["start"]["line"])

    for name in SEMGREP_FILES:
        check(f"{name} reported on exactly the marked lines",
              sorted(got_lines.get(name, set())), sorted(want_lines[name]))


def hook_findings(path: Path) -> set[str]:
    """The rule ids the hook actually REPORTED, not every id in its payload.

    The hook's closing paragraph names rule ids while explaining that the band differs per
    pattern, so a substring search over the whole payload matches on a file the hook found
    nothing in. That is how this test passed while checking nothing. Read the finding lines,
    which are the ones the hook indents and brackets.
    """
    payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(path)}})
    proc = subprocess.run(["bash", str(HOOK)], input=payload, capture_output=True, text=True)
    if not proc.stdout.strip():
        return set()
    try:
        ctx = json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    except (json.JSONDecodeError, KeyError):
        return set()
    ids = set()
    for line in ctx.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            ids.add(stripped.split("]", 1)[0].lstrip("["))
    return ids


def run_hook() -> None:
    print("hook (dangerous-pattern-warn.sh)")
    # Control first: a file the hook must report, and one it must not, so a parser that
    # always returns an empty set cannot make every negative expectation pass.
    check("control, the bad python fixture yields at least one finding",
          len(hook_findings(FIX / "sec_auth_03_bad.py")) > 0, True)
    check("control, the good C# fixture yields no finding at all",
          len(hook_findings(FIX / "sec_auth_03_good.cs")), 0)
    for name, want in HOOK_EXPECT.items():
        check(f"{name} reported", RULE_ID in hook_findings(FIX / name), want)


def main() -> int:
    missing = [n for n in set(SEMGREP_FILES) | set(HOOK_EXPECT) if not (FIX / n).is_file()]
    if missing:
        print(f"FAIL: missing fixtures: {sorted(missing)}")
        return 1

    run_semgrep()
    run_hook()

    total = len(SEMGREP_FILES) + len(HOOK_EXPECT) + 5
    print()
    if failures:
        print(f"FAIL: {len(failures)} of about {total} checks failed: {failures}")
        return 1
    print(f"PASS: about {total} checks, both tools, both directions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
