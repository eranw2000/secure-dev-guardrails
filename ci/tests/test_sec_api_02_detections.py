#!/usr/bin/env python3
"""Regression tests for the SEC-API-02 detections, both tools, both directions.

    python3 ci/tests/test_sec_api_02_detections.py

Same shape as test_sec_auth_03_detections.py, for the same reasons. semgrep is handed every
fixture as an explicit path with --no-git-ignore, because a directory argument is skipped by
semgrep's default ignore list and comes back as a clean sheet. A missing semgrep fails the run.
The lines semgrep must report are read from `EXPECT SEC-API-02` markers in the fixtures, so a
case added to a fixture is a case this test requires.

The hook is checked per pattern: each positive `sec_api_02_hook_*` fixture holds one required case,
so a narrowed pattern shows up as its own red check. Fixtures ending in `_control` hold safe code
that shares a shape with an unsafe case.
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
RULE_ID = "SEC-API-02"
MARKER = "EXPECT " + RULE_ID

SEMGREP_FILES = [
    "sec_api_02_bad.py",
    "sec_api_02_bad_no_import.py",
    "sec_api_02_good.py",
    "sec_api_02_bad.js",
    "sec_api_02_bad.ts",
    "sec_api_02_good.js",
]


def is_negative_fixture(name: str) -> bool:
    return "_good." in name


# fixture -> must the shell hook report SEC-API-02 in it?
HOOK_EXPECT = {
    "sec_api_02_bad.py": True,
    "sec_api_02_bad_no_import.py": True,
    "sec_api_02_good.py": False,
    "sec_api_02_bad.js": True,
    "sec_api_02_good.js": False,
    # Positive hook fixtures hold one required case each. Fixtures ending in _control hold safe
    # code that shares a shape with an unsafe case, and may hold more than one such line.
    "sec_api_02_hook_all_fields_form.py": True,
    "sec_api_02_hook_all_fields_hyperlinked.py": True,
    "sec_api_02_hook_all_fields_nested.py": True,
    "sec_api_02_hook_all_fields_serializer.py": True,
    "sec_api_02_hook_all_fields_wrapped.py": True,
    "sec_api_02_hook_build.js": True,
    "sec_api_02_hook_build_two_arg.js": True,
    "sec_api_02_hook_builtin_receiver_control.js": False,
    "sec_api_02_hook_bulk_create.js": True,
    "sec_api_02_hook_bulk_create_two_arg.js": True,
    "sec_api_02_hook_chained_assign_save.js": True,
    "sec_api_02_hook_chained_set_save.js": True,
    "sec_api_02_hook_constructor.js": True,
    "sec_api_02_hook_constructor.py": True,
    "sec_api_02_hook_constructor_builtin_control.js": False,
    "sec_api_02_hook_constructor_module.py": True,
    "sec_api_02_hook_constructor_response_control.py": False,
    "sec_api_02_hook_create.js": True,
    "sec_api_02_hook_create_cast.ts": True,
    "sec_api_02_hook_create_ctx_body.js": True,
    "sec_api_02_hook_create_request_body.js": True,
    "sec_api_02_hook_create_spread.js": True,
    "sec_api_02_hook_create_two_arg.js": True,
    "sec_api_02_hook_dict_update_control.py": False,
    "sec_api_02_hook_direct_field_control.py": False,
    "sec_api_02_hook_fields_from_body.js": True,
    "sec_api_02_hook_find_by_id_update.js": True,
    "sec_api_02_hook_find_one_update.js": True,
    "sec_api_02_hook_helper_meta_control.py": False,
    "sec_api_02_hook_insert_many.js": True,
    "sec_api_02_hook_manager_create.py": True,
    "sec_api_02_hook_manager_defaults.py": True,
    "sec_api_02_hook_manager_update.py": True,
    "sec_api_02_hook_mixed_filterset_control.py": False,
    "sec_api_02_hook_non_meta_scope_control.py": False,
    "sec_api_02_hook_object_assign_copy_control.js": False,
    "sec_api_02_hook_prisma_create.js": True,
    "sec_api_02_hook_prisma_create_many.js": True,
    "sec_api_02_hook_prisma_update.js": True,
    "sec_api_02_hook_prisma_update_many.js": True,
    "sec_api_02_hook_prisma_upsert_create.js": True,
    "sec_api_02_hook_prisma_upsert_update.js": True,
    "sec_api_02_hook_scope_closed_control.py": False,
    "sec_api_02_hook_sequelize_options_control.js": False,
    "sec_api_02_hook_update_many.js": True,
    "sec_api_02_hook_update_one.js": True,
    "sec_api_02_hook_update_two_arg.js": True,
}

failures: list[str] = []
checks_run = 0


def check(label: str, got, want) -> None:
    global checks_run
    checks_run += 1
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
    targets = [str(FIX / n) for n in SEMGREP_FILES]
    proc = subprocess.run(
        ["semgrep", "--config", str(RULES), "--no-git-ignore", "--json", "--quiet", "--metrics=off", *targets],
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

    want_lines: dict[str, set[int]] = {}
    for name in SEMGREP_FILES:
        want_lines[name] = {
            i for i, line in enumerate((FIX / name).read_text().splitlines(), start=1)
            if MARKER in line
        }
    for name in SEMGREP_FILES:
        if not is_negative_fixture(name):
            check(f"{name} carries at least one marker", len(want_lines[name]) > 0, True)
        else:
            check(f"{name} carries no marker", len(want_lines[name]), 0)

    got_lines: dict[str, set[int]] = {n: set() for n in SEMGREP_FILES}
    for r in data["results"]:
        if RULE_ID in r["check_id"]:
            got_lines.setdefault(Path(r["path"]).name, set()).add(r["start"]["line"])

    for name in SEMGREP_FILES:
        check(f"{name} reported on exactly the marked lines",
              sorted(got_lines.get(name, set())), sorted(want_lines[name]))


def hook_findings(path: Path) -> set[str]:
    """The rule ids the hook reported, read from its bracketed finding lines only."""
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
    check("control, the bad python fixture yields at least one finding",
          len(hook_findings(FIX / "sec_api_02_bad.py")) > 0, True)
    check("control, the good javascript fixture yields no finding at all",
          len(hook_findings(FIX / "sec_api_02_good.js")), 0)
    for name, want in HOOK_EXPECT.items():
        check(f"{name} reported", RULE_ID in hook_findings(FIX / name), want)


def main() -> int:
    missing = [n for n in set(SEMGREP_FILES) | set(HOOK_EXPECT) if not (FIX / n).is_file()]
    if missing:
        print(f"FAIL: missing fixtures: {sorted(missing)}")
        return 1

    run_semgrep()
    run_hook()

    print()
    if failures:
        print(f"FAIL: {len(failures)} of {checks_run} checks failed: {failures}")
        return 1
    print(f"PASS: {checks_run} checks, both tools, both directions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
