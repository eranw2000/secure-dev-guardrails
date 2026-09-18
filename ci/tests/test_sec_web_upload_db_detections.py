#!/usr/bin/env python3
"""Regression tests for the SEC-WEB-03, SEC-UPLOAD-01 and SEC-DB-01 detections, both directions.

    python3 ci/tests/test_sec_web_upload_db_detections.py

Built the same way as test_sec_auth_03_detections.py, for the same reasons:

  - semgrep is handed every fixture as an explicit path with --no-git-ignore, because given a
    directory it skips `tests/` and reports an empty scan that reads as a clean sheet. An empty
    or short scanned list fails the run.
  - Which lines semgrep must report is read from `EXPECT <RULE>` markers in the fixtures, per
    line, so a case added to a fixture is a case this test requires, and a rule that loses one
    alternation goes red on that line rather than hiding behind a sibling in the same file.
  - The hook reports per file, so its fixtures hold one case each.
  - A missing semgrep fails the run: "no findings" and "no scanner" look the same in a log.
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

# fixture -> the rule ids semgrep checks in it, by marker. A fixture with no marker for a rule
# must get no report for that rule on any line.
SEMGREP = {
    "sec_web_03_bad.py": ["SEC-WEB-03"],
    "sec_web_03_good.py": ["SEC-WEB-03"],
    "sec_web_03_bad.js": ["SEC-WEB-03"],
    "sec_web_03_good.js": ["SEC-WEB-03"],
    "sec_upload_01_bad.py": ["SEC-UPLOAD-01"],
    "sec_upload_01_good.py": ["SEC-UPLOAD-01"],
    # The hook over-matches here on purpose (see the fixture); semgrep, which parses, must not.
    "sec_upload_01_ast_only.py": ["SEC-UPLOAD-01"],
}
POSITIVE = {"sec_web_03_bad.py", "sec_web_03_bad.js", "sec_upload_01_bad.py"}

# fixture -> (rule id, must the hook report it). One case per file.
HOOK_EXPECT = {
    "sec_db_01_hook_pg_url.py": ("SEC-DB-01", True),
    "sec_db_01_hook_driver_url.py": ("SEC-DB-01", True),
    "sec_db_01_hook_mysql_root.js": ("SEC-DB-01", True),
    "sec_db_01_hook_mongo_admin.js": ("SEC-DB-01", True),
    "sec_db_01_hook_dotnet_sa.cs": ("SEC-DB-01", True),
    "sec_db_01_hook_driver_kwarg.py": ("SEC-DB-01", True),
    "sec_db_01_hook_django_user.py": ("SEC-DB-01", True),
    # A host named postgres is a container name, not a login; a login that only starts with
    # postgres is a different account; a login read from the environment shows nothing.
    "sec_db_01_hook_host_named_postgres_control.py": ("SEC-DB-01", False),
    "sec_db_01_hook_prefixed_login_control.py": ("SEC-DB-01", False),
    "sec_db_01_hook_django_env_control.py": ("SEC-DB-01", False),
    # A Unix-user check, a plain variable and an unrelated settings dict name no database;
    # a DB_ variable, an admin login in a driver call and in DATABASES do.
    "sec_db_01_hook_unix_user_control.py": ("SEC-DB-01", False),
    "sec_db_01_hook_plain_user_control.py": ("SEC-DB-01", False),
    "sec_db_01_hook_config_dict_control.py": ("SEC-DB-01", False),
    "sec_db_01_hook_db_user_var.py": ("SEC-DB-01", True),
    "sec_db_01_hook_driver_admin.py": ("SEC-DB-01", True),
    "sec_db_01_hook_django_admin.py": ("SEC-DB-01", True),
    "sec_web_03_hook_requests.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_keyword.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_verb.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_urlopen.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_fetch.js": ("SEC-WEB-03", True),
    "sec_web_03_hook_axios.js": ("SEC-WEB-03", True),
    "sec_web_03_hook_https.js": ("SEC-WEB-03", True),
    # A validating helper first, a request value in params=, and a function merely ending in
    # "fetch" all stay quiet.
    "sec_web_03_hook_validated_control.py": ("SEC-WEB-03", False),
    "sec_web_03_hook_params_control.py": ("SEC-WEB-03", False),
    "sec_web_03_hook_prefetch_control.js": ("SEC-WEB-03", False),
    "sec_web_03_hook_session_inline.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_session_var.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_aiohttp.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_url_kw_verb.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_urljoin.py": ("SEC-WEB-03", True),
    "sec_web_03_hook_cache_control.py": ("SEC-WEB-03", False),
    "sec_upload_01_hook_tar.py": ("SEC-UPLOAD-01", True),
    "sec_upload_01_hook_unpack.py": ("SEC-UPLOAD-01", True),
    "sec_upload_01_hook_fully_trusted.py": ("SEC-UPLOAD-01", True),
    "sec_upload_01_ast_only.py": ("SEC-UPLOAD-01", True),
    "sec_upload_01_hook_filtered_control.py": ("SEC-UPLOAD-01", False),
    "sec_upload_01_hook_zip_only_control.py": ("SEC-UPLOAD-01", False),
    "sec_upload_01_hook_other_extract_control.py": ("SEC-UPLOAD-01", False),
    # The call is read to its closing parenthesis, so a filter on a later line counts.
    "sec_upload_01_hook_multiline_filtered_control.py": ("SEC-UPLOAD-01", False),
    "sec_upload_01_hook_multiline_unfiltered.py": ("SEC-UPLOAD-01", True),
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


def marked(name: str, rule: str) -> set[int]:
    return {i for i, line in enumerate((FIX / name).read_text().splitlines(), start=1)
            if f"EXPECT {rule}" in line}


def run_semgrep() -> None:
    print("semgrep")
    if shutil.which("semgrep") is None:
        print("  FAIL semgrep is not installed, so these rules were not exercised at all.")
        failures.append("semgrep missing")
        return
    targets = [str(FIX / n) for n in SEMGREP]
    proc = subprocess.run(
        ["semgrep", "--config", str(RULES), "--no-git-ignore", "--json", "--quiet", *targets],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  FAIL semgrep produced no JSON. stderr: {proc.stderr.strip()[:300]}")
        failures.append("semgrep output")
        return
    check("the rule file parses (no semgrep errors)", len(data.get("errors", [])), 0)
    scanned = {Path(p).name for p in data.get("paths", {}).get("scanned", [])}
    check("every fixture was scanned", sorted(n for n in SEMGREP if n in scanned), sorted(SEMGREP))

    got: dict[tuple[str, str], set[int]] = {}
    for r in data.get("results", []):
        name = Path(r["path"]).name
        for rule in SEMGREP.get(name, []):
            if rule in r["check_id"]:
                got.setdefault((name, rule), set()).add(r["start"]["line"])
    for name, rules in SEMGREP.items():
        for rule in rules:
            want = marked(name, rule)
            if name in POSITIVE:
                check(f"{name} carries {rule} markers", len(want) > 0, True)
            check(f"{name}: {rule} reported on exactly the marked lines",
                  sorted(got.get((name, rule), set())), sorted(want))


def hook_findings(path: Path) -> set[str]:
    """The rule ids the hook REPORTED, read from its bracketed finding lines only."""
    payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(path)}})
    proc = subprocess.run(["bash", str(HOOK)], input=payload, capture_output=True, text=True)
    if not proc.stdout.strip():
        return set()
    try:
        ctx = json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    except (json.JSONDecodeError, KeyError):
        return set()
    return {line.strip().split("]", 1)[0].lstrip("[")
            for line in ctx.splitlines() if line.strip().startswith("[")}


def run_hook() -> None:
    print("hook (dangerous-pattern-warn.sh)")
    check("control, a positive fixture yields at least one finding",
          len(hook_findings(FIX / "sec_db_01_hook_pg_url.py")) > 0, True)
    check("control, a negative fixture yields no finding at all",
          len(hook_findings(FIX / "sec_upload_01_hook_zip_only_control.py")), 0)
    for name, (rule, want) in HOOK_EXPECT.items():
        check(f"{name} reported as {rule}", rule in hook_findings(FIX / name), want)


def main() -> int:
    missing = [n for n in set(SEMGREP) | set(HOOK_EXPECT) if not (FIX / n).is_file()]
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
