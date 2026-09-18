#!/usr/bin/env python3
"""Regression tests for SEC-DEP-05, ci/check-package-exists.py, both directions.

    python3 ci/tests/test_sec_dep_05_detections.py

Runs offline against canned registry answers in fixtures/sec_dep_05_registry.json, so CI
never depends on a registry being up. Every case that must FAIL has a sibling that must
PASS, because a checker that reports everything as missing passes half its tests.

The exit-2 cases matter most. A check that reads "clean" when it could not ask is worse
than no check, so "registry unreachable" and "offline file unreadable" are each tested to
exit 2 and never 0.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
PACK = HERE.parent.parent
SCRIPT = PACK / "ci" / "check-package-exists.py"
FIXTURE = FIX / "sec_dep_05_registry.json"
# Filled in by main(): the fixture with its one relative date made real.
REGISTRY = Path()

results: list[tuple[str, bool, str]] = []


def run(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--offline", str(REGISTRY), *args],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def case(name: str, args: list[str], code: int, must_say: list[str] = (),
         must_not_say: list[str] = ()) -> None:
    got, out = run(*args)
    ok = got == code and all(s in out for s in must_say) \
        and not any(s in out for s in must_not_say)
    results.append((name, ok, f"exit {got}, wanted {code}\n{out}"))


def write(tmp: Path, name: str, text: str) -> str:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def live_network_cases() -> None:
    """The code that talks to the real registry, with the network replaced.

    The offline file stands in for fetch_live everywhere above, so without these a broken
    404 test in fetch_live would pass every case. Each fake answers one way, and the
    function must turn it into the right outcome and ask for the right address.
    """
    import urllib.error

    spec = importlib.util.spec_from_file_location("check_package_exists", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    asked: list[str] = []

    def fake(answer):
        def urlopen(req, timeout):
            asked.append(req.full_url)
            if isinstance(answer, Exception):
                raise answer
            return io.BytesIO(answer)
        return urlopen

    def http_error(code):
        return urllib.error.HTTPError("u", code, "x", {}, None)

    def outcome(eco, name, answer):
        mod.urllib.request.urlopen = fake(answer)
        try:
            return mod.fetch_live(eco, name, 1)
        except mod.CannotAsk:
            return "cannot-ask"

    checks = [
        ("live: a 404 means the package does not exist",
         outcome("pypi", "x", http_error(404)) is None),
        ("live: a 503 is not a 404, so it cannot be read as missing or clean",
         outcome("pypi", "x", http_error(503)) == "cannot-ask"),
        ("live: a rate limit (429) cannot be read as missing or clean",
         outcome("npm", "x", http_error(429)) == "cannot-ask"),
        ("live: no network cannot be read as clean",
         outcome("npm", "x", urllib.error.URLError("down")) == "cannot-ask"),
        ("live: a body that is not JSON cannot be read as clean",
         outcome("npm", "x", b"<html>") == "cannot-ask"),
        ("live: a 200 returns the metadata",
         outcome("npm", "left-pad", b'{"time": {"created": "2014-03-14T00:00:00Z"}}')
         == {"time": {"created": "2014-03-14T00:00:00Z"}}),
    ]
    asked.clear()
    outcome("pypi", "Python_Dateutil", b"{}")
    outcome("npm", "@types/node", b"{}")
    checks += [
        ("live: PyPI is asked for the normalised name",
         asked[0] == "https://pypi.org/pypi/python-dateutil/json"),
        ("live: a scoped npm name keeps its @ and encodes the slash",
         asked[1] == "https://registry.npmjs.org/@types%2Fnode"),
    ]
    for name, ok in checks:
        results.append((name, ok, f"asked: {asked}"))


def main() -> int:
    global REGISTRY
    five_days_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    text = FIXTURE.read_text(encoding="utf-8")
    assert text.count("__FIVE_DAYS_AGO__") == 2, "fixture lost a relative date"
    work = Path(tempfile.mkdtemp())
    REGISTRY = work / "registry.json"
    REGISTRY.write_text(text.replace("__FIVE_DAYS_AGO__", five_days_ago), encoding="utf-8")

    # --- names on the command line, both directions -------------------------------------
    case("an established PyPI package passes", ["pypi:requests"], 0,
         ["1 established"], ["NOT ON THE REGISTRY"])
    case("an invented PyPI name is reported and fails", ["pypi:requests-oauth-helperz"], 1,
         ["NOT ON THE REGISTRY", "pypi:requests-oauth-helperz"])
    case("an established npm package passes", ["npm:left-pad"], 0, ["1 established"])
    case("an invented npm name is reported and fails", ["npm:left-padz"], 1,
         ["NOT ON THE REGISTRY", "npm:left-padz"])
    case("a scoped npm package passes", ["npm:@types/node"], 0, ["1 established"])
    case("an invented scope fails", ["npm:@typez/node"], 1, ["npm:@typez/node"])
    case("PyPI names match after normalising case and separators", ["pypi:Python_Dateutil"], 0,
         ["1 established"])
    case("one invented name among real ones still fails the run",
         ["pypi:requests", "npm:left-pad", "pypi:fastapi-auth-magic"], 1,
         ["2 established", "1 not found", "pypi:fastapi-auth-magic"])
    case("a duplicate is checked once", ["pypi:requests", "pypi:Requests"], 0,
         ["Checked 1 package name"])

    # --- young packages are a question, not a failure -----------------------------------
    case("a package first published days ago is flagged young but passes",
         ["pypi:brand-new-lib"], 0, ["YOUNGER THAN 90 DAYS", "pypi:brand-new-lib"])
    case("the age line moves with --young-days",
         ["--young-days", "1", "pypi:brand-new-lib"], 0, ["1 established"],
         ["YOUNGER THAN"])
    case("an old package is not flagged young", ["pypi:requests"], 0, [], ["YOUNGER THAN"])
    case("age is the FIRST release, not the latest: an old project with a new release "
         "is established", ["pypi:old-lib-new-release"], 0, ["1 established"],
         ["YOUNGER THAN"])
    case("a project with no published file is a question", ["pypi:empty-shell"], 0,
         ["no published file"])

    # --- could not ask: never clean ------------------------------------------------------
    case("an unreachable registry exits 2, not 0", ["pypi:flaky-lookup"], 2,
         ["NOT CHECKED", "Not treating that as clean"])
    case("a missing name outranks an unreachable one", ["pypi:flaky-lookup", "npm:left-padz"],
         1, ["NOT CHECKED", "npm:left-padz"])
    got, out = subprocess.run(
        [sys.executable, str(SCRIPT), "--offline", "/nonexistent/registry.json", "pypi:x"],
        capture_output=True, text=True).returncode, ""
    results.append(("an unreadable offline file exits 2", got == 2, f"exit {got}"))

    # --- names that must never reach a URL -----------------------------------------------
    case("a name with a path in it is refused", ["pypi:../simple"], 1, ["NOT A VALID"])
    case("an npm name with capitals is refused", ["npm:Left-Pad"], 1, ["NOT A VALID"])
    case("a query string is refused", ["npm:left-pad?x=1"], 1, ["NOT A VALID"])
    case("a bad ecosystem is refused, not ignored", ["cargo:serde"], 2, ["pypi or npm"])

    # --- manifests ------------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        req = write(tmp, "requirements.txt", "\n".join([
            "# a comment",
            "-r base.txt",
            "--index-url https://pypi.org/simple",
            "requests[security]>=2.31  # inline comment",
            "python-dateutil==2.9.0; python_version >= '3.8'",
            "requests-oauth-helperz==0.1",
            "-e ./local-pkg",
            "mylib @ https://example.com/mylib.tar.gz",
            "git+https://github.com/org/repo.git",
            "internal @ file:wheels/internal.whl",
        ]))
        case("requirements: the invented name is found among real ones",
             ["--requirements", req], 1,
             ["2 established", "1 not found", "pypi:requests-oauth-helperz"])
        case("requirements: URL, path and editable lines are listed for SEC-DEP-02",
             ["--requirements", req], 1,
             ["mylib @ https://example.com", "git+https://github.com", "-e ./local-pkg",
              "internal @ file:wheels"])
        case("requirements: comments and options are neither checked nor listed",
             ["--requirements", req], 1, [], ["# a comment", "-r base.txt", "--index-url"])
        clean_req = write(tmp, "clean.txt", "requests==2.32.0\npython-dateutil\n")
        case("requirements: a clean file passes", ["--requirements", clean_req], 0,
             ["2 established"], ["NOT ON THE REGISTRY"])

        pkg = write(tmp, "package.json", """{
          "dependencies": {"left-pad": "^1.3.0", "left-padz": "1.0.0",
                           "local": "file:../local", "fork": "user/repo",
                           "packed": "file:packed.tgz", "sibling": "workspace:*"},
          "devDependencies": {"@types/node": "^20", "renamed": "npm:left-pad@1.3.0"}
        }""")
        case("package.json: the invented name fails, aliases resolve to the real package",
             ["--package-json", pkg], 1,
             ["2 established", "1 not found", "npm:left-padz"])
        case("package.json: file and GitHub-shorthand specs are listed for SEC-DEP-02",
             ["--package-json", pkg], 1, ["local: file:../local", "fork: user/repo",
                                        "packed: file:packed.tgz", "sibling: workspace:*"])
        broken = write(tmp, "broken.json", "{not json")
        case("package.json: an unreadable manifest exits 2", ["--package-json", broken], 2,
             ["cannot read a manifest"])

    case("no names at all is reported, and is not a finding", [], 0, ["nothing to check"])

    live_network_cases()
    shutil.rmtree(work, ignore_errors=True)

    bad = 0
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            bad += 1
            print("        " + detail.replace("\n", "\n        "))
    print(f"--- SEC-DEP-05: {len(results) - bad}/{len(results)} ---")
    if len(results) < 37:
        print("FAIL: fewer cases ran than are written here; the runner is broken")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
