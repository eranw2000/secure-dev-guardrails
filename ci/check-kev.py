#!/usr/bin/env python3
"""SEC-DEP-04: check advisory IDs against CISA's Known Exploited Vulnerabilities catalogue.

A CVSS score is a guess about how bad a flaw could be. A KEV listing is a statement that
somebody is exploiting it now, and it carries a remediation date set by CISA rather than by
whoever is triaging. That is why a KEV hit outranks its score.

Usage
  check-kev.py CVE-2021-44228 CVE-2020-1938        # ids as arguments
  pip-audit -r requirements.txt -f json | check-kev.py --pip-audit -
  check-kev.py --catalogue kev.json CVE-...        # offline copy, for an air-gapped runner
  check-kev.py --self-test                         # controls, no network needed

Exit codes
  0  no id given was listed
  1  at least one id is listed (the finding)
  2  the check could not run

Two design choices worth keeping, because both are the difference between a check and a
decoration:

  - It NEVER exits 0 when it could not read the catalogue. An unreachable feed exits 2 and
    says so. A KEV check that reports "clean" because the network was down is worse than no
    check, because it converts a look into a tick.
  - It matches on the CVE ID and nothing else. A KEV entry names a vendor and a product, not
    a package on your registry, so matching by package name invents both false positives and
    false negatives. Feed it the advisory IDs your SCA tool actually reported.

What it does not do: decide whether the vulnerable path is reachable in your code. That stays
a judgement call for the dependency-review skill, and SEC-DEP-04 says what to do with it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def load_catalogue(path: str | None, timeout: int) -> dict:
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except OSError as exc:
            sys.stderr.write(f"cannot read the catalogue at {path}: {exc}\n")
            raise SystemExit(2)
    try:
        with urllib.request.urlopen(FEED, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        sys.stderr.write(
            f"cannot reach the KEV catalogue: {exc}\n"
            "Not treating that as clean. Re-run when the network is back, or pass a cached\n"
            "copy with --catalogue. A KEV check that passes because it could not look is\n"
            "worse than no check at all.\n"
        )
        raise SystemExit(2)


def index(cat: dict) -> dict[str, dict]:
    return {v["cveID"].upper(): v for v in cat.get("vulnerabilities", [])}


def ids_from_args(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.cve)
    if args.pip_audit:
        text = sys.stdin.read() if args.pip_audit == "-" else open(args.pip_audit).read()
        try:
            doc = json.loads(text)
        except ValueError:
            sys.stderr.write("--pip-audit input is not JSON\n")
            raise SystemExit(2)
        deps = doc.get("dependencies", doc if isinstance(doc, list) else [])
        for d in deps:
            for v in d.get("vulns", []) or []:
                for candidate in [v.get("id", "")] + list(v.get("aliases", []) or []):
                    raw.extend(CVE_RE.findall(candidate or ""))
    if args.stdin:
        raw.extend(CVE_RE.findall(sys.stdin.read()))
    seen, out = set(), []
    for cid in raw:
        u = cid.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def report(ids: list[str], kev: dict[str, dict]) -> int:
    hits = [(i, kev[i]) for i in ids if i in kev]
    print(f"KEV catalogue: {len(kev)} entries. Checked {len(ids)} advisory id(s).")
    if not hits:
        print("No id given is in the catalogue.")
        return 0
    print(f"\n{len(hits)} LISTED AS KNOWN EXPLOITED (SEC-DEP-04):\n")
    for cid, v in hits:
        ransom = v.get("knownRansomwareCampaignUse", "Unknown")
        print(f"  {cid}  {v.get('vendorProject','?')} {v.get('product','?')}")
        print(f"    added {v.get('dateAdded','?')}   CISA remediation due {v.get('dueDate','?')}")
        print(f"    used in a known ransomware campaign: {ransom}")
        action = " ".join((v.get("requiredAction") or "").split())
        if action:
            print(f"    required action: {action[:160]}")
        print()
    return 1


def self_test() -> int:
    """Controls. A checker that cannot fail is the thing this file exists to avoid."""
    cat = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates."},
    ]}
    kev = index(cat)
    checks = [
        ("a listed id is reported", report(["CVE-2021-44228"], kev) == 1),
        ("an unlisted id is not", report(["CVE-1999-0001"], kev) == 0),
        ("matching is case-insensitive", report(["cve-2021-44228".upper()], kev) == 1),
        ("no ids given is not a pass by accident", report([], kev) == 0),
        ("an id that only LOOKS similar is not matched", report(["CVE-2021-4422"], kev) == 0),
    ]
    print("\n--- self-test ---")
    bad = 0
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        bad += 0 if ok else 1
    # The control that matters: an unreachable catalogue must NOT look clean.
    try:
        load_catalogue("/nonexistent/kev.json", 1)
        print("  FAIL  an unreadable catalogue exited 0")
        bad += 1
    except SystemExit as exc:
        ok = exc.code == 2
        print(f"  {'PASS' if ok else 'FAIL'}  an unreadable catalogue exits 2, not 0")
        bad += 0 if ok else 1
    print(f"--- {len(checks)+1 - bad}/{len(checks)+1} ---")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Check advisory IDs against the CISA KEV catalogue.")
    ap.add_argument("cve", nargs="*", help="CVE ids")
    ap.add_argument("--catalogue", help="path to a saved copy of the KEV JSON")
    ap.add_argument("--pip-audit", metavar="FILE", help="pip-audit JSON ('-' for stdin)")
    ap.add_argument("--stdin", action="store_true", help="scrape CVE ids from stdin text")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    ids = ids_from_args(args)
    if not ids:
        print("No advisory ids given, nothing to check.")
        print("Pass CVE ids, or pipe your SCA output with --pip-audit or --stdin.")
        return 0

    return report(ids, index(load_catalogue(args.catalogue, args.timeout)))


if __name__ == "__main__":
    sys.exit(main())
