#!/usr/bin/env python3
"""SEC-DEP-05: confirm that every package name you are about to depend on really exists.

A coding assistant can write an import or an install line for a package that has never been
published. The name looks right, the code around it looks right, and nothing fails until the
install. Worse, attackers watch for the names assistants tend to invent and publish packages
under them, so the install that should have failed succeeds and runs their code. OWASP lists
this under LLM09:2025 Misinformation ("The model suggests insecure or non-existent code
libraries").

This script asks the registry itself. It runs before the name reaches a manifest, or over a
manifest a change touched.

Usage
  check-package-exists.py pypi:requests npm:left-pad npm:@types/node
  check-package-exists.py --requirements requirements.txt
  check-package-exists.py --package-json package.json
  check-package-exists.py --young-days 90 pypi:some-new-lib   # age below which to ask
  check-package-exists.py --offline registry.json pypi:x      # canned answers, for tests

Exit codes
  0  every name exists on its registry (young names are reported, not failed)
  1  at least one name is not on its registry (the finding), or is not a valid name
  2  the check could not run: a registry was unreachable or answered with an error

Design choices worth keeping:

  - It NEVER exits 0 when it could not ask. A timeout, a 5xx or a rate limit exits 2 and says
    so. Only a 404 counts as "does not exist", because only a 404 is the registry saying so.
  - A name is validated BEFORE it is put into a URL, so a manifest line cannot steer the
    request to another path on the registry.
  - A package that exists but was first published recently is reported as a question, not a
    failure. A new package is often fine; a new package whose name an assistant produced is
    the exact shape of the attack, so a person should look at it.
  - A dependency from outside the registry (a git URL, a local path, a tarball) is listed by
    name for SEC-DEP-02, which owns where a package comes from.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}"

# PEP 508 project names, and npm's documented name rules (lowercase, optional @scope/).
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$")

NON_REGISTRY_NPM = ("file:", "link:", "workspace:", "git+", "git:", "github:",
                    "http:", "https:", "portal:")


class CannotAsk(Exception):
    """The registry did not give a yes-or-no answer."""


def pypi_normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def valid(eco: str, name: str) -> bool:
    if eco == "pypi":
        return bool(PYPI_NAME.match(name))
    return bool(NPM_NAME.match(name)) and len(name) <= 214


# ----------------------------------------------------------------- asking the registry

def fetch_live(eco: str, name: str, timeout: int) -> dict | None:
    """Return registry metadata, None on a 404, raise CannotAsk on anything else."""
    if eco == "pypi":
        url = PYPI_URL.format(name=urllib.parse.quote(pypi_normalise(name), safe=""))
    else:
        url = NPM_URL.format(name=urllib.parse.quote(name, safe="@"))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise CannotAsk(f"{url} answered HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise CannotAsk(f"{url}: {exc}")


def first_published(eco: str, meta: dict) -> dt.datetime | None:
    stamps: list[str] = []
    if eco == "pypi":
        for files in (meta.get("releases") or {}).values():
            stamps.extend(f.get("upload_time_iso_8601", "") for f in files or [])
    else:
        stamps.append((meta.get("time") or {}).get("created", ""))
    parsed = []
    for s in stamps:
        if not s:
            continue
        try:
            parsed.append(dt.datetime.fromisoformat(s.replace("Z", "+00:00")))
        except ValueError:
            continue
    return min(parsed) if parsed else None


class Offline:
    """Canned registry answers: {"pypi": {"name": {...meta...}}, "npm": {...}}.

    A name absent from the file is a 404. The value "__error__" simulates a registry that
    could not answer, so the exit-2 path can be tested without a network.
    """

    def __init__(self, path: str):
        try:
            with open(path, encoding="utf-8") as fh:
                self.data = json.load(fh)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"cannot read the offline registry file {path}: {exc}\n")
            raise SystemExit(2)

    def __call__(self, eco: str, name: str, timeout: int) -> dict | None:
        key = pypi_normalise(name) if eco == "pypi" else name
        meta = self.data.get(eco, {}).get(key)
        if meta == "__error__":
            raise CannotAsk(f"offline registry marks {eco}:{name} as unreachable")
        return meta


# ----------------------------------------------------------------- reading manifests

def names_from_requirements(path: str) -> tuple[list[str], list[str]]:
    names, skipped = [], []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                # -r other.txt, -e path, --index-url: options, not package names.
                if line.startswith(("-e", "--editable")):
                    skipped.append(line)
                continue
            if "://" in line or line.startswith((".", "/")):
                skipped.append(line)
                continue
            if " @ " in line:
                skipped.append(line)
                continue
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if m:
                names.append(m.group(1))
            else:
                skipped.append(line)
    return names, skipped


def names_from_package_json(path: str) -> tuple[list[str], list[str]]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    names, skipped = [], []
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        for name, spec in (doc.get(section) or {}).items():
            spec = str(spec)
            if spec.startswith("npm:"):
                # An alias: the real package is the part after npm:, before the version.
                target = spec[4:]
                at = target.rfind("@")
                names.append(target[:at] if at > 0 else target)
            elif spec.startswith(NON_REGISTRY_NPM) or "/" in spec:
                # a "/" in a version spec is GitHub shorthand (user/repo), never a range.
                skipped.append(f"{name}: {spec}")
            else:
                names.append(name)
    return names, skipped


# ----------------------------------------------------------------- the check

def check(targets: list[tuple[str, str]], fetch, young_days: int, timeout: int,
          now: dt.datetime | None = None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    missing, invalid, young, unreachable, ok = [], [], [], [], 0
    seen = set()
    for eco, name in targets:
        key = (eco, pypi_normalise(name) if eco == "pypi" else name)
        if key in seen:
            continue
        seen.add(key)
        if not valid(eco, name):
            invalid.append(f"{eco}:{name}")
            continue
        try:
            meta = fetch(eco, name, timeout)
        except CannotAsk as exc:
            unreachable.append(f"{eco}:{name}  ({exc})")
            continue
        if meta is None:
            missing.append(f"{eco}:{name}")
            continue
        born = first_published(eco, meta)
        if born is None:
            young.append(f"{eco}:{name}  (exists, but the registry shows no published file)")
        elif (now - born).days < young_days:
            young.append(f"{eco}:{name}  (first published {born.date()}, "
                         f"{(now - born).days} days ago)")
        else:
            ok += 1

    print(f"Checked {len(seen)} package name(s): {ok} established, {len(young)} young, "
          f"{len(missing)} not found, {len(invalid)} invalid, {len(unreachable)} not checked.")
    if missing:
        print("\nNOT ON THE REGISTRY (SEC-DEP-05). Do not install a name to find out whether it")
        print("exists. Find the real package the code meant:")
        for m in missing:
            print(f"  {m}")
    if invalid:
        print("\nNOT A VALID PACKAGE NAME (SEC-DEP-05):")
        for m in invalid:
            print(f"  {m}")
    if young:
        print(f"\nYOUNGER THAN {young_days} DAYS, a question for a person (SEC-DEP-05). Confirm")
        print("the maintainer and that this is the package you meant, not a look-alike:")
        for m in young:
            print(f"  {m}")
    if unreachable:
        print("\nNOT CHECKED: the registry did not answer. Not treating that as clean:")
        for m in unreachable:
            print(f"  {m}")
    if missing or invalid:
        return 1
    if unreachable:
        return 2
    return 0


def parse_target(text: str) -> tuple[str, str]:
    eco, sep, name = text.partition(":")
    if not sep or eco not in ("pypi", "npm") or not name:
        sys.stderr.write(f"'{text}' is not ECOSYSTEM:NAME with ECOSYSTEM pypi or npm\n")
        raise SystemExit(2)
    return eco, name


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Confirm package names exist on their registry.")
    ap.add_argument("target", nargs="*", help="pypi:NAME or npm:NAME")
    ap.add_argument("--requirements", action="append", default=[], metavar="FILE")
    ap.add_argument("--package-json", action="append", default=[], metavar="FILE")
    ap.add_argument("--young-days", type=int, default=90)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--offline", metavar="FILE", help="canned registry answers (tests)")
    args = ap.parse_args(argv)

    targets = [parse_target(t) for t in args.target]
    skipped: list[str] = []
    try:
        for path in args.requirements:
            names, skip = names_from_requirements(path)
            targets += [("pypi", n) for n in names]
            skipped += skip
        for path in args.package_json:
            names, skip = names_from_package_json(path)
            targets += [("npm", n) for n in names]
            skipped += skip
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"cannot read a manifest: {exc}\n")
        return 2

    if skipped:
        print("From outside the registry, listed for SEC-DEP-02, which owns where a package comes from:")
        for s in skipped:
            print(f"  {s}")
        print()
    if not targets:
        print("No package names given, nothing to check.")
        return 0

    fetch = Offline(args.offline) if args.offline else fetch_live
    return check(targets, fetch, args.young_days, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
