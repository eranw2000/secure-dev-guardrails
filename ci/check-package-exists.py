#!/usr/bin/env python3
"""SEC-DEP-05: confirm that every package name you are about to depend on really exists.

A coding assistant can write an import or an install line for a package that has never been
published. The name looks right, the code around it looks right, and nothing fails until the
install. Worse, attackers watch for the names assistants tend to invent and publish packages
under them, so the install that should have failed succeeds and runs their code. OWASP lists
this under LLM09:2025 Misinformation ("The model suggests insecure or non-existent code
libraries").

This script asks the public registry itself. It runs before the name reaches a manifest, or
over a manifest a change touched.

Usage
  check-package-exists.py pypi:requests npm:left-pad npm:@types/node
  check-package-exists.py --requirements requirements.txt   # follows -r and -c on disk
  check-package-exists.py --package-json package.json       # reads the .npmrc beside it
  check-package-exists.py --young-days 90 pypi:some-new-lib   # age below which to ask
  check-package-exists.py --offline registry.json pypi:x      # canned answers, for tests

Exit codes
  0  every name checked exists on its registry (young names are listed, not failed)
  1  at least one name is not on its registry (the finding), or is not a valid name
  2  the run is incomplete: a registry did not give a usable answer for some name, or a
     manifest could not be read. This wins over 1, because a run that could not ask about
     every name has not answered the question, whatever else it found.

Design choices worth keeping:

  - It NEVER exits 0 when it could not ask. A timeout, a reset connection, a 5xx, a rate
    limit, or a 200 whose body is not a registry answer for that name all exit 2. Only a 404
    counts as "does not exist", because only a 404 is the registry saying so.
  - A name is validated BEFORE it is put into a URL, so a manifest line cannot steer the
    request to another path on the registry.
  - A package that exists but was first published recently is listed as a question, not a
    failure. A new package is often fine; a new package whose name an assistant produced is
    the exact shape of the attack, so a person should look at it. Whether a name is a
    near-miss of a well-known package is also a question for a person, which the
    dependency-review skill asks at its step 6.
  - The public registry is the right place to ask only when it is where the install will
    look. An index named anywhere in a requirements file's include tree, or an .npmrc that
    maps a scope or replaces the default registry, sends those names to a person to confirm
    against that registry instead. An include at a URL exits 2 and names the file to fetch.
  - A registry address is printed without its login or query, because index URLs often
    carry credentials and this output lands in CI logs.
  - A dependency from outside any registry (a git URL, a local path, a tarball) is listed by
    name for SEC-DEP-02, which owns where a package comes from.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}"
PUBLIC_PYPI_INDEXES = {"https://pypi.org/simple", "https://pypi.python.org/simple"}
PUBLIC_NPM_REGISTRIES = {"https://registry.npmjs.org", "https://registry.npmjs.com"}

# PEP 508 project names, and npm's documented name rules (lowercase, optional @scope/).
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$")

NON_REGISTRY_NPM = ("file:", "link:", "workspace:", "git+", "git:", "github:",
                    "http:", "https:", "portal:")

REQ_INCLUDE = re.compile(r"^(-r|--requirement|-c|--constraint)(?:\s+|=)\s*(\S+)$")
REQ_INDEX = re.compile(r"^(-i|--index-url|--extra-index-url|-f|--find-links)(?:\s+|=)\s*(\S+)$")
REQ_DIRECT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*@")
REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def redact(url: str) -> str:
    """A registry address fit for a log: scheme, host, port and path, never a login or query.

    Index and registry URLs often carry a user and password or a token, and this script's
    output lands in CI logs.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<an address that could not be parsed>"
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


def is_public_pypi(url: str) -> bool:
    return redact(url).rstrip("/") in PUBLIC_PYPI_INDEXES


def is_public_npm(url: str) -> bool:
    return redact(url).rstrip("/") in PUBLIC_NPM_REGISTRIES


class CannotAsk(Exception):
    """The registry did not give a usable yes-or-no answer."""


def pypi_normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def valid(eco: str, name: str) -> bool:
    if eco == "pypi":
        return bool(PYPI_NAME.match(name))
    return bool(NPM_NAME.match(name)) and len(name) <= 214


# ----------------------------------------------------------------- asking the registry

def fetch_live(eco: str, name: str, timeout: int):
    """Return the decoded registry answer, None on a 404, raise CannotAsk on anything else."""
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
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        # OSError covers a timeout and a connection reset mid-read; HTTPException covers a
        # truncated body; ValueError covers a body that is not JSON or not UTF-8.
        raise CannotAsk(f"{url}: {type(exc).__name__}: {exc}")


def require_shape(eco: str, name: str, meta) -> None:
    """A 200 is only an answer if its body is a registry document about this name."""
    if not isinstance(meta, dict):
        raise CannotAsk(f"the registry answered for {eco}:{name} with a "
                        f"{type(meta).__name__}, not a package document")
    if eco == "pypi":
        if not isinstance(meta.get("info"), dict) or not isinstance(meta.get("releases"), dict):
            raise CannotAsk(f"the PyPI answer for {name} has no info and releases objects")
        answered = str(meta["info"].get("name") or "")
        if pypi_normalise(answered) != pypi_normalise(name):
            raise CannotAsk(f"the PyPI answer for {name} names {answered!r}")
    else:
        if meta.get("name") != name:
            raise CannotAsk(f"the npm answer for {name} names {meta.get('name')!r}")
        if not isinstance(meta.get("time", {}), dict):
            raise CannotAsk(f"the npm answer for {name} has a time field that is not an object")


def first_published(eco: str, meta: dict) -> dt.datetime | None:
    stamps: list[str] = []
    if eco == "pypi":
        for files in meta["releases"].values():
            for f in files if isinstance(files, list) else []:
                if isinstance(f, dict):
                    stamps.append(str(f.get("upload_time_iso_8601") or ""))
    else:
        stamps.append(str((meta.get("time") or {}).get("created") or ""))
    parsed = []
    for s in stamps:
        try:
            when = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            continue
        # Both registries publish UTC. A stamp without a zone is read as UTC rather than
        # compared with an aware clock, which Python refuses.
        parsed.append(when if when.tzinfo else when.replace(tzinfo=dt.timezone.utc))
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

    def __call__(self, eco: str, name: str, timeout: int):
        key = pypi_normalise(name) if eco == "pypi" else name
        meta = self.data.get(eco, {}).get(key)
        if meta == "__error__":
            raise CannotAsk(f"offline registry marks {eco}:{name} as unreachable")
        return meta


# ----------------------------------------------------------------- reading manifests

class Manifests:
    """What the manifests asked for, sorted by who should confirm each name.

    names:       ask the public registry (the targets of this script)
    elsewhere:   listed for SEC-DEP-02, because they do not come from a registry at all
    other_index: listed for a person, because the install looks in a registry other than
                 the public one, so the public registry is the wrong place to ask
    """

    def __init__(self):
        self.names: list[tuple[str, str]] = []
        self.elsewhere: list[str] = []
        self.other_index: list[str] = []


def _logical_lines(text: str) -> list[str]:
    out, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _walk_requirements(path: str, seen: set[str], entries: list[str],
                       indexes: list[str], into: Manifests) -> None:
    real = os.path.realpath(path)
    if real in seen:
        return
    seen.add(real)
    with open(path, encoding="utf-8") as fh:
        lines = _logical_lines(fh.read())
    here = os.path.dirname(path)
    for raw in lines:
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        idx = REQ_INDEX.match(line)
        if idx:
            url = idx.group(2)
            if idx.group(1) in ("-f", "--find-links") or not is_public_pypi(url):
                indexes.append(url)
            continue
        inc = REQ_INCLUDE.match(line)
        if inc:
            target = inc.group(2)
            if "://" in target:
                # pip fetches a URL include; this script asks the caller to, and exits 2 meanwhile.
                raise ValueError(f"{path} includes {redact(target)}; fetch that file and "
                                 "pass it with --requirements")
            _walk_requirements(os.path.join(here, target), seen, entries, indexes, into)
            continue
        if line.startswith("-"):
            if line.startswith(("-e", "--editable")):
                into.elsewhere.append(line)
            continue  # other options are not package names
        entries.append(line)


def read_requirements(path: str, into: Manifests) -> None:
    """Read a requirements file and every file it includes, then sort the names.

    pip applies index options to the whole resolution, wherever in the include tree they
    sit, so one private index anywhere in the tree covers every name in it.
    """
    entries: list[str] = []
    indexes: list[str] = []
    _walk_requirements(path, set(), entries, indexes, into)
    index = redact(indexes[0]) if indexes else None
    for line in entries:
        if "://" in line or line.startswith((".", "/")) or REQ_DIRECT_REF.match(line):
            into.elsewhere.append(line)
            continue
        m = REQ_NAME.match(line)
        if not m:
            into.elsewhere.append(line)
        elif index:
            into.other_index.append(f"{m.group(1)}  (index {index})")
        else:
            into.names.append(("pypi", m.group(1)))


def _npmrc_registries(package_json: str) -> tuple[str | None, dict[str, str]]:
    """The project's .npmrc: a replaced default registry, and any scope mappings."""
    default, scopes = None, {}
    rc = os.path.join(os.path.dirname(package_json), ".npmrc")
    if not os.path.exists(rc):
        return default, scopes
    with open(rc, encoding="utf-8") as fh:
        for raw in fh:
            key, sep, value = raw.strip().partition("=")
            key, value = key.strip(), value.strip().rstrip("/")
            if not sep or key.startswith((";", "#")):
                continue
            # npm reads the file top to bottom and the last assignment of a key wins, so a
            # later line pointing back at the public registry clears an earlier private one.
            private = None if is_public_npm(value) else redact(value)
            if key == "registry":
                default = private
            elif key.startswith("@") and key.endswith(":registry"):
                scope = key[: -len(":registry")]
                if private:
                    scopes[scope] = private
                else:
                    scopes.pop(scope, None)
    return default, scopes


def read_package_json(path: str, into: Manifests) -> None:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} is not a JSON object")
    default, scopes = _npmrc_registries(path)
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        deps = doc.get(section) or {}
        if not isinstance(deps, dict):
            raise ValueError(f"{path}: {section} is not an object")
        for name, spec in deps.items():
            spec = str(spec)
            if spec.startswith("npm:"):
                # An alias: the real package is the part after npm:, before the version.
                target = spec[4:]
                at = target.rfind("@")
                real = target[:at] if at > 0 else target
            elif spec.startswith(NON_REGISTRY_NPM) or "/" in spec:
                # a "/" in a version spec is GitHub shorthand (user/repo), never a range.
                into.elsewhere.append(f"{name}: {spec}")
                continue
            else:
                real = name
            scope = real.split("/", 1)[0] if real.startswith("@") else None
            registry = scopes.get(scope) or default
            if registry:
                into.other_index.append(f"{real}  (registry {registry})")
            else:
                into.names.append(("npm", real))


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
            if meta is None:
                missing.append(f"{eco}:{name}")
                continue
            require_shape(eco, name, meta)
            born = first_published(eco, meta)
        except CannotAsk as exc:
            unreachable.append(f"{eco}:{name}  ({exc})")
            continue
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
        print("\nNOT CHECKED: the registry did not give a usable answer. Not treating that as")
        print("clean, so the run exits 2:")
        for m in unreachable:
            print(f"  {m}")
        return 2
    if missing or invalid:
        return 1
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

    found = Manifests()
    found.names = [parse_target(t) for t in args.target]
    try:
        for path in args.requirements:
            read_requirements(path, found)
        for path in args.package_json:
            read_package_json(path, found)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"cannot read a manifest: {exc}\n")
        return 2

    if found.elsewhere:
        print("From outside any registry, listed for SEC-DEP-02, which owns where a package "
              "comes from:")
        for s in found.elsewhere:
            print(f"  {s}")
        print()
    if found.other_index:
        print("INSTALLED FROM A CONFIGURED REGISTRY, a question for a person (SEC-DEP-05).")
        print("Confirm each name on that registry; the public one is the wrong place to ask:")
        for s in found.other_index:
            print(f"  {s}")
        print()
    if not found.names:
        print("No names for the public registries, nothing to check there.")
        return 0

    fetch = Offline(args.offline) if args.offline else fetch_live
    return check(found.names, fetch, args.young_days, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
