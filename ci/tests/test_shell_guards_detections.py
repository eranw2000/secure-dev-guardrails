#!/usr/bin/env python3
"""Regression tests for the Bash guards, both directions.

    python3 ci/tests/test_shell_guards_detections.py

Each guard runs as a real process on a hook payload, with an empty HOME so nothing
outside this pack is imported. Every command that must fire has a twin that must stay
quiet, because a guard that fires on everything passes half its tests. Commands are only
read by the hooks, never run.

The last group asks secret-scan-git.py which repository a commit or push lands in when
the folder is named by a shell variable. None means the command is refused, and a None
with no refusal would be a silent pass, so `lands_in` fails the row in that case.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__":
    for _stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent.parent / "hooks"

BLOCK, WARN, QUIET = "block", "warn", "quiet"

ROWS = [
    ("destructive-command-guard.py", "rm -rf /srv/data", BLOCK),
    ("destructive-command-guard.py", "git push --force origin main", BLOCK),
    ("destructive-command-guard.py", "git status", QUIET),
    ("destructive-command-guard.py", "git push origin main", QUIET),
    ("chain-abort-guard.py", "cd sub && echo x > out.txt", WARN),
    ("chain-abort-guard.py", "cd /tmp && echo x > out.txt", QUIET),
    ("chain-abort-guard.py", "echo ====", WARN),
    ("chain-abort-guard.py", "echo '===='", QUIET),
    ("shell-status-guard.py", "until ! pgrep -f myjob; do sleep 1; done", BLOCK),
    ("shell-status-guard.py", 'cmd | tail -5; echo "EXIT=$?"', WARN),
    ("shell-status-guard.py", 'cmd > log 2>&1; echo "EXIT=$?"', QUIET),
    ("write-then-remote-guard.py", "cat > /tmp/a.txt <<'EOF'\nx\nEOF\ngit push origin work", WARN),
    ("write-then-remote-guard.py", "cat > /tmp/a.txt <<'EOF'\nx\nEOF\n", QUIET),
    ("write-then-remote-guard.py", "git push origin work", QUIET),
]

# Where the repository is: (command, repository or None for refused).
LANDS_IN = [
    ("git -C /lit commit -m x", "/lit"),
    ("cd /lit && git push origin main", "/lit"),
    ("W=/a/r; git -C $W commit -m x", "/a/r"),
    ('W=/a/r; git -C "$W" push origin main', "/a/r"),
    ("R=/a/r; cd $R && git commit -m x", "/a/r"),
    ("R=/a/r; cd $R && git push origin main", "/a/r"),
    ('set -e; D=/a/r; echo "D=$D"; git -C $D commit', "/a/r"),
    ("T=$(mktemp -d /tmp/x.XXXX); cd $T && git commit -m i", "/tmp"),
    ("W=/s; if false; then W=/c; fi; git -C $W commit", None),
    ("W=/s; (W=/c); git -C $W commit", None),
    ("if true; then R=/s; else R=/c; fi; cd $R && git commit", None),
    ("W=/s; W+=/x; git -C $W commit", None),
    ("cd $GUARDS_TEST_UNSET_NAME && git commit -m x", None),
    ("git -C $GUARDS_TEST_UNSET_NAME commit -m x", None),
    ("for p in /x/*; do git -C $p push; done", None),
]


def verdict(hook: str, command: str, home: str) -> str:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "ci", "cwd": home,
               "tool_input": {"command": command}}
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    done = subprocess.run([sys.executable, str(HOOKS / hook)], input=json.dumps(payload), capture_output=True,
                          text=True, encoding="utf-8", env=env, cwd=home)
    if done.returncode == 2:
        return BLOCK
    if done.returncode != 0:
        return "crash %d: %s" % (done.returncode, done.stderr[-120:])
    return WARN if "additionalContext" in done.stdout else QUIET


def load_secret_scan():
    sys.path.insert(0, str(HOOKS))
    spec = importlib.util.spec_from_file_location("_secret_scan_git", HOOKS / "secret-scan-git.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lands_in(mod, command: str):
    calls = mod._git_calls(command, "/c", ("commit", "push"))
    if len(calls) != 1:
        return "%d calls" % len(calls)
    call = calls[0]
    if call["repo"] is None:
        return None if call["shape"] else "no refusal"
    return os.path.normpath(call["repo"]).replace(os.sep, "/")


def main() -> int:
    failed = []
    with tempfile.TemporaryDirectory() as home:
        for hook, command, want in ROWS:
            got = verdict(hook, command, home)
            if got != want:
                failed.append("%s %r: got %s, want %s" % (hook, command, got, want))
    os.environ.pop("GUARDS_TEST_UNSET_NAME", None)
    mod = load_secret_scan()
    for command, want in LANDS_IN:
        got = lands_in(mod, command)
        if got != want:
            failed.append("secret-scan-git %r: got %s, want %s" % (command, got, want))
    total = len(ROWS) + len(LANDS_IN)
    for line in failed:
        print("FAIL", line)
    print("%d of %d passed" % (total - len(failed), total))
    return 1 if failed or not total else 0


if __name__ == "__main__":
    sys.exit(main())
