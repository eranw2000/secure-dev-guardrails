#!/usr/bin/env python3
"""Regression tests for the four shell-safety hooks, both directions.

    python3 ci/tests/test_shell_safety_hooks_detections.py

Covers hooks/write-then-remote-guard.py, hooks/chain-abort-guard.py,
hooks/shell-status-guard.py and hooks/destructive-command-guard.py. Each hook gets the
JSON envelope Claude Code sends a PreToolUse hook, on stdin, and the test reads what
Claude Code reads: exit 2 is a block, exit 0 with `hookSpecificOutput.additionalContext`
on stdout is a warning, exit 0 with nothing is a pass.

Every case that must BLOCK or WARN has a sibling that must stay QUIET, because a hook
that blocks everything passes half its tests, and one that blocks nothing passes the
other half.

Every hook runs with HOME set to an empty folder, so nothing can be borrowed from an
existing ~/.claude/hooks install. SHELL_HOOKS_DIR points the test at another hooks
folder; pointing it at hooks that do nothing must turn this run red.

SHELL is set to zsh for every run unless a case says otherwise, because several checks
describe zsh behaviour and run only when zsh is the shell Claude Code uses; the cases
that set SHELL to bash prove those checks stay quiet there.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE.parent.parent
HOOKS = Path(os.environ.get("SHELL_HOOKS_DIR") or PACK / "hooks")

WRITE_REMOTE = "write-then-remote-guard.py"
CHAIN_ABORT = "chain-abort-guard.py"
SHELL_STATUS = "shell-status-guard.py"
DESTRUCTIVE = "destructive-command-guard.py"

BLOCK, WARN, QUIET = "block", "warn", "quiet"

results: list[tuple[str, bool, str]] = []

# One empty HOME for every hook run.
FAKE_HOME = tempfile.mkdtemp(prefix="shell-hooks-home-")


def run_hook(hook: str, command: str, cwd: str, background: bool = False,
             env_extra: dict | None = None) -> tuple[str, str]:
    """(verdict, output) for one PreToolUse call."""
    path = HOOKS / hook
    if not path.is_file():
        return "missing", f"no hook at {path}"
    envelope = {"tool_name": "Bash", "cwd": cwd,
                "tool_input": {"command": command, "run_in_background": background}}
    env = {"HOME": FAKE_HOME, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "SHELL": "/bin/zsh"}
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, str(path)], input=json.dumps(envelope),
                          capture_output=True, text=True, env=env, cwd=cwd)
    out = proc.stdout + proc.stderr
    if proc.returncode == 2:
        return BLOCK, out
    if proc.returncode != 0:
        return f"crash (exit {proc.returncode})", out
    if "additionalContext" in proc.stdout:
        try:
            payload = json.loads(proc.stdout)
        except ValueError:
            return "bad warning JSON", out
        hso = payload.get("hookSpecificOutput") or {}
        if hso.get("hookEventName") != "PreToolUse":
            return "warning without hookEventName", out
        return WARN, out
    if proc.stdout.strip() or proc.stderr.strip():
        return "unexpected output", out
    return QUIET, out


def case(name: str, hook: str, command: str, want: str, cwd: str,
         must_say: str = "", background: bool = False,
         env_extra: dict | None = None) -> None:
    got, out = run_hook(hook, command, cwd, background, env_extra)
    ok = got == want and (not must_say or must_say in out)
    results.append((f"{hook}: {name}", ok, f"got {got}, wanted {want}\n{out}"))


def git_repo(root: Path, name: str, dirty: bool) -> str:
    d = root / name
    d.mkdir()
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null",
               HOME=FAKE_HOME)
    git = lambda *a: subprocess.run(["git", *a], cwd=d, env=env, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (d / "tracked.py").write_text("original\n")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    if dirty:
        (d / "tracked.py").write_text("an unsaved edit\n")
    return str(d)


def write_then_remote_cases(cwd: str) -> None:
    h = WRITE_REMOTE
    case("a heredoc write and then git commit in one call blocks", h,
         "cat > msg.txt <<'EOF'\nfix the parser\nEOF\ngit add a.py && git commit -F msg.txt",
         BLOCK, cwd, "creates a file AND then reaches out")
    case("the same commit with the message on stdin is quiet", h,
         "git commit -F - <<'EOF'\nfix the parser\nEOF", QUIET, cwd)
    case("a heredoc write with nothing after it is quiet", h,
         "cat > notes.txt <<'EOF'\nsome notes\nEOF", QUIET, cwd)
    case("a write then a fetch from a remote host blocks", h,
         "echo '{}' > body.json && curl -s -X POST https://api.example.com/v1 -d @body.json",
         BLOCK, cwd)
    case("a write then a localhost fetch is quiet", h,
         "echo '{}' > body.json && curl -s http://localhost:8000/health", QUIET, cwd)
    case("a fetch BEFORE the write (output capture) is quiet", h,
         "curl -s https://api.example.com/v1 | tee run.log", QUIET, cwd)
    case("writing a script that deletes and then running it blocks", h,
         "cat > purge.sh <<'EOF'\nrm -rf build/cache\nEOF\nbash purge.sh",
         BLOCK, cwd, "WRITES a script and then RUNS it")
    case("writing a harmless script and running it is quiet", h,
         "cat > hello.py <<'EOF'\nprint(1)\nEOF\npython3 hello.py", QUIET, cwd)
    case("output sent to /dev/null is not a file", h,
         "git status > /dev/null && git push origin feature", QUIET, cwd)
    case("the bypass marker lets a blocked call through", h,
         "cat > msg.txt <<'EOF'\nx\nEOF\ngit commit -F msg.txt #allow-combined-write",
         QUIET, cwd)
    case("the bypass variable lets a blocked call through", h,
         "cat > msg.txt <<'EOF'\nx\nEOF\ngit commit -F msg.txt", QUIET, cwd,
         env_extra={"CLAUDE_ALLOW_COMBINED_WRITE": "1"})
    case("a write then git add alone blocks", h,
         "echo x > a.txt && git add a.txt", BLOCK, cwd)
    case("a write then git commit alone blocks", h,
         "echo x > a.txt && git commit -am msg", BLOCK, cwd)
    case("a write then git status is quiet", h,
         "echo x > a.txt && git status", QUIET, cwd)
    case("a redirect with no space before it is a write", h,
         "echo hi>output.txt && git push origin main", BLOCK, cwd, "output.txt")
    case("a descriptor duplicate (>&2) is not a write", h,
         "echo hi>&2 && git push origin main", QUIET, cwd)
    case("git -C <dir> push after a write blocks", h,
         "echo hi > output.txt && git -C /opt/project push origin main", BLOCK, cwd)
    case("git -c k=v commit after a write blocks", h,
         "echo hi > o.txt && git -c core.quotePath=false commit -m x", BLOCK, cwd)
    case("a remote call inside bash -c after a write blocks", h,
         "echo x > f.txt && bash -c 'curl https://example.com/a'", BLOCK, cwd)
    case("a quoted example of the shape is data and is quiet", h,
         'echo "example > output.txt; git push origin main"', QUIET, cwd)
    case("a real push after a quoted > still blocks", h,
         'echo "a > b" > notes.txt && git push origin main', BLOCK, cwd, "notes.txt")


def chain_abort_cases(cwd: str) -> None:
    h = CHAIN_ABORT
    case("a relative cd before a write in an && chain blocks", h,
         "cd build && echo done > status.txt", BLOCK, cwd, "relative `cd`")
    case("an absolute cd before the same write is quiet", h,
         f"cd {cwd} && echo done > status.txt", QUIET, cwd)
    case("a relative cd joined by ; (no short circuit) is quiet", h,
         "cd build; echo done > status.txt", QUIET, cwd)
    case("an unquoted --include=*.py warns", h,
         "grep -rn needle --include=*.py .", WARN, cwd, "CHAIN-ABORT WARNING")
    case("the quoted --include='*.py' is quiet", h,
         "grep -rn needle --include='*.py' .", QUIET, cwd)
    case("echo ==== (zsh EQUALS expansion) warns", h,
         "echo ====", WARN, cwd, "starts with `=`")
    case("echo '====' is quiet", h, "echo '===='", QUIET, cwd)
    case("a glob that matches nothing here warns", h,
         "ls no_such_prefix_*.md", WARN, cwd, "matches NOTHING")
    case("a glob that matches a real file is quiet", h,
         "ls present_*.txt", QUIET, cwd)
    case("rm with two globs, one matching nothing, warns", h,
         "rm -f present_*.txt no_such_prefix_*.md", WARN, cwd, "TWO OR MORE unquoted globs")
    case("the bypass marker lets a blocked call through", h,
         "cd build && echo done > status.txt #allow-chain-write", QUIET, cwd)
    case("a redirect with no space before it is still a write", h,
         "cd build && echo done>status.txt", BLOCK, cwd)
    case("a quoted > after a relative cd is an argument and is quiet", h,
         'cd build && echo "a > b"', QUIET, cwd)
    case("a later write after an independent first one is checked", h,
         "echo ready > first.txt; cd build && echo done > second.txt", BLOCK, cwd)
    case("a ; between the cd and the write ends the chain", h,
         "cd build && true; echo done > status.txt", QUIET, cwd)
    case("2>&1 | tee after a relative cd still blocks", h,
         "cd build && make 2>&1 | tee build.log", BLOCK, cwd)
    case("&> after a relative cd still blocks", h,
         "cd build && make &> log.txt", BLOCK, cwd)
    case("a backslash continuation after && still blocks", h,
         "cd build && \\\n python3 gen.py > out.txt", BLOCK, cwd)
    case("a pipeline stays in the chain: cd && make | tee log blocks", h,
         "cd build && make | tee build.log", BLOCK, cwd)
    case("under bash an unquoted --include=*.py is quiet (a zsh-only abort)", h,
         "grep -rn needle --include=*.py .", QUIET, cwd, env_extra={"SHELL": "/bin/bash"})
    case("under bash a relative cd before a write still blocks", h,
         "cd build && echo done > status.txt", BLOCK, cwd, env_extra={"SHELL": "/bin/bash"})


def shell_status_cases(cwd: str) -> None:
    h = SHELL_STATUS
    case("$? read straight after a pipe into tail warns", h,
         "python3 run_checks.py 2>&1 | tail -20\necho \"EXIT=$?\"", WARN, cwd,
         "status belongs to that filter")
    case("$? after a redirect to a file, no pipe, is quiet", h,
         "python3 run_checks.py > out.txt 2>&1; echo \"EXIT=$?\"", QUIET, cwd)
    case("$? after a pipe into grep -q (a real test) is quiet", h,
         "git log --oneline | grep -q fix\necho $?", QUIET, cwd)
    case("a backgrounded pipe into tail warns", h,
         "python3 long_job.py 2>&1 | tail -5", WARN, cwd, "runs in the BACKGROUND",
         background=True)
    case("the same pipe in the foreground is quiet", h,
         "python3 long_job.py 2>&1 | tail -5", QUIET, cwd)
    case("work detached with a trailing & warns", h,
         "nohup python3 long_job.py > job.log 2>&1 &", WARN, cwd, "trailing `&`")
    case("the same work with a wait is quiet", h,
         "python3 long_job.py > job.log 2>&1 &\nwait", QUIET, cwd)
    case("a writer piped into tail warns", h,
         "python3 sync.py --apply | tail -15", WARN, cwd, "WRITES")
    case("the same writer into head is quiet", h,
         "python3 sync.py --apply | head -15", QUIET, cwd)
    case("a wait loop that pgreps its own pattern blocks", h,
         "while pgrep -f \"run_tests.py\" > /dev/null; do sleep 5; done", BLOCK, cwd,
         "matches ITSELF")
    case("a wait loop on a file is quiet", h,
         "until [ -f done.flag ]; do sleep 5; done", QUIET, cwd)
    case("$b:path (a zsh history modifier) warns", h,
         "git show \"$b:app/config.py\"", WARN, cwd, "HISTORY MODIFIER")
    case("${b}:path is quiet", h, "git show \"${b}:app/config.py\"", QUIET, cwd)
    case("the bypass marker lets a blocked call through", h,
         "while pgrep -f \"run_tests.py\" > /dev/null; do sleep 5; done #allow-shell-status",
         QUIET, cwd)
    case("a wait loop handed to bash -c is executed and blocks", h,
         "bash -c 'while pgrep -f myjob; do sleep 5; done'", BLOCK, cwd, "matches ITSELF")
    case("a quoted example of a wait loop is data and is quiet", h,
         'echo "while pgrep -f run_tests.py; do sleep 5; done"', QUIET, cwd)
    case("a real wait loop after a heredoc still blocks", h,
         "cat > n.md <<'EOF'\nnotes\nEOF\nwhile pgrep -f run_tests.py; do sleep 5; done",
         BLOCK, cwd, "matches ITSELF")
    case("a pipe that ends a line still pipes into the next", h,
         "python3 run_checks.py 2>&1 |\ntail -20\necho \"EXIT=$?\"", WARN, cwd,
         "status belongs to that filter")
    case("raw codex exec with stdin open warns", h,
         'codex exec --sandbox read-only "$(cat prompt.md)"', WARN, cwd, "< /dev/null")
    case("the same codex exec with stdin closed is quiet", h,
         'codex exec --sandbox read-only "$(cat prompt.md)" < /dev/null', QUIET, cwd)
    case("a timeout that is not installed warns", h,
         "timeout 300 python3 run_checks.py", WARN, cwd, "not installed",
         env_extra={"PATH": EMPTY_BIN})
    case("a timeout that is installed is quiet", h,
         "timeout 300 python3 run_checks.py", QUIET, cwd, env_extra={"PATH": TIMEOUT_BIN})
    case("an unsplit $VAR under zsh warns", h,
         'pair="alpha beta"; set -- $pair; echo $2', WARN, cwd, "does NOT split")
    case("the same split on purpose with ${=VAR} is quiet", h,
         'pair="alpha beta"; set -- ${=pair}; echo $2', QUIET, cwd)
    case("the same unsplit $VAR under bash is quiet", h,
         'pair="alpha beta"; set -- $pair; echo $2', QUIET, cwd,
         env_extra={"SHELL": "/bin/bash"})
    case("a backgrounded redirect ending on echo $? warns", h,
         'python3 long_job.py > job.log 2>&1; echo "EXIT=$?"', WARN, cwd,
         "NOT the work", background=True)
    case("the same redirect in the foreground is quiet", h,
         'python3 long_job.py > job.log 2>&1; echo "EXIT=$?"', QUIET, cwd)


def destructive_cases(cwd: str, dirty: str, clean: str) -> None:
    h = DESTRUCTIVE
    case("git checkout -- <path> in a dirty tree blocks", h,
         "git checkout -- tracked.py", BLOCK, dirty, "uncommitted change")
    case("the same checkout in a clean tree only warns", h,
         "git checkout -- tracked.py", WARN, clean, "tree is clean")
    case("git -C <dirty repo> reset --hard blocks from a clean folder", h,
         f"git -C {dirty} reset --hard", BLOCK, clean)
    case("git restore --staged leaves the tree alone and is quiet", h,
         "git restore --staged tracked.py", QUIET, dirty)
    case("rm -rf outside the safe paths blocks", h,
         "rm -rf /opt/project/src", BLOCK, cwd, "outside the paths")
    case("rm -rf of a regenerable build folder is quiet", h,
         "rm -rf node_modules", QUIET, cwd)
    case("rm -rf against the home directory blocks", h, "rm -rf ~", BLOCK, cwd)
    case("rm -rf against an unset bare variable blocks", h,
         "rm -rf $NOT_SET_ANYWHERE_XYZ", BLOCK, cwd, "bare variable")
    case("a destructive string inside grep is data and is quiet", h,
         "grep -rn \"rm -rf /\" .", QUIET, cwd)
    case("the same string echoed into bash is execution and blocks", h,
         "echo \"rm -rf /opt/project/src\" | bash", BLOCK, cwd)
    case("a plain --force push blocks", h,
         "git push --force origin main", BLOCK, clean, "--force-with-lease")
    case("a --force-with-lease push only warns", h,
         "git push --force-with-lease origin feature", WARN, clean)
    case("the bypass marker lets a blocked call through", h,
         "rm -rf /opt/project/src #allow-destructive", QUIET, cwd)
    case("git restore --staged --worktree restores the tree and blocks", h,
         "git restore --staged --worktree tracked.py", BLOCK, dirty)
    case("`command git reset --hard` in a dirty tree blocks", h,
         "command git reset --hard", BLOCK, dirty)
    case("an env assignment before git reset --hard blocks", h,
         "GIT_OPTIONAL_LOCKS=0 git reset --hard", BLOCK, dirty)
    case("git -c k=v before reset --hard blocks", h,
         "git -c core.quotePath=false reset --hard", BLOCK, dirty)
    case("git -c k=v before a read is quiet", h,
         "git -c core.quotePath=false status", QUIET, dirty)
    case("rm -rf /tmp/../<path> leaves /tmp and blocks", h,
         "rm -rf /tmp/../opt/project/src", BLOCK, cwd)
    case("rm -rf /tmp/a/../b stays under /tmp and is quiet", h,
         "rm -rf /tmp/build/../cache", QUIET, cwd)
    case("git reset --hard where git status cannot be read blocks", h,
         "git reset --hard", BLOCK, NOT_A_REPO, "could not read")
    case("git restore -s<source> restores the tree and blocks", h,
         "git restore -sSTABLE tracked.py", BLOCK, dirty)
    case("a quoted -c value before reset --hard blocks", h,
         'git -c "core.sshCommand=ssh -i key" reset --hard', BLOCK, dirty)
    case("a quoted assignment before rm -rf blocks", h,
         'FOO="a b" rm -rf /opt/project/src', BLOCK, cwd)
    case("a discard in a folder that does not exist yet only warns", h,
         "git clone https://example.com/x.git newdir && cd newdir && git reset --hard abc",
         WARN, NOT_A_REPO, "does not exist yet")
    case("git branch -D warns", h, "git branch -D feature/x", WARN, clean, "reflog")
    case("git stash warns", h, "git stash", WARN, clean, "stash")
    case("git stash list is quiet", h, "git stash list", QUIET, clean)


def protected_repo_cases(root: Path, clean_name: str) -> None:
    """PROTECTED_REPOS ships empty; a copy with one name in it must block a clean reset."""
    global HOOKS
    src = (HOOKS / DESTRUCTIVE).read_text()
    marker = "PROTECTED_REPOS = []"
    if src.count(marker) != 1:
        results.append(("protected repos: the shipped list was found", False,
                        "expected one `%s` line in %s" % (marker, DESTRUCTIVE)))
        return
    copy_dir = root / "protected_hooks"
    copy_dir.mkdir()
    for f in HOOKS.glob("*.py"):
        (copy_dir / f.name).write_text(f.read_text())
    (copy_dir / DESTRUCTIVE).write_text(
        src.replace(marker, "PROTECTED_REPOS = [%r]" % clean_name))
    saved, HOOKS = HOOKS, copy_dir
    try:
        case("a protected repo blocks reset --hard even on a clean tree", DESTRUCTIVE,
             "git reset --hard", BLOCK, str(root / clean_name), "shared repository")
        case("the same reset in another clean repo only warns", DESTRUCTIVE,
             "git reset --hard", WARN, str(root / "clean_repo"), "tree is clean")
    finally:
        HOOKS = saved


# A PATH with no `timeout` at all, and one whose `timeout` is a stub, so the
# missing-timeout check reads the same on every machine.
EMPTY_BIN = tempfile.mkdtemp(prefix="shell-hooks-nobin-")
TIMEOUT_BIN = tempfile.mkdtemp(prefix="shell-hooks-timeoutbin-")
Path(TIMEOUT_BIN, "timeout").write_text("#!/bin/sh\nexit 0\n")
os.chmod(Path(TIMEOUT_BIN, "timeout"), 0o755)
# A folder that is not inside any git repository, so `git status` fails there.
NOT_A_REPO = tempfile.mkdtemp(prefix="shell-hooks-norepo-")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="shell-hooks-"))
    try:
        (work / "present_a.txt").write_text("x\n")
        (work / "build").mkdir()
        dirty = git_repo(work, "dirty_repo", dirty=True)
        clean = git_repo(work, "clean_repo", dirty=False)
        cwd = str(work)
        write_then_remote_cases(cwd)
        chain_abort_cases(cwd)
        shell_status_cases(cwd)
        destructive_cases(cwd, dirty, clean)
        git_repo(work, "shared_repo", dirty=False)
        protected_repo_cases(work, "shared_repo")
    finally:
        subprocess.run(["rm", "-rf", str(work), FAKE_HOME, EMPTY_BIN, TIMEOUT_BIN,
                        NOT_A_REPO])

    bad = 0
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            bad += 1
            print("        " + detail.strip().replace("\n", "\n        ")[:600])
    print(f"--- shell-safety hooks: {len(results) - bad}/{len(results)} ---")
    if len(results) < 99:
        print("FAIL: fewer cases ran than are written here; the runner is broken")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
