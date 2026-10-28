#!/usr/bin/env python3
"""Destructive Command Guard: a PreToolUse hook on Bash.

Blocks the small set of commands that destroy UNRECOVERABLE work, warns on the
larger set that is merely dangerous, and stays silent on the very large set that
only looks dangerous.

Inspired by dcg (github.com/Dicklesworthstone/destructive_command_guard), which
is a much larger Rust project under a license that cannot be redistributed here.
No code was taken from it. The ideas borrowed are the shape of the problem:
inline-script scanning, treating a pattern inside a read-only command as data
rather than execution, and keeping a regression test per known bypass.

WHY THE BANDS ARE WHERE THEY ARE. The line is recoverability, not scariness.
Losing an uncommitted working tree is unrecoverable by any means. Discarding a
local commit is recoverable from the reflog. So a tree-discard against a DIRTY
tree blocks, while the same command against a clean tree only warns.

The sharpest rule here is not generic: with several background sessions running
against the same repositories, a dirty file is very often ANOTHER session's live
work, and `git checkout -- .` destroys it with no undo.

PROTOCOL (both halves are load-bearing and easy to get wrong):
  block = exit code 2 with the reason on stderr. The stdout {"decision":"block"}
          form is NOT honored and fails OPEN.
  warn  = exit 0 plus stdout JSON carrying hookSpecificOutput.hookEventName,
          which is required or the context is silently dropped.

FAIL-OPEN ON INTERNAL ERROR, deliberately: a crashing guard that blocked every
Bash call would wedge the session entirely. A crash warns loudly instead, so the
failure is visible rather than silent.

BYPASS: append `#allow-destructive` to the command, or set
CLAUDE_ALLOW_DESTRUCTIVE=1. Same shape as the push guard's `#allow-push-main`.

Stdlib only, no PEP 604 syntax, so it runs under any python3 on the machine.
"""

import json
import os
import re
import subprocess
import sys

HOME = os.path.expanduser("~")

# Repositories where a history or tree rewrite needs an explicit decision,
# because someone else's branch lives there.
# Add the folder names of your own shared repositories, for example
# PROTECTED_REPOS = ["team-shared-repo"].
PROTECTED_REPOS = []

# Paths where destruction is the normal, intended operation.
SAFE_ROOTS = [
    os.path.join(HOME, ".claude", "jobs"),
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    os.environ.get("TMPDIR") or "\x00never",
]

# Directory names that are always regenerable.
SAFE_BASENAMES = (
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", ".next", "target", "htmlcov", ".tox", "venv", ".venv",
)

# A destructive-looking string inside one of these is DATA, not execution.
READ_ONLY_HEADS = (
    "grep", "rg", "ag", "ack", "echo", "printf", "cat", "less", "head", "tail",
    "awk", "comm", "diff", "sort", "uniq", "wc", "jq", "find", "ls", "man",
)

BYPASS_MARKER = "#allow-destructive"


HEREDOC_RE = re.compile(r"<<-?\s*([\'\"]?)(\w+)\1")


def strip_heredoc_bodies(command):
    """Split a command into (shell text, [(intro_line, body), ...]).

    A heredoc body is CONTENT, not commands: writing a test file that quotes
    `rm -rf render` must not read as deleting render. The bodies are returned
    rather than discarded so the inline-script scan can still see them, which
    is where a body piped into an interpreter genuinely is execution.
    """
    lines = command.split("\n")
    shell, bodies = [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        shell.append(line)
        m = HEREDOC_RE.search(line)
        if m:
            marker = m.group(2)
            i += 1
            body = []
            while i < len(lines) and lines[i].strip() != marker:
                body.append(lines[i])
                i += 1
            bodies.append((line, "\n".join(body)))
        i += 1
    return "\n".join(shell), bodies


def split_segments(command):
    """Split a compound command into segments, respecting quotes.

    Every segment is evaluated on its own, so burying a command in a chain
    cannot hide it.
    """
    segs = []
    buf = []
    quote = None
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(command):
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\n" or ch == ";":
            segs.append("".join(buf))
            buf = []
            i += 1
            continue
        if command[i:i + 2] in ("&&", "||"):
            segs.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch == "|":
            segs.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def strip_prefixes(segment):
    """Drop wrappers that hide the real command from a naive head-token read.

    `sudo rm -rf /` and `FOO=1 rm -rf /` are still rm. Without this the guard
    reads the head as `sudo` or as the assignment and waves both through.
    """
    s = segment.strip()
    while True:
        m = re.match(r"^(sudo|command|env|nohup|time|nice)\s+(-[-\w]+\s+)*", s)
        if m and m.end() > 0:
            s = s[m.end():]
            continue
        m = re.match(r"^\w+=[^\s]*\s+", s)
        if m:
            s = s[m.end():]
            continue
        return s


def head_token(segment):
    m = re.match(r"^([A-Za-z0-9_./-]+)", strip_prefixes(segment))
    return m.group(1).rsplit("/", 1)[-1] if m else ""


PIPE_TO_INTERPRETER = re.compile(
    r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh|ksh|dash|python3?|perl|ruby|node)\b[^|;&]*")

# The flag that hands an interpreter its program differs per interpreter, and
# guessing one spelling for all of them would cry wolf on `node -e`. Name them.
PROGRAM_FLAGS = {
    "python": {"-c", "-m"}, "python3": {"-c", "-m"}, "python2": {"-c", "-m"},
    "perl": {"-e", "-E"},
    "ruby": {"-e"},
    "node": {"-e", "-p", "--eval", "--print"},
}
SCRIPT_FILE = re.compile(r"[^\s|;&<>-][^\s|;&<>]*\.(?:py|pl|rb|js|mjs|cjs)$")

# The one way this exception could hand back what it just excused: a supplied
# program that runs its own stdin. Scanned over the WHOLE command, because the
# giveaway usually sits past the first `;` and this must not be the half-check.
RUNS_ITS_STDIN = re.compile(
    r"os\.system|subprocess|popen|\beval\s*\(|\bexec\s*\(|\bsystem\s*\(")


def stdin_is_data(pipe_segment):
    """True when this pipe's consumer READS stdin rather than RUNNING it.

    An interpreter already holding its program consumes what arrives as DATA:
    `| python3 -c '<prog>'`, `| perl -e '<prog>'`, `| node -e '<prog>'`,
    `| python3 -m json.tool`, `| python3 parse.py`. A bare `| python3` and an
    explicit `| python3 -` DO run stdin, and a shell always does.

    This enumerates the SAFE side positively, which is the only way to narrow a
    guard without failing open: whatever it does not positively recognise stays
    flagged.
    """
    tokens = pipe_segment.lstrip("|").split()
    while tokens and (tokens[0] == "sudo" or "=" in tokens[0]):
        tokens.pop(0)
    if not tokens:
        return False
    flags = PROGRAM_FLAGS.get(tokens[0].rsplit("/", 1)[-1])
    if flags is None:            # a shell, or something unrecognised
        return False
    for tok in tokens[1:]:
        if tok == "-":           # explicit "the program is on stdin"
            return False
        if tok in flags or SCRIPT_FILE.match(tok):
            return True
        if not tok.startswith("-"):
            return False         # an argument this cannot account for
    return False                 # bare interpreter: stdin IS the program


def pipes_into_interpreter(shell_text):
    """True when some pipe hands stdin to something that RUNS it."""
    if RUNS_ITS_STDIN.search(shell_text):
        return bool(PIPE_TO_INTERPRETER.search(shell_text))
    for m in PIPE_TO_INTERPRETER.finditer(shell_text):
        if not stdin_is_data(m.group(0)):
            return True
    return False


def is_data_context(segment, piped_to_interpreter=False):
    """True when the segment only MENTIONS a destructive string.

    A pipe into an interpreter turns the mention back into execution:
    `echo "rm -rf /" | bash` would otherwise read as data because the head
    token is `echo`. When the command pipes into a shell, nothing is data.
    """
    if piped_to_interpreter:
        return False
    return head_token(segment) in READ_ONLY_HEADS


def collect_vars(segments, upto):
    """VAR=value assignments made earlier in the same command.

    Command substitutions are skipped rather than guessed: `D=$(mktemp -d)`
    has no value until the shell runs it, and inventing one would be worse
    than admitting the target is unknown.
    """
    vals = {}
    for seg in segments[:upto]:
        for m in re.finditer(r"(?:^|\s)(\w+)=([^\s;&|]+)", seg):
            value = m.group(2).strip("'\"")
            if re.match(r"^\$\(mktemp\b", value) or "$(mktemp" in seg:
                # mktemp always returns a fresh path under the system temp
                # dir, so the target is safe by construction even though the
                # exact name is unknowable before the shell runs.
                vals[m.group(1)] = (os.environ.get("TMPDIR") or "/tmp") \
                    .rstrip("/") + "/mktemp-placeholder"
                continue
            if "$(" in value or "`" in value:
                continue
            vals[m.group(1)] = value
    return vals


def expand_vars(path, vals):
    """Expand $VAR / ${VAR} from vals, then the environment.

    Returns (expanded, resolved). `resolved` is False when a variable is
    still present, and the caller must NOT treat an unresolved path as safe:
    that is the direction in which an allowlist fails open.
    """
    out = path
    for _ in range(3):
        prev = out

        def sub(m):
            name = m.group(1) or m.group(2)
            if name in vals:
                return vals[name]
            if name in os.environ:
                return os.environ[name]
            return m.group(0)

        out = re.sub(r"\$\{(\w+)\}|\$(\w+)", sub, out)
        if out == prev:
            break
    return out, ("$" not in out)


def resolve_cwd(segments, index, default_cwd):
    """Best-effort cwd for a segment, honoring earlier `cd` in the same command."""
    cwd = default_cwd
    for seg in segments[:index]:
        m = re.match(r"^[{(\s]*cd\s+(?:-[-\w]+\s+)*([^\s;&|]+)", seg.strip())
        if m:
            target = m.group(1).strip("'\"")
            target, _ok = expand_vars(target, collect_vars(segments, index))
            target = os.path.expanduser(target)
            cwd = target if os.path.isabs(target) else os.path.normpath(
                os.path.join(cwd, target))
    return cwd


def git_target_dir(segment, seg_cwd, segments, index):
    """The directory `git -C <path>` points this segment at, or None.

    Without this the guard measures the SESSION's repository and reports on it while
    the command targets another one. That is wrong in both directions: it would
    block a clean checkout because the launch repository is dirty, and it would let
    a reset through against a dirty repo whenever the launch directory is clean.
    The second direction is the one that loses work.

    Only a `-C` that appears BEFORE the subcommand counts. `git commit -C HEAD`
    reuses a commit message and names no directory at all.
    """
    tokens = strip_prefixes(segment).split()
    if not tokens or os.path.basename(tokens[0].strip("'\"")) != "git":
        return None
    target = None
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-C" and i + 1 < len(tokens):
            target = tokens[i + 1]
            i += 2
            continue
        if tok in ("--git-dir", "--work-tree", "-c"):
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        break                      # the subcommand; any later -C is not a directory
    if target is None:
        return None
    target = target.strip("'\"")
    target, _ok = expand_vars(target, collect_vars(segments, index))
    target = os.path.expanduser(target)
    if not os.path.isabs(target):
        target = os.path.normpath(os.path.join(seg_cwd, target))
    return target


def under_safe_root(path):
    p = os.path.expanduser(path.strip("'\""))
    if not os.path.isabs(p):
        return False
    for root in SAFE_ROOTS:
        if p == root.rstrip("/") or p.startswith(root.rstrip("/") + "/"):
            return True
    return False


def rm_targets(segment):
    """Return the non-flag arguments of an rm, or None when it is not an rm."""
    toks = segment.split()
    if not toks:
        return None
    if head_token(segment) != "rm":
        return None
    # `docker run --rm`, `--rm` as anyone else's flag: not our rm.
    args = []
    skip_next = False
    for t in toks[1:]:
        if skip_next:
            skip_next = False
            continue
        if t.startswith("-"):
            continue
        # A redirection is not a deletion target: in `rm -rf "$WT" 2>/dev/null`
        # the `2>/dev/null` is not a path.
        if re.match(r"^\d?[<>]", t):
            if t.rstrip().endswith((">", "<")):
                skip_next = True
            continue
        args.append(t)
    return args


def rm_is_recursive_force(segment):
    flags = re.findall(r"(?<!\S)-([A-Za-z]+)", segment)
    joined = "".join(flags)
    return ("r" in joined.lower()) and ("f" in joined)


def git_repo_root(cwd):
    try:
        p = subprocess.run(["git", "-C", cwd, "rev-parse", "--show-toplevel"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=3)
        if p.returncode == 0:
            return p.stdout.decode("utf-8", "replace").strip()
    except Exception:
        pass
    return None


def dirty_files(cwd):
    """Return the porcelain lines of the repo at cwd, or None when unknown."""
    try:
        p = subprocess.run(["git", "-C", cwd, "status", "--porcelain"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=5)
        if p.returncode != 0:
            return None
        out = p.stdout.decode("utf-8", "replace").strip()
        return [ln for ln in out.split("\n") if ln.strip()] if out else []
    except Exception:
        return None


TREE_DISCARD = [
    (re.compile(r"^git\s+(?:-C\s+\S+\s+)?reset\s+(?:.*\s)?--(hard|merge|keep)\b"),
     "git reset --hard discards every uncommitted change in the tree"),
    (re.compile(r"^git\s+(?:-C\s+\S+\s+)?checkout\s+(?:\S+\s+)?--\s+\S"),
     "git checkout -- <path> overwrites that path from the index, with no undo"),
    (re.compile(r"^git\s+(?:-C\s+\S+\s+)?checkout\s+\.(\s|$)"),
     "git checkout . overwrites the whole tree from the index, with no undo"),
    (re.compile(r"^git\s+(?:-C\s+\S+\s+)?clean\s+[-\w]*f"),
     "git clean -f deletes untracked files outright; they are in no index"),
]

# `git restore` is destructive ONLY without --staged. With --staged it unstages
# and leaves the working tree untouched, which is the opposite of destructive.
RESTORE_RE = re.compile(r"^git\s+(?:-C\s+\S+\s+)?restore\b")

WARN_RULES = [
    (re.compile(r"^git\s+(?:-C\s+\S+\s+)?branch\s+-D\b"),
     "git branch -D force-deletes a branch; recoverable from the reflog for now"),
    (re.compile(r"--force-with-lease\b"),
     "force-push with lease: safe against overwriting someone else's push, still rewrites history"),
    (re.compile(r"^git\s+(?:-C\s+\S+\s+)?stash\b(?!.*\blist\b)(?!.*\bshow\b)"),
     "git stash moves the working tree aside; a later drop/clear makes it unrecoverable"),
    (re.compile(r"\bdocker\s+(volume\s+rm|system\s+prune|image\s+prune|rm\b)"),
     "docker removal can delete a volume's data with no undo"),
    (re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b", re.I),
     "SQL DDL that destroys a table or database"),
    (re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.I),
     "DELETE FROM with no WHERE clause removes every row"),
    (re.compile(r"^(chmod|chown)\s+-R\b"),
     "a recursive permission change can make a tree unusable, including a mounted disk"),
    (re.compile(r"\b(pkill|killall)\b|\bkill\s+-9\b"),
     "signalling by name can hit processes this session did not start"),
    (re.compile(r"\bgh\s+repo\s+delete\b"),
     "deleting a GitHub repository is immediate and permanent"),
    (re.compile(r"\bgit\s+(filter-branch|filter-repo)\b"),
     "history rewrite: every downstream clone diverges"),
    (re.compile(r"\bmv\s+"),
     "mv overwrites the destination silently when it already exists"),
]

INLINE_DESTRUCTIVE = re.compile(
    r"(shutil\.rmtree|os\.removedirs|os\.remove|os\.unlink|Path\([^)]*\)\.unlink"
    r"|\.unlink\(|rmdir\(|fs\.rmSync|fs\.unlinkSync|rimraf)")


def check_segment(seg, cwd, all_segs, idx, piped_to_interpreter=False):
    """Return (verdict, reason) where verdict is 'block', 'warn' or None."""
    if is_data_context(seg, piped_to_interpreter):
        return None, None

    seg_cwd = resolve_cwd(all_segs, idx, cwd)
    # `git -C <repo>` retargets the command, so it must retarget every question the
    # guard asks about the tree as well.
    seg_cwd = git_target_dir(seg, seg_cwd, all_segs, idx) or seg_cwd

    # 1. Working-tree discards. Blocks only when there is something to lose.
    discard_reason = None
    for rx, why in TREE_DISCARD:
        if rx.search(seg):
            discard_reason = why
            break
    if discard_reason is None and RESTORE_RE.search(seg) and "--staged" not in seg:
        discard_reason = "git restore <path> overwrites that path from the index, with no undo"
    if discard_reason:
        dirty = dirty_files(seg_cwd)
        if dirty:
            listed = ", ".join(d[3:].strip() for d in dirty[:4])
            more = "" if len(dirty) <= 4 else " and %d more" % (len(dirty) - 4)
            return "block", (
                discard_reason + ".\nThe working tree at " + seg_cwd + " has "
                + str(len(dirty)) + " uncommitted change(s): " + listed + more
                + ".\nWith parallel sessions running, some of these may be another "
                "session's live work, and this command has no undo.\n"
                "Reconcile first (git status, git stash push -m 'name', or commit), "
                "or re-run with " + BYPASS_MARKER + " once you are sure.")
        return "warn", (discard_reason
                        + ", but the tree is clean, so only committed state is at risk "
                          "and the reflog can recover it")

    # 2. rm -rf outside the places where deleting is the point.
    seg = strip_prefixes(seg)
    targets = rm_targets(seg)
    if targets is not None and rm_is_recursive_force(seg):
        seg_vars = collect_vars(all_segs, idx + 1)
        for t in targets:
            raw = t.strip("'\"")
            resolved, fully = expand_vars(raw, seg_vars)
            expanded = os.path.expanduser(resolved)

            # ORDER IS LOAD-BEARING. The unresolvable and catastrophic cases are
            # decided BEFORE any allowlist, so a path the guard could not resolve is
            # never treated as safe just because the cwd sits under a safe root.
            if raw in ("/", "/*", "~", "~/", "$HOME", "${HOME}", "$HOME/", "~/*") \
                    or expanded.rstrip("/") in ("", HOME) or expanded == "/":
                return "block", ("rm -rf against " + raw
                                 + " would delete your home directory or the filesystem root")
            bare_var = re.match(r"^\$\{?\w+\}?/?\*?$", raw)
            if bare_var and not fully:
                return "block", (
                    "rm -rf against the bare variable " + raw + " deletes the wrong "
                    "tree entirely when that variable is empty or unset, which is the "
                    "classic form of this accident. Expand it to a literal path, or "
                    "guard it with ${VAR:?} so the shell refuses when it is unset.")

            base = os.path.basename(expanded.rstrip("/"))
            if base in SAFE_BASENAMES:
                continue
            if under_safe_root(expanded if os.path.isabs(expanded)
                               else os.path.join(seg_cwd, expanded)):
                continue
            if not fully:
                return "block", (
                    "rm -rf against " + raw + " contains a variable the guard cannot "
                    "resolve, so it cannot tell whether the target is safe. Expand it "
                    "first, or re-run with " + BYPASS_MARKER + ".")
            return "block", (
                "rm -rf against " + raw + " is outside the paths where deleting is "
                "expected (the Claude Code background-job folder, the temp folders, "
                "and regenerable build dirs).\n"
                "If this is genuinely intended, re-run with " + BYPASS_MARKER + ".")

    # 3. A plain --force push. --force-with-lease is handled in the warn band.
    if re.search(r"^git\s+(?:-C\s+\S+\s+)?push\b", seg) and \
            re.search(r"(--force(?!-with-lease)|(?<!\S)-f(?!\S))", seg):
        return "block", (
            "git push --force can overwrite commits someone else pushed, and on a "
            "shared branch that loss is not yours to undo.\n"
            "Use --force-with-lease, which refuses when the remote moved under you.")

    # 4. Anything tree- or history-shaped inside a protected repository.
    root = git_repo_root(seg_cwd) or ""
    repo_name = os.path.basename(root)
    if repo_name in PROTECTED_REPOS and re.search(
            r"^git\s+(?:-C\s+\S+\s+)?(reset|push\b.*(--force|-f\b)|filter-branch|filter-repo)", seg):
        return "block", (
            repo_name + " is a shared repository where someone else's branch lives, "
            "so a reset or a force-push there can destroy work that is not yours.\n"
            "Merge instead, or re-run with " + BYPASS_MARKER + " if you have agreed it.")

    # 5. Destructive filesystem calls hidden in an inline script or heredoc.
    if re.search(r"(python3?|node|ruby|perl)\s+(-c|-e)\b", seg) or "<<" in seg:
        if INLINE_DESTRUCTIVE.search(seg):
            return "warn", (
                "an inline script deletes files, which no command-level check can "
                "see once it is inside the interpreter; confirm the path it targets")

    for rx, why in WARN_RULES:
        if rx.search(seg):
            return "warn", why

    if re.search(r"\b(dd\s+if=|mkfs|shred)\b", seg):
        return "warn", "a raw device or overwrite utility"

    if piped_to_interpreter and re.match(r"^(curl|wget)\b", seg):
        return "warn", (
            "this pipes a downloaded script straight into an interpreter, so whatever "
            "the server returns runs unread, and the content can differ between the "
            "request you inspected and this one. Download it, read it, then run it.")

    return None, None


def main():
    try:
        raw = sys.stdin.read()
    except Exception:
        return 0
    try:
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0

    command = ((data.get("tool_input") or {}).get("command") or "")
    if not isinstance(command, str) or not command.strip():
        return 0

    if BYPASS_MARKER in command or os.environ.get("CLAUDE_ALLOW_DESTRUCTIVE") == "1":
        return 0

    cwd = data.get("cwd") or os.getcwd()
    shell_text, heredoc_bodies = strip_heredoc_bodies(command)
    segs = split_segments(shell_text)
    # Compute this on the SHELL TEXT, never the whole command: a heredoc body
    # that merely CONTAINS the characters "| bash" (a test fixture, a doc, a
    # patch script) would otherwise flip the flag and drag the body back in as
    # live commands. That is the data-versus-execution confusion one level down.
    piped = pipes_into_interpreter(shell_text)

    # What a heredoc body IS depends on what consumes it: `bash <<EOF` is shell,
    # `python3 - <<EOF` is Python (covered by the inline scan), and `cat > f <<EOF`
    # is a file being written, which is data and must not be analyzed at all.
    inline_bodies = []
    for intro, body in heredoc_bodies:
        consumer = head_token(intro)
        if consumer in ("bash", "sh", "zsh", "ksh", "dash"):
            segs.extend(split_segments(body))
        elif consumer in ("python", "python3", "node", "perl", "ruby"):
            inline_bodies.append(body)
    if piped:
        for _intro, body in heredoc_bodies:
            segs.extend(split_segments(body))

    # When the command pipes into an interpreter, the text an `echo` or `printf`
    # emits IS the script that runs. Analyze that payload as commands in its own
    # right, or `echo "rm -rf /path" | bash` passes: the outer segment's head is
    # `echo`, so no filesystem rule ever looks inside the quotes.
    if piped:
        for seg in list(segs):
            if head_token(seg) not in ("echo", "printf", "cat"):
                continue
            for m in re.finditer(r'"([^"]*)"|\'([^\']*)\'', seg):
                payload = m.group(1) or m.group(2) or ""
                if payload.strip():
                    segs.extend(split_segments(payload))

    blocks = []
    warns = []
    for i, seg in enumerate(segs):
        verdict, reason = check_segment(seg, cwd, segs, i, piped)
        if verdict == "block":
            blocks.append((seg, reason))
        elif verdict == "warn":
            warns.append((seg, reason))

    for body in inline_bodies:
        if INLINE_DESTRUCTIVE.search(body):
            warns.append(("(heredoc script)",
                          "an inline script deletes files, which no command-level "
                          "check can see once it is inside the interpreter; confirm "
                          "the path it targets"))

    if blocks:
        seg, reason = blocks[0]
        sys.stderr.write(
            "BLOCKED by destructive-command-guard\n\n"
            "  " + seg.strip()[:200] + "\n\n" + reason + "\n")
        return 2

    if warns:
        lines = []
        for seg, reason in warns[:3]:
            lines.append("  " + seg.strip()[:120] + "\n    " + reason)
        json.dump({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext":
                "DESTRUCTIVE-COMMAND WARNING (not blocked, proceed if intended):\n"
                + "\n".join(lines)
                + "\nConfirm the target is what you mean before relying on the result."
        }}, sys.stdout)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail open, but loudly
        try:
            json.dump({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext":
                    "destructive-command-guard failed to run (" + type(exc).__name__
                    + "), so this command was NOT checked. The guard is failing open "
                      "by design; fix it rather than trusting the silence."
            }}, sys.stdout)
        except Exception:
            pass
        sys.exit(0)
