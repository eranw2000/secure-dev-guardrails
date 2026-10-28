#!/usr/bin/env python3
"""PreToolUse guard: never create a file and then reach out to the world in ONE Bash call.

THE FAILURE THIS PREVENTS. When a PreToolUse hook or the auto-mode classifier
refuses a Bash call, NOTHING in that call ran, including the heredoc that wrote
a script. The refusal names only the
offending clause, so it reads as though the rest went through, and the next command
dies with a confusing "no such file".

WHY IT BLOCKS RATHER THAN WARNS. A warning is easy to read past, and the remedy
costs one extra Bash call.

WHY THIS TRIGGER AND NOT A WIDER ONE. Firing on every call that writes a file
and then does anything else would fire on a large share of ordinary calls, and
a guard that cries wolf gets its next real warning discounted. So it fires only
when a later clause reaches production, a credential loader, or git/gh.

ORDER IS PART OF THE SIGNAL. The guard fires only when a WRITE comes BEFORE the
risky clause, because that is the shape where refusing the call loses the file.
`... | tee run.log` AFTER a production call is output capture and loses nothing.

BYPASS: append `#allow-combined-write` to the command, or set
CLAUDE_ALLOW_COMBINED_WRITE=1. Same shape as `#allow-destructive` and
`#allow-push-main`. Never put the marker in a command a person runs in their own
shell: that shell has no hook, and interactive zsh does not treat `#` as a comment.

Fails OPEN, loudly, like the other guards here. Python 3.9 compatible.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BYPASS_MARKER = "#allow-combined-write"

# A clause that CREATES a file: a heredoc, a redirect to a path, or tee.
# Discarding output is not creating a file: /dev/null cannot be lost, so a
# refusal costs nothing there. Same for /dev/stdout and
# /dev/stderr. Excluded by name rather than by a cleverer pattern, because the
# set is tiny and a wider rule would need its own measurement.
_DISCARD = re.compile(r"^/dev/(null|stdout|stderr|fd/\d+)$")

WRITE = re.compile(
    r"<<-?\s*['\"]?[A-Za-z_][A-Za-z0-9_]*"      # heredoc open
    r"|(?:^|[\s;&|({])>>?\s*([^\s;&|<>()]+)"     # > path  /  >> path
    r"|\btee\s"                                  # tee path
)


# A heredoc fed to a command that only READS it from stdin as a message writes no
# file: `git commit -F -`, `git tag -F -`, `gh ... --body-file -`. A refusal loses
# nothing a retry does not resend. Named by command rather than by a rule about
# stdin, because a script on stdin (`python3 - <<EOF`) can write files and must
# keep firing.
_STDIN_MESSAGE = re.compile(
    r"^\s*(?:git\s+(?:-C\s+\S+\s+)?(?:commit|tag)\b[^\n]*\s(?:-F|--file)(?:\s+|=)-(?=\s|$)"
    r"|gh\s[^\n]*\s--body-file(?:\s+|=)-(?=\s|$))"
)


def creates_a_file(segment):
    """True when this clause brings a file into existence that a refusal loses."""
    for m in WRITE.finditer(segment):
        if m.group(0).lstrip().startswith("<<"):
            if _STDIN_MESSAGE.match(segment):
                continue          # a message on stdin, not a file
            return True
        target = m.group(1)
        if target and _DISCARD.match(target):
            continue
        return True
    return False

# A clause that can be REFUSED: it leaves this machine, spends money, or moves a repo.
# Each entry is a shape that gets refused. `with_prod_creds` is an example name
# for a script that loads production credentials: replace it with the names of
# your own wrappers, and add your production hosts to the second line.
RISKY = re.compile(
    r"with_prod_creds"                                        # credential loaders
    r"|api\.render\.com|onrender\.com"                        # hosting APIs
    r"|curl\s+[^|;]*https?://(?!127\.0\.0\.1|localhost)"      # any non-local fetch
    r"|(?:^|[\s;&|(])gh\s+(?:pr|api|repo|issue)\b"            # GitHub writes
    r"|(?:^|[\s;&|(])git\s+(?:push|commit|add)\b",            # moving a repo
    re.I,
)

# The Render CLI counts only as the COMMAND of a clause, optionally after `VAR=x`
# assignments, so `make_report.py render a > b`, where "render" is an argument
# to a local script, does not count. Clauses are split on ; & | first, so a
# clause start is a command position.
_RENDER_CLI = re.compile(r"^\s*\(?\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*render\s", re.I)


def reaches_out(segment):
    return bool(RISKY.search(segment) or _RENDER_CLI.match(segment))


# ---------------------------------------------------------------------------
# The SECOND shape: write a script, then RUN THAT SCRIPT. A local run of a
# harmless script is never refused; what gets refused is the script's CONTENT,
# so the content is the trigger. The guard fires when a call writes a file, runs
# that same file later in the chain, and the body it wrote matches
# REFUSABLE_BODY. A benign `print(1)` script stays silent.
_RUNNER = re.compile(
    r"(?:^|[\s;&|(])(?:bash|sh|zsh|python3?|node|ruby|perl|source|\.)\s+([^\s;|&]+)"
    r"|(?:^|[\s;&|(])(\./[^\s;|&]+)"
)

# What gets refused: each entry is a shape that a hook or the auto-mode
# classifier refuses.
REFUSABLE_BODY = re.compile(
    r"rm\s+-[rRf]*[rf]"                                    # a bulk delete
    r"|\bsudo\b"
    r"|with_prod_creds|\.render/cli\.yaml"
    r"|\bgit\s+(?:push|commit|reset\s+--hard)\b"
    r"|api\.render\.com"
    r"|\bdrop\s+table\b|\bdelete\s+from\b|\btruncate\b",
    re.I,
)

_REDIR_TARGET = re.compile(r"(?:^|[\s;&|({])>>?\s*([^\s;&|<>()]+)")
_TEE_TARGET = re.compile(r"\btee\s+([^\s;|&]+)")


def written_targets(segment):
    """Paths this clause brings into existence.

    Never touches the disk. This is a PreToolUse guard, so by definition the
    file does not exist yet, which is exactly why
    `_bash_write_targets.extract_write_targets` cannot be reused: it DROPS any
    candidate that is not already on disk.
    """
    out = []
    for pattern in (_REDIR_TARGET, _TEE_TARGET):
        for m in pattern.finditer(segment):
            target = m.group(1)
            if target and not _DISCARD.match(target):
                out.append(target)
    return out


def self_execution_verdict(command):
    """Return (write clause, run clause) when this call writes a script whose
    body looks refusable and then executes that same script."""
    try:
        from _bash_write_targets import strip_heredocs
        stripped, bodies = strip_heredocs(command)
    except Exception:
        return None
    if not bodies or not REFUSABLE_BODY.search("\n".join(bodies)):
        return None

    segs = re.split(r"&&|\|\||[;|]|\n", stripped)
    written = {}
    for i, seg in enumerate(segs):
        for target in written_targets(seg):
            written.setdefault(os.path.basename(target), i)
    if not written:
        return None

    for i, seg in enumerate(segs):
        for m in _RUNNER.finditer(seg):
            ran = (m.group(1) or m.group(2) or "").strip("'\"")
            if not ran:
                continue
            first_write = written.get(os.path.basename(ran))
            if first_write is not None and first_write < i:
                return segs[first_write].strip(), seg.strip()
    return None


def segments(command):
    """The command split into clauses, with heredoc BODIES removed first.

    Stripping bodies matters in both directions: a script body mentioning a
    production URL must not count as the command calling it, and a body
    containing `>` must not be read as a redirect.
    """
    try:
        from _bash_write_targets import strip_heredocs
        stripped, _bodies = strip_heredocs(command)
    except Exception:
        stripped = command
    return re.split(r"&&|\|\||[;|]|\n", stripped)


def verdict(command):
    """Return the offending (write clause, risky clause) pair, or None."""
    segs = segments(command)
    writes = [i for i, s in enumerate(segs) if creates_a_file(s)]
    risky = [i for i, s in enumerate(segs) if reaches_out(s)]
    if not writes or not risky:
        return None
    first_write, last_risky = min(writes), max(risky)
    if first_write >= last_risky:
        return None
    return segs[first_write].strip(), segs[last_risky].strip()


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except Exception:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command:
        return 0
    if BYPASS_MARKER in command or os.environ.get("CLAUDE_ALLOW_COMBINED_WRITE") == "1":
        return 0

    self_hit = self_execution_verdict(command)
    if self_hit:
        write_clause, run_clause = self_hit
        sys.stderr.write(
            "This call WRITES a script and then RUNS it, and the script it writes "
            "contains something that gets refused here. If the run is refused, "
            "nothing in the call ran, so the script was never written either.\n\n"
            "  the write : %s\n"
            "  the run   : %s\n\n"
            "Split it: write the file in one call, confirm it exists, then run it "
            "in the next call.\n\n"
            "Bypass with %s appended unquoted, or CLAUDE_ALLOW_COMBINED_WRITE=1. "
            "Never put that marker in a command a person will run.\n"
            % (write_clause[:160], run_clause[:160], BYPASS_MARKER)
        )
        return 2

    hit = verdict(command)
    if not hit:
        return 0
    write_clause, risky_clause = hit
    sys.stderr.write(
        "This call creates a file AND then reaches out in the same command. If any "
        "part of it is refused, NOTHING in it runs and the file is silently never "
        "written.\n\n"
        "  the write : %s\n"
        "  the reach : %s\n\n"
        "Split it: write the file in its own call, then run the second half in the "
        "next call.\n\n"
        "Bypass with %s appended unquoted, or CLAUDE_ALLOW_COMBINED_WRITE=1. Never "
        "put that marker in a command a person will run.\n"
        % (write_clause[:160], risky_clause[:160], BYPASS_MARKER)
    )
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail OPEN, loudly
        sys.stderr.write("write-then-remote-guard failed open: %r\n" % (exc,))
        sys.exit(0)
