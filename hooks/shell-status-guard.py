#!/usr/bin/env python3
"""Warn when a Bash call reads an exit status that cannot mean what it looks like.

The first two shapes:

1. STATUS AFTER A PIPE.

       run_checks.py 2>&1 | tail -20
       echo "EXIT=$?"

   `$?` is the status of the LAST stage of a pipeline. `tail` almost always
   succeeds, so this prints 0 for a producer that crashed.

   The status line CANNOT report the producer's failure, so a green reading is
   not evidence of anything.

2. `timeout` THAT IS NOT INSTALLED.

       timeout 300 .venv/bin/python manage.py test

   `timeout` is GNU coreutils and is absent from a stock macOS. The shell exits
   127 and runs NOTHING, so a whole suite reports as failed or empty.

SCOPE:

  * Check 1 fires only when the pipeline's last stage is a PURE DISPLAY filter
    (tail, head, cat, tee, ...). `grep`, `wc`, `jq` and `diff` are deliberately
    excluded: `... | grep -q x; echo $?` is a real test, not a mistake.
  * Check 1 stays silent when `pipefail` or `PIPESTATUS` appears anywhere in the
    command, on the grounds that the author has clearly met this problem before.
  * Check 1 looks only at the group IMMEDIATELY after the pipeline. A `$?` two
    commands later reads something else and is not this bug.
  * Check 2 asks the SYSTEM whether the binary exists rather than hardcoding
    "macOS has no timeout", so it goes quiet by itself the day coreutils is
    installed, and it is correct on a machine that already has it.

Both paths WARN and neither blocks: they produce a wrong READING, not lost work.
One later check BLOCKS: a wait loop that matches itself (self_matching_wait), because its
warning would arrive only when the command ends, which is at the timeout.

Warnings go to STDOUT as hookSpecificOutput with hookEventName. A PreToolUse warn
written to stderr on exit 0 is dropped by Claude Code, so stdout is the only
channel that reaches the session.
"""
import json
import os
import re
import shlex
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _bash_command_parse import (  # noqa: E402
    OPERATORS,
    UnparseableCommand,
    strip_heredocs,
    strip_prefixes,
    tokenize,
)

BYPASS_MARKER = "#allow-shell-status"

# Filters whose own exit status is never the one the author wanted. Anything
# that can meaningfully fail (grep, wc, jq, diff, python) is NOT here on purpose.
DISPLAY_ONLY = {
    "tail", "head", "cat", "tee", "less", "more", "column",
    "fold", "nl", "pr", "rev", "expand", "unexpand",
}

TIMEOUT_NAMES = ("timeout", "gtimeout")

# Commands whose RESULT REACHES YOU AS A NOTIFICATION rather than in the tool result:
# either you launched them in the background, or they run long enough that the harness
# moves them there itself. That distinction is the whole hazard, and it is why this list
# exists rather than a rule about command shape.
#
# In the foreground the shape is harmless: `cmd > log 2>&1; echo "EXIT=$?"` prints the true
# status straight into the output you are reading. Backgrounded, that same line goes to a
# file and what you are handed is the LAST clause's status, which is the echo's, and it is
# 0 whatever the work did.
#
# The shape is common, and firing on every occurrence is the rate at which a
# warning stops being read. Gated on this list it fires rarely. Add the names of
# your own long-running commands here.
SLOW_RUNNERS = (
    "codex_delegate", "codex exec",
    "docker build", "docker compose", "docker-compose",
    "npm run build", "npm build", "pytest",
)


def tool_shell(environ=None):
    """The shell Claude Code's Bash tool runs commands in, "zsh" or "bash".

    Claude Code docs, env-vars page, CLAUDE_CODE_SHELL: "If the value is not a working
    `bash` or `zsh` path, Claude Code ignores it and falls back to auto-detection.
    Auto-detection uses your `$SHELL` when it points to `bash` or `zsh`, otherwise it
    picks the first working `zsh` then `bash` found on your `PATH` and standard
    install locations." The no-split and colon-modifier checks, and the PIPESTATUS
    advice, describe zsh, so they apply only when zsh is the shell.
    """
    env = os.environ if environ is None else environ
    forced = env.get("CLAUDE_CODE_SHELL") or ""
    if os.path.basename(forced) in ("zsh", "bash") and os.access(forced, os.X_OK):
        return os.path.basename(forced)
    name = os.path.basename(env.get("SHELL") or "")
    if name in ("zsh", "bash"):
        return name
    return "zsh" if shutil.which("zsh") else "bash"


def result_arrives_as_notification(command, background):
    """True when the status you are handed will NOT be the tool result you read.

    The name has to be RUN, not merely mentioned. Matching the raw string would fire
    on a commit message that mentions `pytest` inside a heredoc body. A script being WRITTEN is not
    a script being run, which is what `strip_heredocs` exists to say.
    """
    if background:
        return True
    try:
        scannable, _bodies = strip_heredocs(command)
    except Exception:  # noqa: BLE001 - an unparseable command must not blind the check
        scannable = command
    return any(name in scannable for name in SLOW_RUNNERS)


def command_groups(command):
    """Ordered command groups; each group is its list of pipe-separated stages.

    `split_segments` discards the joining operator, so it cannot tell `a | b`
    from `a; b`. This keeps the pipe boundaries AND the order, which is what a
    question about "what did $? just read" needs.

    The whole text is tokenized ONCE. The tokenizer returns a newline as its own
    operator, so `a | tail -3` on one line and `if [ $? ]` on the next stay two
    groups, and a pipe that ENDS a line (`a |` then `tail -3`) arrives as one
    `|` + newline token that still joins the two stages, as the shell does. A
    backslash-newline is a line continuation and is joined first.
    """
    scannable, _bodies = strip_heredocs(command)
    return _groups_from_tokens(tokenize(scannable.replace("\\\n", " ")))


def _groups_from_tokens(tokens):
    groups, current, stage = [], [], []
    for tok in tokens:
        is_pipe = bool(tok) and tok.replace("\n", "") == "|"
        is_other_op = (not is_pipe) and (
            tok in OPERATORS or (tok and all(c in "|&;\n" for c in tok))
        )
        if is_pipe:
            if stage:
                current.append(stage)
                stage = []
            continue
        if is_other_op:
            if stage:
                current.append(stage)
                stage = []
            if current:
                groups.append(current)
                current = []
            continue
        stage.append(tok)
    if stage:
        current.append(stage)
    if current:
        groups.append(current)
    return groups


def _cmd_word(stage):
    tokens = strip_prefixes(stage)
    return os.path.basename(tokens[0]) if tokens else ""


def status_after_pipe(command):
    """The offending pipeline, or None."""
    if "pipefail" in command or "PIPESTATUS" in command:
        return None
    try:
        groups = command_groups(command)
    except (UnparseableCommand, ValueError):
        return None
    for i in range(1, len(groups)):
        reads_status = any("$?" in tok for stage in groups[i] for tok in stage)
        if not reads_status:
            continue
        previous = groups[i - 1]
        if len(previous) > 1 and _cmd_word(previous[-1]) in DISPLAY_ONLY:
            return " | ".join(" ".join(stage) for stage in previous)
    return None


# Flags that make a script DO the write rather than show it. A writer that refuses
# prints the refusal FIRST, then usually the plan it would have written, so a
# trailing `tail` keeps the harmless-looking plan and drops the refusal. There is no
# `$?` in that shape at all, which is why `status_after_pipe` cannot see it.
WRITER_FLAGS = {"--apply", "--push", "--write", "--commit", "--execute", "--yes"}
# A command that only MENTIONS a flag (a search pattern, a printed word) is not a writer.
NOT_WRITERS = {"grep", "rg", "egrep", "fgrep", "echo", "printf", "cat", "sed", "awk"}


def writer_into_tail(command):
    """The offending pipeline, or None: a writer's output ends in `tail`."""
    try:
        groups = command_groups(command)
    except (UnparseableCommand, ValueError):
        return None
    for group in groups:
        if len(group) < 2 or _cmd_word(group[-1]) != "tail":
            continue
        producer = group[0]
        if _cmd_word(producer) in NOT_WRITERS:
            continue
        if any(tok.split("=", 1)[0] in WRITER_FLAGS for tok in producer):
            return " | ".join(" ".join(stage) for stage in group)
    return None


def background_pipeline(command, background):
    """The offending pipeline, or None.

    THE THIRD SHAPE.

    `status_after_pipe` above fires only when the COMMAND reads `$?`. A
    backgrounded command reads nothing: the HARNESS reads the pipeline's exit
    status and reports it back as the task's result. So a producer that failed
    inside `producer | tail` is reported as "exit code 0" and the author is
    told the task succeeded, with the guard silent because no `$?` appears
    anywhere.

    Deliberately narrow, because a noisy guard is one nobody reads: it needs
    the background flag AND a real pipe AND a display-only last stage. A
    foreground `cmd | tail` is not flagged, since there the author sees the
    output and no status is being consumed on their behalf.
    """
    if not background:
        return None
    if "pipefail" in command or "PIPESTATUS" in command:
        return None
    try:
        groups = command_groups(command)
    except (UnparseableCommand, ValueError):
        return None
    for group in groups:
        if len(group) > 1 and _cmd_word(group[-1]) in DISPLAY_ONLY:
            return " | ".join(" ".join(stage) for stage in group)
    return None


def _blank_command_substitutions(text):
    """`text` with every `$(...)` replaced by one placeholder word.

    Without it the detached-work check would warn on calls that background
    nothing. The tokenizer is shlex, and shlex does not know that
    `$(` opens a new quoting context. So in `echo "status: $(curl "http://h?a=1&b=2")"`
    the inner `"` reads as CLOSING the outer string, the URL lands outside every
    quote, and its `&` looks like a job being detached.

    Nothing inside a substitution can detach the call itself, so hiding it costs
    the check nothing. Single-quoted text is left alone, because `$(` there is
    literal. An unbalanced `$(` leaves the rest of the text as it was, so a
    malformed command reads exactly as it did before this existed.
    """
    out, i, n = [], 0, len(text)
    in_single = in_double = False
    while i < n:
        c = text[i]
        if in_single:
            out.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == "$" and text[i + 1:i + 2] == "(":
            depth, j, quote = 1, i + 2, None
            while j < n and depth:
                ch = text[j]
                if ch == "\\" and j + 1 < n and quote != "'":
                    j += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = None
                elif ch in "'\"":
                    quote = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                j += 1
            if depth:
                out.append(text[i:])
                break
            out.append("__CMDSUB__")
            i = j
            continue
        if c == '"':
            in_double = not in_double
        elif c == "'" and not in_double:
            in_single = True
        out.append(c)
        i += 1
    return "".join(out)


def _split_newline_runs(tokens):
    """`tokens` with each operator run that holds a newline split at the newline.

    shlex groups a run of punctuation into ONE token, so a real trailing `&` that
    ends a line arrives as "&\\n", which is not "&". Reading line by line hid that,
    because no line ever carried its newline. Reading the whole command at once
    exposes it.
    """
    out = []
    for tok in tokens:
        if "\n" in tok and tok.strip("\n") and all(ch in "&|;\n" for ch in tok):
            pieces = tok.split("\n")
            for idx, piece in enumerate(pieces):
                if piece:
                    out.append(piece)
                if idx < len(pieces) - 1:
                    out.append("\n")
        else:
            out.append(tok)
    return out


def detached_work(command):
    """The detached command, or None.

    THE FOURTH SHAPE.

    `background_pipeline` above needs a PIPE ending in a display filter. This
    one needs neither. When a call sends its real work into the background with
    a trailing `&`, the shell returns as soon as the job is SPAWNED, so the
    status the harness reports belongs to the wrapper and is 0 whatever the
    work goes on to do. There is no pipe and no `$?`, so the three checks above
    are all silent, and the reported success is about a process that has barely
    started.

    `wait` is the escape hatch and it is not a loophole: a call that waits for
    its jobs really does report their status, which is the correct way to
    background work whose result you intend to read.
    """
    # PARSED, NOT MATCHED.
    #
    # The shared tokenizer already separates `&` from `&&` and knows what is
    # inside quotes, so `echo "tom & jerry"` is not a background job. Rebuilding
    # that with a regex is how a guard starts firing on prose.
    # `strip_heredocs` returns (text, bodies), and shlex drops newlines, so the
    # text is split into lines BEFORE tokenizing exactly as `command_groups`
    # does.
    scannable, _bodies = strip_heredocs(command)
    # JOIN LINE CONTINUATIONS FIRST. A trailing backslash means the shell reads
    # the next line as part of this command, and shlex raises "No escaped
    # character" on the fragment, so a multi-line `nohup ... \` invocation would
    # never be read.
    scannable = scannable.replace("\\\n", " ")
    scannable = _blank_command_substitutions(scannable)
    # READ THE WHOLE COMMAND FIRST, and only split into lines when that fails.
    # Reading line by line cuts a quoted string that spans lines, such as a
    # multi-line `python3 -c "..."`, in half: the closing quote on a later line
    # then reads as OPENING one, and a URL's `&` further along lands outside the
    # quotes. The tokenizer already returns a newline as its own token, so
    # nothing is lost.
    try:
        tokens = _split_newline_runs(tokenize(scannable))
    except (UnparseableCommand, ValueError):
        # Skip a line that will not tokenize rather than abandoning the rest: one
        # bad line must not blind the check to every other line.
        tokens = []
        for line in scannable.split("\n"):
            try:
                tokens.extend(tokenize(line))
            except (UnparseableCommand, ValueError):
                continue
    # No blank-line skip is needed: `tokenize("")` returns `[]` without raising,
    # and with no tokens the `&` check below already returns None.

    if any(t == "wait" for t in tokens):
        return None
    if not any(t == "&" for t in tokens):
        return None

    # Report the segment the `&` detaches, so the warning names the real job
    # rather than the whole call.
    segment, detached = [], None
    for token in tokens:
        if token == "&":
            if segment:
                detached = " ".join(segment)
                break
            continue
        if token in OPERATORS:
            segment = []
            continue
        segment.append(token)
    return detached


def _redirects_to_file(stage):
    """True when this stage sends its output to a FILE, not to another fd.

    `2>&1` is a redirect and is NOT one of these: it duplicates a descriptor and
    leaves the output exactly where it already was. Only a file target hides the
    output from the author, which is the property this check is about.
    """
    tokens = list(stage)
    for i, tok in enumerate(tokens):
        # `>&` is descriptor duplication, never a file. The tokenizer emits it as
        # its OWN token, so `2>&1` arrives as ['2', '>&', '1'] and this is the
        # clause that keeps it out. Checking the token AFTER a bare `>` for a
        # leading `&` would be dead code, because `> &1` never tokenizes that way.
        if tok.startswith(">&"):
            continue
        if tok in (">", ">>", "1>", "2>", "&>"):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if target and not _is_discard(target):
                return True
        elif tok.startswith(">") and len(tok) > 1:
            if not _is_discard(tok.lstrip(">")):
                return True
    return False


def _is_discard(target):
    """`/dev/null` is a bin, not a file anyone reads afterwards.

    `find ... 2>/dev/null; ... | head` throws stderr away and then pages the
    real output, which is an ordinary, correct command: nothing is
    hidden, because nothing was kept. The trap this guard is about needs output
    SAVED somewhere the author is not looking, so a discard cannot be it.

    A guard that cries wolf gets discounted, and the next warning is the real
    one, so this narrowing is the point rather than a concession.
    """
    return target.rstrip("/") in ("/dev/null", "/dev/zero")


def _is_not_the_work(group):
    """True when this final group cannot carry the status the author wanted.

    Two shapes:

      * a pure display filter (`cat log`, `tail -5 log`), whose status is its own
      * `echo "EXIT=$?"`, whose status is the ECHO's and is always 0

    The second is the more common of the two.

    `echo` is deliberately NOT in DISPLAY_ONLY. That set is about filters that consume
    input, and adding echo to it would change what three other checks mean.
    """
    word = _cmd_word(group[-1])
    if word in DISPLAY_ONLY:
        return True
    if word == "echo":
        return "$?" in " ".join(" ".join(s) for s in group)
    return False


def redirect_then_display(command, background=False):
    """The offending chain, or None.

    THE FIFTH SHAPE.

        codex_delegate.py ... > codex.log 2>&1; echo "EXIT=$?"; tail -5 codex.log

    There is no pipe anywhere, so `status_after_pipe` does not apply. The harness
    can move a long foreground call to the background at the ten-minute ceiling,
    so the background flag may be unset and `background_pipeline` does not apply
    either. And the
    `echo "EXIT=$?"` line prints the TRUE status into the output, which makes the
    command look like it followed the rule.

    What actually happens: the reported status is the LAST clause's, and the last
    clause is `tail`, which succeeds on anything. A job that wrote no output file
    still comes back as "completed (exit code 0)".

    THE TWO CONDITIONS TOGETHER ARE WHAT MAKE IT A MISTAKE, and either alone is
    ordinary. A redirect to a file means the author cannot see the real output.
    Ending on a display filter means the status they are handed belongs to the
    filter. `ls; cat notes.txt` has no redirect and is fine. `cmd > log 2>&1`
    alone has no filter and is the form this hook RECOMMENDS. Only the pair is
    the trap, which keeps this narrow.

    It fires in the foreground too, unlike `background_pipeline`, because the
    harness moves a long foreground call into the background on its own after
    ten minutes.
    """
    if "pipefail" in command or "PIPESTATUS" in command:
        return None
    # In the FOREGROUND this shape is harmless: the true status is echoed straight into the
    # output you read, and it is only when the result comes back as a notification that the
    # last clause's status is what you are handed. See SLOW_RUNNERS.
    if not result_arrives_as_notification(command, background):
        return None
    try:
        groups = command_groups(command)
    except (UnparseableCommand, ValueError):
        return None
    # A lone `tail file` needs no early exit: the loop over `groups[:-1]` below is
    # empty for a single group and returns None. This guard is real:
    # `groups[-1]` on an empty list raises.
    if not groups:
        return None
    last = groups[-1]
    if not _is_not_the_work(last):
        return None
    for group in groups[:-1]:
        for stage in group:
            if _redirects_to_file(stage):
                return " ; ".join(
                    " ".join(" ".join(s) for s in g) for g in groups
                )[:200]
    return None


def missing_timeout(command):
    """The offending segment, or None. Asks the system, never assumes the OS."""
    try:
        groups = command_groups(command)
    except (UnparseableCommand, ValueError):
        return None
    for group in groups:
        for stage in group:
            name = _cmd_word(stage)
            if name in TIMEOUT_NAMES and shutil.which(name) is None:
                return " ".join(strip_prefixes(stage))
    return None


def raw_codex_exec(command):
    """The offending segment, or None.

    `codex exec` typed as a shell command bypasses the runner that owns its four
    traps. With no stdin given it prints `Reading additional input from stdin...`
    and waits until the ten-minute Bash ceiling kills it.
    
    The runner, skills/_shared/codex_delegate.py, spawns it as an argv list rather
    than as a shell command line, so it never reaches this hook. A command that already
    closes stdin has dealt with the trap this warns about, so it stays quiet.
    """
    try:
        groups = command_groups(command)
    except (UnparseableCommand, ValueError):
        return None
    for group in groups:
        for stage in group:
            tokens = strip_prefixes(stage)
            if len(tokens) >= 2 and _cmd_word(stage) == "codex" and tokens[1] == "exec":
                if "/dev/null" in command:
                    return None
                return " ".join(tokens)
    return None


# A `while`/`until` loop that waits on `pgrep -f ...` or `ps ... | grep ...`.
# A quoted string, double or single, whichever opens first. Its CONTENT is data.
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'')

SELF_WAIT = re.compile(r"\b(?:while|until)\b[^;\n]*?"
                       r"(?:\bpgrep\s+(?:-\w+\s+)*-\w*f|\bps\b[^|\n;]*\|\s*grep\b)"
                       r"[^\n]*?(?:;|\n)\s*do\b")


def self_matching_wait(command):
    """The loop text, or None. BLOCKS rather than warns: a warn reaches the model only when
    the command ends, and this command ends at the timeout (10 minutes).

    The Bash tool runs the command as `zsh -c '<command>'`, so the pattern is in the waiting
    shell's own command line and pgrep/ps always finds it. Quiet when the loop drops its own
    shell with `$$`. Only the text the shell RUNS is read: heredoc bodies (a script being
    written, which runs in another shell) and quoted strings (an example being printed)
    are removed first, so a real loop beside either one still counts.
    """
    try:
        text, _bodies = strip_heredocs(command)
    except Exception:  # noqa: BLE001 - an unreadable heredoc leaves the text as it is
        text = command
    if "$$" in text:
        return None
    m = SELF_WAIT.search(_QUOTED.sub(lambda q: q.group(0)[0] * 2, text))
    return m.group(0) if m else None


# zsh reads `$NAME:<letter>` as NAME with a HISTORY MODIFIER (`:a` absolute path, `:h` head,
# `:t` tail, `:r` root, `:e` extension, `:l`/`:u` case, `:p`, `:q`, `:s`, `:w`, `:x`, ...), in
# double quotes too, so `git show "$b:app/config.py"` asks git for `<abs path of $b>pp/config.py`.
# `${NAME}:...` is safe and is the fix.
_ZSH_MODIFIER = re.compile(r"(?<![\\$])\$([A-Za-z_][A-Za-z0-9_]*|[0-9])(:[aAcehlpPqQrstuwx][^\s\"'`;|&)]*)")
_HEREDOC_BODY = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\s*(?:\n|$)", re.S)
_SINGLE_QUOTED = re.compile(r"'[^']*'")


def zsh_colon_modifier(command):
    """The offending `$NAME:...` text, or None. Heredoc bodies and single-quoted text are
    skipped: a heredoc is written out for another program, and zsh does not expand inside
    single quotes. Warns only; a deliberate `$0:h` is rare and can take the bypass."""
    text = _HEREDOC_BODY.sub("\n", command)
    text = _SINGLE_QUOTED.sub("''", text)
    m = _ZSH_MODIFIER.search(text)
    return m.group(0) if m else None


# zsh does NOT word-split an unquoted `$VAR`, so a value holding spaces or newlines reaches
# the command as ONE word: a check loop reads "cannot open file" on every row, or a
# verification reports 0 present.
_FOR_LOOP = re.compile(r"\bfor\s+([A-Za-z_]\w*)\s+in\s+([^;\n]*?)\s*(?:;|\n)\s*do\b(.*?)\bdone\b",
                       re.S)
_DOUBLE_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
_BARE_VAR_LIST = re.compile(r"^\$\{?([A-Za-z_]\w*)\}?$")
_SET_DASHDASH = re.compile(r"\bset\s+--\s+\$\{?([A-Za-z_]\w*)\}?(?=\s|;|$)")


def _unquoted_var_uses(text, name):
    """How many times `$name` / `${name}` appears OUTSIDE quotes, tracking nesting: a double
    quote inside `$( )` opens a new string, so `"$(grep "$t" f)"` is quoted throughout."""
    stack, i, hits, n = ["top"], 0, 0, len(text)
    pat = re.compile(r"\$(?:\{%s\}|%s(?![\w]))" % (re.escape(name), re.escape(name)))
    while i < n:
        ctx, c = stack[-1], text[i]
        if c == "\\":
            i += 2
            continue
        if ctx != "dq" and c == "'":
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if text.startswith("$(", i):
            stack.append("cs")
            i += 2
            continue
        if c == '"':
            if ctx == "dq":
                stack.pop()
            else:
                stack.append("dq")
            i += 1
            continue
        if c == ")" and ctx == "cs":
            stack.pop()
            i += 1
            continue
        if c == "$" and ctx != "dq" and pat.match(text, i):
            hits += 1
        i += 1
    return hits


def _item_with_space(items):
    """True when one ITEM of a for-list holds whitespace, read the way the shell splits the
    list. A list built by `$( )` or backticks is split by zsh itself, so it never counts."""
    if items.startswith(("$(", "`")):
        return False
    try:
        tokens = shlex.split(items)
    except ValueError:
        return False
    return any(re.search(r"\s", t) for t in tokens)


def _plain_string_var(text, name):
    """True when the command assigns `name` a plain (non-array) value itself."""
    return bool(re.search(r"(?:^|[\s;&|(])%s=(?!\()" % re.escape(name), text))


def zsh_no_split(command):
    """The offending text, or None.
    Three shapes:
    a loop over quoted items holding spaces whose variable is used UNQUOTED in the body;
    `for f in $VAR` with one bare variable as the whole list; and `set -- $VAR`. The last two
    fire only when this same command assigns VAR a plain string (a zsh array splits, and a
    variable set elsewhere cannot be judged). Heredoc bodies are skipped."""
    text = _HEREDOC_BODY.sub("\n", command)
    for m in _FOR_LOOP.finditer(text):
        name, items, body = m.group(1), m.group(2).strip(), m.group(3)
        if _item_with_space(items) and _unquoted_var_uses(body, name):
            return m.group(0)[:160]
        lone = _BARE_VAR_LIST.match(items)
        if lone and _plain_string_var(text[:m.start()], lone.group(1)):
            return ("for %s in %s" % (name, items))[:160]
    s = _SET_DASHDASH.search(text)
    if s and _plain_string_var(text[:s.start()], s.group(1)):
        return s.group(0)
    return None


def build_message(command, background=False):
    zsh = tool_shell() == "zsh"
    pipeline = status_after_pipe(command)
    colon_mod = zsh_colon_modifier(command) if zsh else None
    no_split = zsh_no_split(command) if zsh else None
    timeout_seg = missing_timeout(command)
    bg_pipeline = background_pipeline(command, background)
    codex_seg = raw_codex_exec(command)
    redirect_chain = redirect_then_display(command, background)
    detached = detached_work(command)
    writer = writer_into_tail(command)
    if (not pipeline and not timeout_seg and not bg_pipeline and not colon_mod
            and not no_split
            and not codex_seg and not redirect_chain and not detached and not writer):
        return None

    parts = ["SHELL-STATUS WARNING (not blocked, proceed if intended):"]

    if pipeline:
        parts.append(
            "\n  This reads `$?` straight after a pipeline that ends in a display\n"
            "  filter, so the status belongs to that filter and NOT to the command\n"
            "  whose result you want.\n\n"
            "    the pipeline : %s\n\n"
            "  `tail`/`head` succeed on almost anything, so a producer that crashed\n"
            "  still prints 0.\n\n"
            "  Read the real status one of these ways, BEST FIRST:\n"
            "      cmd > out.txt 2>&1; echo $?   # no pipe at all, then read out.txt\n"
            "      set -o pipefail            # then $? is the first failing stage"
            % pipeline[:160]
        )
        if zsh:
            parts.append(
                "  Do NOT reach for ${PIPESTATUS[0]}: that array is bash's, the shell here\n"
                "  is zsh where it is lowercase AND 1-indexed, so the bash spelling expands\n"
                "  to an empty string."
            )

    if writer:
        parts.append(
            "\n  This pipes a command that WRITES (it carries --apply, --push or a\n"
            "  similar flag) into `tail`. A writer that refuses prints the refusal\n"
            "  FIRST, then the plan it would have written, so `tail` keeps the plan\n"
            "  and drops the refusal. What you read looks like success.\n\n"
            "    the pipeline : %s\n\n"
            "  Send it to a file and read the whole file, or use `head`:\n"
            "      cmd --apply > out.log 2>&1; echo $?   # then read out.log\n"
            "  And confirm the WRITE landed (grep the file it changed)."
            % writer[:160]
        )

    if redirect_chain:
        parts.append(
            "\n  This sends the real output to a FILE and ends on a clause that is\n"
            "  NOT the work, so the status you are handed belongs to that clause.\n"
            "  A trailing `tail`/`cat` reports its own success; a trailing\n"
            "  `echo \"EXIT=$?\"` reports the echo's, which is 0 whatever happened.\n\n"
            "    the chain : %s\n\n"
            "  You are seeing this because the result comes back as a NOTIFICATION\n"
            "  rather than in the output you read: the call is backgrounded, or it\n"
            "  is a long runner the harness moves there itself. In the foreground\n"
            "  the echo prints the true status straight to you and this stays quiet.\n\n"
            "  A job that wrote no output file still comes back this way as\n"
            "  \"completed (exit code 0)\".\n\n"
            "  Read the file in the NEXT call, or `wait` for the job:\n"
            "      cmd > out.log 2>&1        # then read out.log\n"
            "  And before believing any delegated run, check its OUTPUT FILE EXISTS.\n"
            "  A missing artifact is the honest signal; the status never was."
            % redirect_chain[:200]
        )

    if bg_pipeline:
        parts.append(
            "\n  This runs in the BACKGROUND and ends in a display filter, so the\n"
            "  exit status the task reports back is the FILTER's, never the\n"
            "  producer's.\n\n"
            "    the pipeline : %s\n\n"
            "  Nothing here reads `$?`, which is why the other check above stays\n"
            "  silent: the HARNESS reads it for you and hands it back as\n"
            "  \"completed (exit code 0)\" even when the producer failed. Only a\n"
            "  missing output FILE shows the work never happened.\n\n"
            "  Drop the filter and read the file afterwards:\n"
            "      cmd > out.log 2>&1        # then read out.log when it finishes\n"
            "  A background task's output is already captured to a file, so the\n"
            "  filter buys nothing and costs the status."
            % bg_pipeline[:160]
        )

    if timeout_seg:
        parts.append(
            "\n  `%s` is not installed on this machine, so this segment exits 127 and\n"
            "  runs NOTHING.\n\n"
            "    the segment : %s\n\n"
            "  It is GNU coreutils and a stock macOS does not ship it. A per-file loop\n"
            "  using it records a failure for EVERY file, which reads as the code being\n"
            "  broken rather than the harness. Drop it, or run the command in the\n"
            "  background and poll it."
            % (_cmd_word(tokenize(timeout_seg)) or "timeout", timeout_seg[:160])
        )

    if detached:
        parts.append(
            "\n  This sends its real work into the BACKGROUND with a trailing `&`,\n"
            "  so the shell returns as soon as the job is SPAWNED. The status you\n"
            "  are handed belongs to the wrapper and is 0 whatever the work goes\n"
            "  on to do, including failing immediately.\n\n"
            "    the detached command : %s\n\n"
            "  There is no pipe and no `$?` here, which is why the other checks in\n"
            "  this guard stay silent on it.\n\n"
            "  If you MEANT to detach (a dev server you will curl anyway), carry on.\n"
            "  If you intend to READ this work's result, do one of these:\n"
            "      cmd > out.log 2>&1 &\n"
            "      wait                      # now the status is really the work's\n"
            "  or drop the `&` and let the harness run it in the background for you.\n\n"
            "  Either way, before believing ANY status: check the OUTPUT FILE EXISTS\n"
            "  and read it in the NEXT call. A missing artifact is the honest signal.\n"
            "  The status never was."
            % detached[:160]
        )

    if no_split:
        parts.append(
            "\n  zsh does NOT split an unquoted $VAR into words, so a value holding spaces\n"
            "  or newlines reaches the command as ONE argument.\n\n"
            "    the loop : %s\n\n"
            "  `for t in \"x.py --check\"; do $P $t` runs a file literally named\n"
            "  \"x.py --check\" (\"can't open file\" on every row); `for f in $FILES` runs the\n"
            "  body once with every name joined; `set -- $pair` leaves $2 empty.\n"
            "\n  Split it on purpose:  ${=VAR}  (words)  or  ${(f)VAR}  (lines),\n"
            "  or list the items separately."
            % no_split[:160]
        )

    if colon_mod:
        parts.append(
            "\n  zsh reads `$NAME:<letter>` as a HISTORY MODIFIER on NAME, even inside\n"
            "  double quotes, so this is not NAME followed by \":...\".\n\n"
            "    the text : %s\n\n"
            "  `git show \"$b:app/config.py\"` becomes `<absolute path of $b>pp/config.py`\n"
            "  (`:a`), and the same bites `:h :t :r :e :l :u :p :q :s :w :x`. In a loop\n"
            "  every row comes back empty or zero, which reads like a clean result.\n"
            "\n  Write the variable with braces:  \"${b}:app/config.py\""
            % colon_mod[:160]
        )

    if codex_seg:
        parts.append(
            "\n  This calls `codex exec` directly instead of the runner that owns its\n"
            "  traps, and stdin is not closed.\n\n"
            "    the segment : %s\n\n"
            "  `codex exec` READS STDIN when none is given and blocks. The tell is an\n"
            "  output file holding only `Reading additional input from stdin...`, and\n"
            "  the run then dies at the 10-minute Bash ceiling having done nothing.\n\n"
            "  Close stdin in the same breath: append `< /dev/null` to the command.\n"
            "  If you installed this pack's skills (README step 2), the runner\n"
            "  ~/.claude/skills/_shared/codex_delegate.py also handles the missing\n"
            "  `timeout` and the writable-sandbox default; its guide is\n"
            "  ~/.claude/skills/_shared/codex-delegation.md."
            % codex_seg[:160]
        )

    parts.append(
        "\n  Bypass with %s appended unquoted, or CLAUDE_ALLOW_SHELL_STATUS=1.\n"
        "  Never put that marker in a command a person will run." % BYPASS_MARKER
    )
    return "\n".join(parts)


def main():
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command:
        return 0
    if BYPASS_MARKER in command or os.environ.get("CLAUDE_ALLOW_SHELL_STATUS") == "1":
        return 0

    loop = self_matching_wait(command)
    if loop:
        sys.stderr.write(
            "BLOCKED: this wait loop matches ITSELF and never ends.\n\n"
            "    the loop : %s\n\n"
            "  The shell running this command has the pgrep/grep pattern in its own command\n"
            "  line, so the process never looks finished and the loop waits until the Bash\n"
            "  timeout. Wait on what the work writes instead: its output file, a final line in\n"
            "  its log, or the harness's completion notice (run the work with\n"
            "  run_in_background and do not poll).\n"
            "  Bypass with %s appended unquoted, or CLAUDE_ALLOW_SHELL_STATUS=1.\n"
            "  Never put that marker in a command a person will run.\n" % (loop[:160], BYPASS_MARKER))
        return 2

    background = bool((payload.get("tool_input") or {}).get("run_in_background"))
    message = build_message(command, background)
    if not message:
        return 0

    json.dump({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": message,
    }}, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail OPEN, loudly
        sys.stderr.write("shell-status-guard failed open: %r\n" % (exc,))
        sys.exit(0)
