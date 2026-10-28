#!/usr/bin/env python3
"""PreToolUse guard: an early clause that can ABORT an && chain must not sit before a file write.

THE FAILURE THIS PREVENTS. In an `&&` chain, when an early clause fails, every later
clause is skipped. The side effects of those later clauses simply never happen, and the
only signal is one error line about the early clause. When a later clause was writing a
file, the file is silently never written, and the next command reports success about
something else, which reads as though the write went through.

Two causes produce it. A relative `cd` that fails because the shell is already
somewhere else: the shell's directory carries over between calls, so a relative
path is a bet on where it is. And an unmatched glob: zsh's NOMATCH errors the
command BEFORE it runs, so `rm -f page-*.png` with no matches aborts the chain,
and `-f` does not help because rm is never invoked.

WHY THESE TRIGGERS AND NOT A WIDER ONE. "Any clause before a write" and "any cd
before a write" both cover a large share of ordinary calls, so the guard looks
only at a RELATIVE cd and at an unquoted glob. An absolute `cd` does not
depend on where the shell is, so only a relative one is checked.

WHY ONE ARM BLOCKS AND THE OTHER WARNS. A relative `cd` is unambiguous to detect
and rare, so blocking it is nearly free and the remedy is to write an absolute
path. The glob arm cannot know in advance whether every glob will match, so it
warns.

THE GLOB ARM IS QUOTE AWARE, deliberately. A `*` inside quotes is a pattern argument and
not a glob, so a substring scan would fire on `grep -rn '*.py'`, which is exactly the
mistake `_bash_command_parse.py` was written to stop.

ORDER AND OPERATOR ARE BOTH PART OF THE SIGNAL. The guard fires only when the risky
clause comes BEFORE the write and is joined forward by `&&`. A `;` or a newline does not
short-circuit, so the write still runs and nothing is lost. A risky clause AFTER the
write loses nothing either.

Heredoc bodies are stripped before any of this, so a script being WRITTEN whose
text contains `cd`, `>` or `*` is not read as shell.

BYPASS: append `#allow-chain-write` to the command, or set CLAUDE_ALLOW_CHAIN_WRITE=1.
Never put the marker in a command a person runs in their own shell: that shell has
no hook, and interactive zsh has interactivecomments unset, so the marker reaches
the command as an argument.

Fails OPEN, loudly, like the other guards here. Python 3.9 compatible.
"""

import glob as globmod
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Any `cd`, absolute or relative. `relative_cd` answers a narrower question (is this a
# BET on the current directory); this one answers "can I still trust cwd for a glob".
_CD_ANY = re.compile(r"(?:^|[\s;&|(])cd\s")

BYPASS_MARKER = "#allow-chain-write"

# A clause writes a file when it redirects to one or pipes into tee. Heredoc bodies are
# stripped first, so a script BEING WRITTEN whose text contains '>' is not misread.
_WRITE = re.compile(
    r"(?:^|[\s;&|({])(?:\d?>>?|&>>?)\s*[^\s;&|<>()]"
    r"|(?:^|[\s;&|(])tee\s"
)

# Split on operator text, keeping the operator that joins each clause to the next.
_SPLIT = re.compile(r"(\|\||&&|;|\||&|\n)")

# Redirect operators as the tokenizer returns them. `>&` duplicates a descriptor
# (`>&2`) and creates no file, so it is not here.
_REDIRECT_OPS = {">", ">>", ">|", "&>", "&>>"}


def writes_file(text):
    """True when this clause redirects into a file or runs tee.

    Read from the QUOTE-AWARE parse, so `echo done>status.txt` is a write (no space
    is needed before `>`) and `echo "a > b"` is not (the `>` is inside an argument).
    A clause that will not tokenize is read with the `_WRITE` pattern instead.
    """
    try:
        from _bash_command_parse import strip_prefixes, tokenize
        tokens = tokenize(text)
    except Exception:  # noqa: BLE001 - unbalanced quotes or a missing helper
        return bool(_WRITE.search(text))
    for i, tok in enumerate(tokens):
        if tok in _REDIRECT_OPS and i + 1 < len(tokens):
            return True
    words = strip_prefixes(tokens)
    while words and words[0] in ("(", "{"):
        words = strip_prefixes(words[1:])
    return bool(words) and os.path.basename(words[0]) == "tee"


def tool_shell(environ=None):
    """The shell Claude Code's Bash tool runs commands in, "zsh" or "bash".

    Claude Code docs, env-vars page, CLAUDE_CODE_SHELL: "If the value is not a working
    `bash` or `zsh` path, Claude Code ignores it and falls back to auto-detection.
    Auto-detection uses your `$SHELL` when it points to `bash` or `zsh`, otherwise it
    picks the first working `zsh` then `bash` found on your `PATH` and standard
    install locations." The glob and `=word` arms describe zsh behaviour, so they run
    only when zsh is the shell.
    """
    env = os.environ if environ is None else environ
    forced = env.get("CLAUDE_CODE_SHELL") or ""
    if os.path.basename(forced) in ("zsh", "bash") and os.access(forced, os.X_OK):
        return os.path.basename(forced)
    name = os.path.basename(env.get("SHELL") or "")
    if name in ("zsh", "bash"):
        return name
    import shutil
    return "zsh" if shutil.which("zsh") else "bash"


def chained(cl):
    """The clauses with a line break after `&&`, `||` or `|` folded away.

    `cd x &&` at the end of a line continues the same list on the next line, so the
    empty clause the split leaves there must not end the chain.
    """
    out = []
    for text, op in cl:
        if not text.strip() and out and out[-1][1] in ("&&", "||", "|"):
            continue
        out.append((text, op))
    return out


def _strip_heredocs(command):
    try:
        from _bash_write_targets import strip_heredocs
        stripped, _bodies = strip_heredocs(command)
        return stripped
    except Exception:
        return command


def clauses(command):
    """[(clause_text, operator_joining_it_to_the_next)]; the last operator is None."""
    parts = _SPLIT.split(_strip_heredocs(command))
    out = []
    i = 0
    while i < len(parts):
        text = parts[i]
        op = parts[i + 1] if i + 1 < len(parts) else None
        out.append((text, op))
        i += 2
    return out


def relative_cd(text):
    """The target of a `cd` whose path is relative, or None.

    A leading `/`, `~` or `$` means the target does not depend on where the shell
    happens to be, which is the whole hazard. `cd -` is relative to history and is
    treated as relative.

    The target is read from a QUOTE-AWARE PARSE, not from a regex over the raw text.
    A regex stopping at whitespace reads `cd "/home/me/My Projects"` as the token
    `"/home/me/My`, which begins with a quote rather than a slash and so reports an
    absolute path as relative; `cd "$(mktemp -d)"` is another. This is the same
    substring-versus-parse mistake `_bash_command_parse.py` exists to stop.
    """
    try:
        from _bash_command_parse import tokenize, strip_prefixes, cd_target
        target = cd_target(strip_prefixes(tokenize(text)))
    except Exception:
        # Unbalanced quotes or a missing helper: fail open rather than guess.
        return None
    if not target:
        return None
    if target.startswith(("/", "~", "$")):
        return None
    return target


def unquoted_glob(text):
    """True when *, ? or [ appears OUTSIDE quotes, so zsh would expand it.

    A `[` that stands as its own WORD is the test command, not a glob. zsh expands
    `[0-9]` and never a bracket with whitespace on both sides, so counting one as a
    glob would make this arm fire on ordinary shell, and a warning that is often
    wrong is one nobody reads.
    """
    quote = None
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "[" and (i == 0 or text[i - 1].isspace()):
            j = i
            while j < len(text) and not text[j].isspace():
                j += 1
            if text[i:j] in ("[", "[["):
                i = j
                continue
            return True
        if c in "*?[":
            return True
        i += 1
    return False


def unquoted_glob_tokens(text):
    """The whitespace-separated tokens whose glob character sits OUTSIDE quotes.

    `unquoted_glob` above answers "does this clause carry a glob at all", which is the
    right question when the glob endangers a LATER clause. It is the wrong question when
    the destructive command IS the clause, because the hazard there is the COUNT: zsh
    aborts the whole command when ANY one glob matches nothing, so a command carrying two
    globs deletes NEITHER set when only one of them matches.
    """
    tokens, buf, quote = [], [], None
    has_glob = False
    i = 0
    while i <= len(text):
        c = text[i] if i < len(text) else " "
        if quote:
            if c == "\\" and quote == '"':
                buf.append(c)
                i += 2
                continue
            if c == quote:
                quote = None
            buf.append(c)
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "\\":
            buf.append(c)
            i += 2
            continue
        if c.isspace():
            if buf and has_glob:
                tokens.append("".join(buf))
            buf, has_glob = [], False
            i += 1
            continue
        if c in "*?":
            has_glob = True
        buf.append(c)
        i += 1
    return tokens


_OPT_HEAD = re.compile(r"^--?[A-Za-z][\w.-]*=")


def _glob_scan(text, per_line):
    """(words, final_quote) for `glob_words`. See there for the rules."""
    out = []
    quote = None
    for line in (text.split("\n") if per_line else [text]):
        if per_line:
            quote = None
        buf, has_glob, depth = [], False, 0
        i, n = 0, len(line)
        while i <= n:
            c = line[i] if i < n else " "
            if quote:
                # Backslash escapes inside "..." and inside $'...' (ANSI-C quoting,
                # where `\\'` is an apostrophe and does NOT close the string).
                if c == "\\" and quote in ('"', "$'"):
                    buf.append(c)
                    i += 2
                    continue
                if c == quote[-1]:
                    quote = None
                buf.append(c)
                i += 1
                continue
            if c == "$" and i + 1 < n and line[i + 1] == "'":
                quote = "$'"
                buf.append("$'")
                i += 2
                continue
            if c in ("'", '"'):
                quote = c
                buf.append(c)
                i += 1
                continue
            if c == "\\":
                buf.append(c)
                i += 2
                continue
            # An unquoted `#` starting a word opens a comment, so an apostrophe in
            # "# don't" cannot open a quote that swallows the lines after it.
            if c == "#" and not buf:
                j = line.find("\n", i)
                if j == -1:
                    break
                i = j
                continue
            # A word ends at whitespace, or at `;` `&` `|` `<` `>` outside (...) and
            # {...}, so `${x%%|*}` and `${x//&*/y}` stay one word. Without this,
            # `ls *.md; echo` looked up `*.md;`, which matches nothing, and warned on
            # a glob that matched.
            if c.isspace() or (c in ";&|<>" and depth == 0):
                if buf and has_glob:
                    out.append("".join(buf))
                buf, has_glob, depth = [], False, 0
                i += 1
                continue
            if c in "({":
                depth += 1
            elif c in ")}" and depth:
                depth -= 1
            if c in "*?":
                has_glob = True
            buf.append(c)
            i += 1
        if not per_line:
            return out, quote
    return out, quote


def glob_words(text):
    """Whitespace-separated words whose glob character sits OUTSIDE quotes.

    Quote state CARRIES across newlines when the command's quotes balance as a whole,
    and resets at every newline only when they do not.
    
    - Resetting always would read a quoted multi-line string as code:
      `sqlite3 db "...\nSELECT 'x', COUNT(*) FROM t;"` would warn that `COUNT(*)`
      matches nothing.
    - Carrying always would let one unbalanced quote on an early line swallow
      every later line, so an unbalanced command gets the per-line scan.
    """
    words, final_quote = _glob_scan(text, per_line=False)
    if final_quote is None:
        return words
    return _glob_scan(text, per_line=True)[0]


def option_glob(command):
    """An `--opt=<glob>` word whose glob is unquoted, or None.

    zsh expands the word before the tool ever sees it, so `grep --include=*.py` is wrong
    BOTH ways. Matching nothing aborts the whole command and runs no grep at all, which
    reads exactly like a clean search. Matching something is worse: the option silently
    becomes several words and grep searches a different set than the one asked for.
    Quoting it is right either way, which is why this arm needs no filesystem check.
    """
    for word in glob_words(_strip_heredocs(command)):
        if _OPT_HEAD.match(word):
            return word
    return None


_CASE_WORD = re.compile(r"(?:^|[\s;&|(])case\s")
_ESAC_WORD = re.compile(r"(?:^|[\s;&|])esac(?:$|[\s;&|)])")
# A case pattern label: after `in` or a `;;` / `;&` / `;|` terminator, an optional `(`,
# one or more patterns joined by `|`, then the closing `)`.
_CASE_LABEL = re.compile(r"((?:\bin|;;|;&|;\|)\s*)\(?[^\s;()|]+(?:\s*\|\s*[^\s;()|]+)*\)")


def _strip_case_labels(command):
    """Remove the pattern labels of a `case ... esac` block, keeping everything else.

    In `case "$x" in MERGED*) ... ;; *) ... ;; esac`, `MERGED*` and `*` are patterns
    matched against the case WORD, never against filenames, so zsh does not expand them
    and NOMATCH cannot fire. Read as glob words they match nothing in any directory, and
    this arm would warn that zsh cancels a command that then runs fine. Only the
    labels go: a real glob inside a branch body is
    still scanned. Gated on both keywords, so a command with no case block is untouched.
    """
    if not (_CASE_WORD.search(command) and _ESAC_WORD.search(command)):
        return command
    return _CASE_LABEL.sub(lambda m: m.group(1), command)


# A command that OPENS with `cd /absolute/path` (bare or double-quoted) and never cds
# again. Its globs resolve against that folder, which is known for certain.
_LEADING_ABS_CD = re.compile(
    r'^\s*cd\s+(?:"(/[^"$`\\]*)"|(/[^\s;&|$`~\'"\\]*))\s*(?:&&|;|\n)')


def _glob_dir(scannable, cwd):
    """The folder this command's globs resolve against, or None when it cannot be known.

    No cd: the harness's cwd. A command that opens with an ABSOLUTE cd to a folder that
    exists, and has no other cd: that folder. Anything else: None. Opening with
    `cd /abs && ...` is the safe habit, so it keeps the check rather than
    switching it off.
    """
    if not _CD_ANY.search(scannable):
        return cwd
    m = _LEADING_ABS_CD.match(scannable)
    if not m or _CD_ANY.search(scannable[m.end() - 1:]):
        return None
    target = m.group(1) or m.group(2)
    return target if os.path.isdir(target) else None


def nonmatching_glob(command, cwd):
    """An unquoted glob that matches NOTHING right now, or None.

    This hook runs BEFORE the command, so it can settle the question zsh is about to
    answer instead of guessing: a glob matching nothing makes zsh NOMATCH abort (the
    command carrying it and its && chain, or the rest of the whole command when the glob
    is a `for` list, a `>` target or an array value), and one that matches is fine. The check is therefore exact for the
    moment the command runs, and a matching glob stays silent, which is what keeps this
    arm quiet enough to be read.

    It checks plain glob words against the working folder the harness supplies,
    or against the folder named by a leading absolute `cd` (`_glob_dir`). Words
    carrying `$`, a backtick, `~` or `**` are read by the shell, and `--opt=`
    words go to `option_glob`.
    """
    if not cwd or not os.path.isdir(cwd):
        return None
    scannable = _strip_case_labels(_strip_heredocs(command))
    cwd = _glob_dir(scannable, cwd)
    if not cwd:
        return None
    for word in glob_words(scannable):
        if _OPT_HEAD.match(word):
            continue
        if any(ch in word for ch in "$`~") or "**" in word:
            continue
        pattern = word if os.path.isabs(word) else os.path.join(cwd, word)
        try:
            if not globmod.glob(pattern):
                return word
        except Exception:
            continue
    return None


def destructive_head(text):
    """The command word when this clause deletes or moves files, else None."""
    try:
        from _bash_command_parse import tokenize, strip_prefixes
        toks = strip_prefixes(tokenize(text))
    except Exception:
        return None
    if not toks:
        return None
    head = toks[0].rsplit("/", 1)[-1]
    return head if head in ("rm", "mv") else None


def multi_glob_delete(command):
    """A delete or move clause carrying TWO OR MORE unquoted globs, or None.

    One glob is deliberately not reported. A single glob that matches nothing removes
    nothing that was going to be removed, so the abort is harmless. Two or more is the
    silent case: the sets that DID match survive, and the only output is the non-match.
    """
    for text, _op in clauses(command):
        if not destructive_head(text):
            continue
        if len(unquoted_glob_tokens(text)) >= 2:
            return text.strip()
    return None


_DECLARERS = {"export", "local", "typeset", "declare", "readonly", "integer", "float"}
# NAME==value: an assignment whose VALUE begins with `=`, which zsh expands too
# (`x==1` and `export A==b` both abort, `echo a==b` does not).
_ASSIGN_EQ = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?==[^\s]")


def _brace_end(text, i):
    """Index just past the `}` closing the `${` whose `{` is text[i]."""
    depth, j, n = 0, i, len(text)
    while j < n:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _eq_words(text):
    """[(word, inside_double_bracket, position, head)] over the whole command.

    Quote state CARRIES across newlines here, unlike `glob_words`: resetting it per
    line would read Python `==` inside a multi-line `python3 -c "..."` as shell.
    Contexts live on
    a stack: `'`, `"`, `$(` (whose words ARE expanded even inside double quotes, since
    `echo "--$(echo a == b)"` aborts) and `(` nested inside one. Outside quotes a newline
    or an unquoted ; | & ( ) { } starts a new simple command, `#` at a word start comments
    out the line, `${...}` stays whole (`${=var}` is zsh's split flag, not an `=` word),
    and arithmetic (( )) / $(( )) is skipped.
    """
    words = []
    buf = []
    stack = []
    dbl = False
    arith = 0
    pos, head = 0, None
    i, n = 0, len(text)

    def flush():
        nonlocal buf, dbl, pos, head
        if buf:
            w = "".join(buf)
            if pos == 0:
                head = w
            if w == "[[":
                dbl = True
            elif w == "]]":
                dbl = False
            else:
                words.append((w, dbl, pos, head))
            pos += 1
        buf = []

    def new_command():
        nonlocal pos, head
        pos, head = 0, None

    while i <= n:
        c = text[i] if i < n else " "
        nxt = text[i + 1] if i + 1 < n else ""
        top = stack[-1] if stack else None
        if arith:
            if c == ")" and nxt == ")":
                arith -= 1
                i += 2
            elif c == "(" and nxt == "(":
                arith += 1
                i += 2
            else:
                i += 1
            continue
        if top == "'":
            if c == "'":
                stack.pop()
            buf.append(c)
            i += 1
            continue
        if top == '"':
            if c == "\\":
                buf.append(text[i:i + 2])
                i += 2
                continue
            if c == '"':
                stack.pop()
                buf.append(c)
                i += 1
                continue
            if c == "$" and nxt == "(" and text[i + 2:i + 3] != "(":
                flush()
                stack.append("$(")
                new_command()
                i += 2
                continue
            buf.append(c)
            i += 1
            continue
        if c in ("'", '"'):
            stack.append(c)
            buf.append(c)
            i += 1
            continue
        if c == "\\":
            buf.append(text[i:i + 2])
            i += 2
            continue
        if c == "#" and not buf:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "$" and nxt == "{":
            end = _brace_end(text, i + 1)
            buf.append(text[i:end])
            i = end
            continue
        if c == "(" and nxt == "(" and (not buf or buf == ["$"]):
            buf = []
            arith = 1
            i += 2
            continue
        if c == "$" and nxt == "(":
            flush()
            stack.append("$(")
            new_command()
            i += 2
            continue
        if top in ("$(", "(") and c == "(":
            flush()
            stack.append("(")
            new_command()
            i += 1
            continue
        if top in ("$(", "(") and c == ")":
            flush()
            stack.pop()
            new_command()
            i += 1
            continue
        if c.isspace() or c in ";|&(){}":
            flush()
            if c == "\n" or c in ";|&(){}":
                new_command()
                if c == "\n":
                    dbl = False
            i += 1
            continue
        buf.append(c)
        i += 1
    flush()
    return words


def equals_word(command):
    """The first unquoted word zsh's EQUALS option would expand, or None.

    zsh replaces a word starting with `=` by the path of the command it names, so
    `echo ====` looks up a command called `===` and, finding none, CANCELS THE WHOLE
    COMMAND with `(eval):1: === not found`. A lookup that succeeds is quieter and no
    better: `echo =ls` prints `/bin/ls`. The zsh behaviour behind it was checked in
    zsh 5.9, including the safe side: a lone `=`, `x=1`, `--opt=val`, `a==b`,
    `[[ a == b ]]`, `(( 1 == 1 ))`.
    """
    for word, dbl, pos, head in _eq_words(_strip_heredocs(command)):
        if word.startswith("=") and len(word) >= 2:
            if dbl and word in ("==", "=~"):
                continue
            return word
        assigning = pos == 0 or head in _DECLARERS
        if not dbl and assigning and _ASSIGN_EQ.match(word):
            return word
    return None


def _glob_only(command, cwd):
    """The arms that need no write and no delete, lowest priority. See step 2 below."""
    hit = option_glob(command)
    if hit:
        return "warn-optglob", hit, ""
    hit = equals_word(command)
    if hit:
        return "warn-equals", hit, ""
    hit = nonmatching_glob(command, cwd)
    if hit:
        return "warn-nomatch", hit, ""
    return None


def verdict(command, cwd=None):
    """Return (severity, risky_clause, write_clause) or None.

    severity is 'block' for a relative cd, 'warn' for an unquoted glob before a write,
    'warn-delete' for a delete carrying two or more globs, 'warn-optglob' for an
    `--opt=<glob>` word, 'warn-equals' for a word zsh's EQUALS option expands, and
    'warn-nomatch' for a glob that matches nothing right now.
    A relative cd anywhere before the write outranks a glob, because it is the sharper
    signal.

    The last two arms need NEITHER a write NOR a delete, which is what they add. Every
    earlier arm requires one, and a plain search or listing is the commonest
    place a NOMATCH abort happens.

    `cwd` is optional; the 'warn-nomatch' arm runs when the harness supplies one.
    """
    cl = chained(clauses(command))
    zsh = tool_shell() == "zsh"

    # Each write is checked against ITS OWN dependency chain: the clauses joined to it
    # by an unbroken run of `&&`. A `;`, `||` or newline ends that run, because a
    # failure before it no longer skips the write. A `|` does not end it: a pipeline
    # is one command in the chain, so `cd x && make | tee log` skips the tee too. Only
    # the clause right before an `&&` is checked, since an earlier pipeline stage's
    # failure does not decide the pipeline's status.
    glob_hit = None
    for write_at, (wtext, _wop) in enumerate(cl):
        if not writes_file(wtext):
            continue
        idx = write_at - 1
        while idx >= 0 and cl[idx][1] in ("&&", "|"):
            text, op = cl[idx]
            idx -= 1
            if op != "&&":
                continue
            if relative_cd(text):
                return "block", text.strip(), wtext.strip()
            if zsh and glob_hit is None and unquoted_glob(text):
                glob_hit = (text.strip(), wtext.strip())
    if glob_hit:
        return "warn", glob_hit[0], glob_hit[1]
    if not zsh:
        # The remaining arms describe how zsh expands a word before the command runs.
        return None
    hit = multi_glob_delete(command)
    return ("warn-delete", hit, "") if hit else _glob_only(command, cwd)


def _emit_warn(message):
    """Deliver a PreToolUse WARNING, which is STDOUT JSON and never stderr.

    A warn written to stderr on exit 0 is discarded in silence: the hook runs, the check
    is right, the exit code is right, and nothing reaches the transcript.
    `hookEventName` is load-bearing; without it the payload is dropped even
    when the JSON is otherwise perfect. Blocking is the opposite and stays on stderr.
    """
    json.dump({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": message,
    }}, sys.stdout)
    sys.stdout.write("\n")
    return 0


def main():
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command:
        return 0
    if BYPASS_MARKER in command or os.environ.get("CLAUDE_ALLOW_CHAIN_WRITE") == "1":
        return 0

    # Deliberately NOT `or os.getcwd()`. This process's directory is not the shell's, so
    # falling back to it resolves the glob against the wrong tree and invents
    # warnings. The 'warn-nomatch' arm runs on the cwd the harness supplies, which
    # is the contract `nonmatching_glob` documents.
    hit = verdict(command, payload.get("cwd"))
    if not hit:
        return 0
    severity, risky, write = hit

    if severity == "block":
        sys.stderr.write(
            "A relative `cd` sits before a file write in the same && chain. If the cd "
            "fails, the write is skipped and the file is silently never created.\n\n"
            "  the cd    : %s\n"
            "  the write : %s\n\n"
            "The shell's directory carries over between calls, so a relative path is a "
            "bet on where it currently is.\n\n"
            "Use an absolute path in the cd, or drop the cd and put the path in the "
            "command itself (`git -C <path>`, an absolute path inside the heredoc).\n\n"
            "Bypass with %s appended unquoted, or CLAUDE_ALLOW_CHAIN_WRITE=1. Never put "
            "that marker in a command a person will run.\n"
            % (risky[:160], write[:160], BYPASS_MARKER)
        )
        return 2

    if severity == "warn-delete":
        return _emit_warn(
            "CHAIN-ABORT WARNING (not blocked, proceed if intended):\n"
            "  This delete carries TWO OR MORE unquoted globs, so it may remove NOTHING "
            "while looking like it worked.\n\n"
            "  the command : %s\n\n"
            "  zsh errors on a glob that matches nothing BEFORE the command runs, and it "
            "cancels the WHOLE command, not just the empty pattern. So the paths that DID "
            "match are still there afterwards, and the only output is the non-match, "
            "which reads as ordinary noise. `-f` does not help, because rm never runs.\n"
            "  Example: `rm -f out/*.md out/*.txt` with no .txt files left removes "
            "none of the .md files either.\n\n"
            "  To empty a directory, use a command that takes no glob:\n"
            "    find <dir> -type f ! -name '.gitkeep' -delete\n"
            "  Otherwise split it into one delete per pattern, and COUNT AFTER DELETING. "
            "A count is the only thing that separates deleted from never-ran.\n"
            % (risky[:160],)
        )

    if severity == "warn-optglob":
        return _emit_warn(
            "CHAIN-ABORT WARNING (not blocked, proceed if intended):\n"
            "  An option value carries an UNQUOTED glob, so zsh expands it before the "
            "tool ever sees it.\n\n"
            "  the option : %s\n\n"
            "  This is wrong BOTH ways, which is why quoting is always the answer:\n"
            "    matches nothing -> zsh cancels the WHOLE command and no search runs at "
            "all, which reads exactly like a clean result.\n"
            "    matches something -> the option silently becomes several words, and the "
            "tool searches a different set than the one you asked for.\n\n"
            "  Quote it: --include='*.py'\n"
            % (risky[:160],)
        )

    if severity == "warn-equals":
        return _emit_warn(
            "CHAIN-ABORT WARNING (not blocked, proceed if intended):\n"
            "  A word starts with `=`, so zsh replaces it with the path of the command it "
            "names before anything runs.\n\n"
            "  the word : %s\n\n"
            "  No such command -> zsh cancels the WHOLE command (`(eval):1: === not "
            "found`), so every later clause silently never runs and the output looks like "
            "a partial result.\n"
            "  A real command -> the word silently becomes its path (`=ls` is /bin/ls).\n"
            "  The common shapes are `echo ====` used as a divider and "
            "`[ \"$a\" == b ]`.\n"
            "  Quote it (`echo '===='`), or use `[[ a == b ]]` for a comparison.\n"
            % (risky[:160],)
        )

    if severity == "warn-nomatch":
        return _emit_warn(
            "CHAIN-ABORT WARNING (not blocked, proceed if intended):\n"
            "  This glob matches NOTHING in the current directory, so zsh stops before "
            "it runs anything that uses it.\n"
            "    as a command's argument (`ls x/*.md`): that command and every clause "
            "chained after it with `&&` are skipped; clauses after `;` still run.\n"
            "    in a `for ... in` list, after `>`, or in an array value: zsh abandons "
            "the rest of the WHOLE command.\n\n"
            "  the glob : %s\n\n"
            "  The only trace is one `no matches found` line, which reads like ordinary "
            "noise or an empty result. `2>/dev/null` does NOT help, because the shell "
            "aborts before the command is invoked.\n"
            "  Quote the pattern to pass it through literally, or pipe a plain listing "
            "into grep instead:\n"
            "    ls | grep -i <name>\n"
            % (risky[:160],)
        )

    return _emit_warn(
        "CHAIN-ABORT WARNING (not blocked, proceed if intended):\n"
        "  An unquoted glob sits before a file write in the same && chain.\n\n"
        "  the glob  : %s\n"
        "  the write : %s\n\n"
        "  zsh errors on a glob that matches NOTHING before the command runs, which "
        "aborts the chain, so the write never happens. `rm -f` does not help, because rm "
        "is never invoked.\n"
        "  If the glob may match nothing, quote it or split the call.\n"
        % (risky[:160], write[:160])
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail OPEN, loudly
        sys.stderr.write("chain-abort-guard failed open: %r\n" % (exc,))
        sys.exit(0)
