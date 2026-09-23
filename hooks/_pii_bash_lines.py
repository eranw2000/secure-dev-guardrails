#!/usr/bin/env python3
"""Split a Bash command into one line per SHELL CLAUSE, for pii-in-logs.sh.

pii-in-logs.sh asks whether a logging call and a personal-data value sit on the SAME
line. For a Bash command a line can hold several commands joined by `;`, `&&`, `||` or
`|`, and those are separate statements: an address passed as an argument to one command
and a `print(...)` in the next were refused together (2026-09-22, a createsuperuser call
followed by a port probe). So a shell line is cut at those operators, and each piece is
judged on its own.

What is NEVER cut, because cutting it would separate a log call from its own argument
and fail open:

  - anything inside quotes, carried across newlines, so a `python3 -c "a; log(x)"` or a
    `node -e '...||...'` one-liner stays one piece;
  - a heredoc body, which is a file being written and is scanned line by line exactly as
    before, operators and all.

Reads the command on stdin, prints the pieces on stdout, one per line. On any error it
prints the command unchanged, so the hook scans what it always scanned: a failure here
can only make the hook stricter, never looser.
"""
import re
import sys

HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def split_clauses(command):
    out = []
    piece = []
    quote = None
    i = 0
    n = len(command)
    pending = []        # heredoc terminators opened on the current shell line
    while i < n:
        ch = command[i]
        if quote:
            piece.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                piece.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            piece.append(ch)
            piece.append(command[i + 1])
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            piece.append(ch)
            i += 1
            continue
        if ch == "#" and (not piece or piece[-1] in " \t"):
            # A shell comment runs to the end of the line; keep it with its piece.
            j = command.find("\n", i)
            j = n if j < 0 else j
            piece.append(command[i:j])
            i = j
            continue
        if ch == "<" and command.startswith("<<", i):
            m = HEREDOC.match(command, i)
            if m:
                pending.append((m.group(2), command.startswith("<<-", i)))
                piece.append(m.group(0))
                i = m.end()
                continue
        if ch == "\n":
            out.append("".join(piece))
            piece = []
            i += 1
            # Copy each heredoc body through untouched, up to its terminator line.
            for word, strip_tabs in pending:
                while i < n:
                    j = command.find("\n", i)
                    j = n if j < 0 else j
                    line = command[i:j]
                    out.append(line)
                    i = j + 1
                    if (line.lstrip("\t") if strip_tabs else line) == word:
                        break
            pending = []
            continue
        two = command[i:i + 2]
        if two in ("&&", "||"):
            out.append("".join(piece))
            piece = []
            i += 2
            continue
        if ch in (";", "|") and two not in (";;",):
            out.append("".join(piece))
            piece = []
            i += 1
            continue
        piece.append(ch)
        i += 1
    out.append("".join(piece))
    return out


def main():
    command = sys.stdin.read()
    try:
        pieces = split_clauses(command)
    except Exception:
        sys.stdout.write(command)
        return 0
    sys.stdout.write("\n".join(pieces))
    return 0


if __name__ == "__main__":
    sys.exit(main())
