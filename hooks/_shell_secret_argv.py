#!/usr/bin/env python3
"""Find shell lines that hand a credential-named variable to an external command.

Called by dangerous-pattern-warn.sh for .sh/.bash files. Prints the 1-based line
numbers of hits, comma separated (at most five), and nothing when clean. Always
exits 0: this feeds a WARNING, and a crash here must not look like a finding.

WHAT COUNTS AS A CREDENTIAL NAME: a variable whose LAST underscore-separated part
is one of CRED_PARTS. So `LINK_KEY`, `MCP_KEY`, `GITHUB_TOKEN` count, and
`MCP_KEY_FILE`, `KEY_PATH`, `API_KEY_ID` and `PATH` do not: a variable that names
WHERE a secret lives is safe to pass around, and the last part says which it is.

WHAT IS SAFE, and every entry here is a reason a real fix of 2026-09-11 is
clean while the original is not:
- a builtin as the command word (`printf`, `echo`, `[`, `test`, `read`, ...):
  a builtin runs inside the shell, so its arguments never reach any argv;
- the secret only in a leading assignment (`KEY="$KEY" cmd`), which is the
  environment route the rule's own message recommends;
- `${#KEY}`, the length, which is not the value;
- a here-string (`<<< "$KEY"`), which is stdin;
- the body of a heredoc, which is text written somewhere, not a command line;
- comment lines.
"""

import re
import sys

CRED_PARTS = {"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PAT",
              "CREDENTIAL", "CREDENTIALS", "APIKEY"}

SAFE_COMMANDS = {"printf", "echo", "[", "[[", "test", "local", "export",
                 "declare", "readonly", "read", "unset", "return", "exit",
                 "case", ":", "shift", "typeset"}

KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{",
            "(", "time", "fi", "done", "esac", "}", ")"}

EXPANSION = re.compile(r"\$\{?(#?)([A-Za-z_][A-Za-z0-9_]*)")
ASSIGNMENT = re.compile(
    r"""^\s*[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=("(\\.|[^"\\])*"|'[^']*'|[^\s]*)\s*""")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SEGMENT_SPLIT = re.compile(r"\|\||&&|;|\||\$\(|`")


def is_credential(name):
    return name.split("_")[-1].upper() in CRED_PARTS


def credential_in(text):
    for m in EXPANSION.finditer(text):
        if m.group(1) == "#":
            continue
        if is_credential(m.group(2)):
            return True
    return False


def segment_hits(segment):
    segment = segment.split("<<<", 1)[0]
    rest = segment
    while True:
        m = ASSIGNMENT.match(rest)
        if not m:
            break
        rest = rest[m.end():]
    words = rest.split()
    while words and words[0] in KEYWORDS:
        words = words[1:]
    if not words:
        return False
    if words[0] in SAFE_COMMANDS:
        return False
    return credential_in(" ".join(words[1:]))


def logical_lines(text):
    """Yield (first line number, joined text), joining backslash continuations
    and skipping heredoc bodies."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1
        line = lines[i]
        while line.endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line[:-1] + " " + lines[i]
        i += 1
        heredoc = HEREDOC.search(line)
        yield start, line
        if heredoc:
            end = heredoc.group(2)
            while i < len(lines) and lines[i].strip() != end:
                i += 1
            i += 1


def scan(text):
    hits = []
    for number, line in logical_lines(text):
        if line.lstrip().startswith("#"):
            continue
        if any(segment_hits(s) for s in SEGMENT_SPLIT.split(line)):
            hits.append(number)
    return hits


def main():
    try:
        with open(sys.argv[1], errors="replace") as f:
            hits = scan(f.read())
    except Exception:
        return 0
    if hits:
        print(", ".join(str(n) for n in hits[:5]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
