#!/usr/bin/env python3
"""Which part of a file did an Edit tool call change?

For hooks that run after an edit and read the whole file. Without this, a finding
anywhere in a file is reported again on every edit of that file, whatever the edit
touched, and a warning that repeats gets ignored.

Every answer is either exact or None. None means "cannot tell" (a Write, a deletion,
new text that is not in the file, text that occurs more than once with no replace_all)
and the caller must then fall back to the whole file: not knowing what changed is not
permission to stay quiet.

Used two ways:
    from _edit_scope import touched_lines          # from a Python hook
    _edit_scope.py <file> <outdir> < tool_input    # from a shell hook

The command writes <outdir>/before.<ext> (the file as it was) and <outdir>/added.<ext>
(only the new text), and exits 3 when it cannot tell.
"""
import json
import os
import sys

CANNOT_TELL = 3


def _edits(tool_input):
    """[(old, new, replace_all), ...], or None when this is not a replace we can read."""
    if not isinstance(tool_input, dict):
        return None
    raw = tool_input["edits"] if "edits" in tool_input else [tool_input]
    if not isinstance(raw, list) or not raw:
        return None
    out = []
    for e in raw:
        if not isinstance(e, dict):
            return None
        old, new = e.get("old_string"), e.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str) or not old or not new:
            return None
        out.append((old, new, bool(e.get("replace_all"))))
    return out


def touched_lines(src, tool_input):
    """[(first_line, last_line), ...] of every place the new text sits, 1-based, or None."""
    edits = _edits(tool_input)
    if edits is None:
        return None
    spans = []
    for _old, new, _all in edits:
        at = src.find(new)
        if at < 0:
            return None
        while at >= 0:
            first = src.count("\n", 0, at) + 1
            # The last line is the one holding the last character written: a new text that
            # ends in "\n" ends its own line and writes nothing on the next (2026-11-22).
            spans.append((first, src.count("\n", 0, at + len(new) - 1) + 1))
            at = src.find(new, at + len(new))
    return spans


def before_image(src, tool_input):
    """The file as it was before the edit, or None."""
    edits = _edits(tool_input)
    if edits is None:
        return None
    for old, new, replace_all in reversed(edits):
        found = src.count(new)
        if found == 0 or (found > 1 and not replace_all):
            return None
        src = src.replace(new, old)
    return src


def added_text(tool_input):
    """Only the new text, or None."""
    edits = _edits(tool_input)
    if edits is None:
        return None
    return "\n".join(new for _old, new, _all in edits) + "\n"


def _save(path, text):
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(text)


def main(argv):
    if len(argv) != 3:
        return CANNOT_TELL
    path, outdir = argv[1], argv[2]
    try:
        tool_input = json.load(sys.stdin)
        with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
            src = f.read()
    except (OSError, ValueError):
        return CANNOT_TELL
    before, added = before_image(src, tool_input), added_text(tool_input)
    if before is None or added is None:
        return CANNOT_TELL
    ext = os.path.splitext(path)[1]
    _save(os.path.join(outdir, "before" + ext), before)
    _save(os.path.join(outdir, "added" + ext), added)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
