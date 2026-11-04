"""Deliver a PreToolUse warning the model can read.

Claude Code drops a hook's stderr when it exits 0, so a warning written there is invisible.
The channel that reaches the model is JSON on stdout with `hookEventName` set, then exit 0.
Callers exit 0 themselves after calling this.
"""
import json
import sys


def emit_warn(text, out=None):
    out = out if out is not None else sys.stdout
    json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                      "additionalContext": text}}, out)
    out.write("\n")
    out.flush()


def crash_warn(hook_name, exc):
    """The fail-open message for a crashed hook, on the channel the model reads."""
    try:
        emit_warn("%s crashed and ALLOWED the command (fail-open): %r" % (hook_name, exc))
    except Exception:  # never let the crash report itself crash the hook
        sys.stderr.write("%s crashed and ALLOWED the command (fail-open): %r\n" % (hook_name, exc))
