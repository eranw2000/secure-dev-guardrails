#!/usr/bin/env python3
"""Hard-block hook, the Bash half of secret-scan.sh. Enforces SEC-SECRET-01.

secret-scan.sh keeps the registration (settings.json names only the .sh) and keeps
its own Write/Edit/MultiEdit branch. For a Bash call it execs this file.

WHY THIS EXISTS (2026-09-11, plan items A2 and A3)

A2, DISCLOSURE. The shell version printed `tail -c 2000` of gitleaks' own output
into the denial message, and gitleaks' human-readable output QUOTES the secret it
found. So a hook whose entire job is to stop a credential leaking wrote the
credential into the transcript. This version asks for a JSON report on disk inside
a 0700 directory, prints only the rule id, the repository-relative path, the line
number and a count, and deletes the report. No raw scanner output ever reaches
stdout or stderr, and no Secret / Match / Line / Author / Commit-message field is
ever read out of the report.

A3, RECOGNITION AND SUBJECT. The shell version matched `git[[:space:]]+(commit|push)`
against the raw command, so:
  - `git -C <repo> commit` was not recognised at all,
  - the envelope's `cwd` was never read, so the scan ran in the hook process's own
    directory rather than the shell's,
  - both commit AND push ran `gitleaks protect --staged`, so a push whose index was
    empty scanned nothing and reported clean while the outgoing commits carried the
    secret.
This version decides from the shared quote-aware parse in _bash_command_parse.py,
resolves the repository for the plain, `git -C <repo>`, `cd <dir> && git` and
`bash -c "git ..."` forms, and scans three different subjects:
  - commit:      the INDEX of that repository (`gitleaks git --staged <repo>`),
  - commit -a:   the index AND the worktree changes to tracked files, because -a
                 commits both (`gitleaks git --pre-commit <repo>`),
  - push:        the commits that would LEAVE (`gitleaks git --log-opts <range>`).

REVIEW ROUND A, 2026-09-11. Eight holes found by two reviewers and closed here
(S1 to S8). Each one had the same shape: a command that really does send or commit
something reached exit 0 with nothing scanned, and silence is indistinguishable
from a clean result.

  S1 A printed FIELD can itself be a credential. gitleaks redacts the value it
     matched, but the JSON `File` field is an attacker-choosable repository path,
     and the rule id, branch, remote and repository path were all printed
     verbatim. Every field this hook prints now goes through _safe(), which
     strips control characters and replaces a value matching secret-scan.sh's own
     patterns with <redacted>. The patterns are READ from secret-scan.sh so there
     is one owner; the mirrored fallback below is only for an unreadable .sh, and
     a test asserts the two agree.
  S2 The bulk push forms are modelled rather than dropped: `:` is git's MATCHING
     refspec (every local branch with a same-named ref on the target, measured
     with `git push --dry-run --porcelain`), a wildcard source expands against
     the local refs, `--branches` is an alias of `--all`, `--tags` alone sends
     ONLY the tags, `--follow-tags` sends the default refspec plus the tags, and
     `--mirror` sends every ref under refs/. When the outgoing subject cannot be
     PROVEN the hook exits 2 with "cannot prove the outgoing subject", never 0.
  S3 The old fallback range excluded commits on ANY remote, so a secret already
     on origin was not scanned when pushed to a NEW remote. Exclusions are now
     the TARGET remote's refs only (`--not --remotes=<remote>`). When the target
     has no known refs here (a new remote, a URL, `--repo=URL`) the WHOLE history
     of the pushed tips is scanned and the message says so. A deliberate decision,
     2026-09-11, with the cost accepted: it can be slow, and it can block a
     repository whose old history carries a secret. That is intended, because the
     alternative is copying that credential to a new recipient in silence.
  S5 A bash-valid command the tokenizer cannot read (`git commit -m $'don\\'t'`)
     used to be skipped silently. It now fails closed the same way the push guard
     does on the same input, and only when the raw text really looks like a git
     commit or push, so an unparseable command that has nothing to do with git is
     still allowed.
  S6 `git commit -a` / `-am` / `--all` commits the worktree changes to tracked
     files, which `--staged` cannot see. Those get a second subject scanned with
     `--pre-commit`.
  S7 `--git-dir=` / `--work-tree=` / a `GIT_DIR=` prefix names a repository this
     parse does not resolve. Scanning the shell's directory instead would block
     on findings belonging to somebody else's work, so the shape is reported as
     unproven (exit 2) rather than passed in silence.
  S8 `git push --dry-run` (or `-n`) sends nothing, so the scan is skipped with one
     line on stderr rather than blocking work that cannot leak.

MEASURED LIMIT OF THE PUSH SCAN, and it is deliberate. For a target whose refs are
KNOWN here, the range excludes only that remote's refs, so a repository whose
EXISTING history already carries a secret is not blocked from pushing to the remote
that already has it: that secret is already there and blocking every future push
would stop work that is recoverable by nothing this hook can do. Cleaning existing
history is the secrets-remediation skill's job. Measured against what is live
before shipping: a whole-history scan on every push would block pushes in
repositories already in production. A push to a target that does NOT already have
the history is the opposite case and is scanned in full (S3).

THE GITLEAKS CONTRACT, read from the installed CLI's own help (8.30.1) rather than
from memory, and probed live:
  gitleaks git [flags] [repo]    --staged            scan staged commits
                                 --pre-commit        scan using git diff
                                 --log-opts string   git log options
                                 --exit-code int     exit code when leaks found
                                 -f/--report-format  json
                                 -r/--report-path    report file
  `protect` and `detect` are no longer in `gitleaks --help`'s command list.
  `--pre-commit` scans `git diff`, which is the WORKTREE against the index, so it
  is the complement of `--staged` rather than a superset: measured 2026-09-11, a
  token in a modified tracked file with an empty index is found by --pre-commit
  (exit 7, one github-pat finding) and reported CLEAN by --staged (exit 0). That
  is why `commit -a` needs both.
  On an ERROR (a path that is not a repository) gitleaks exits 1, which is the
  SAME as its default findings code, and writes NO report. That is why this hook
  passes `--exit-code 7`: 0 is clean, 7 is findings, anything else is an error.
  A bogus --log-opts range exits 0 with an empty report, which is a silent
  scanned-nothing, so every tip is resolved with `git rev-parse` here and a range
  is never handed to gitleaks unresolved.

Exit-code contract, the one every other hook here uses: exit 2 with a message on
stderr BLOCKS, exit 0 allows. The stdout {"decision":"block"} form is NOT honored
for PreToolUse and fails OPEN.

A scanner error NEVER reads as clean: it exits 2 with a message beginning
"scanner error:", so silence cannot be mistaken for a pass.

Suppress a confirmed false positive via the baseline register (owner, expiry and
the repo's directory name), not inline. Reading that register is NOT implemented
here; another plan item owns it.
"""
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
REAL_HOOK_DIR = os.path.expanduser("~/.claude/hooks")
for _d in (HOOK_DIR, REAL_HOOK_DIR):
    if _d not in sys.path:
        sys.path.insert(0, _d)

BASELINE = "standards/baseline.yml"

# Below whatever timeout the harness applies to a hook, so an overrun is reported
# here as an error rather than the process being killed without a word.
SCAN_TIMEOUT = int(os.environ.get("CLAUDE_GITLEAKS_TIMEOUT", "50"))

# Findings get their own exit code so an error cannot masquerade as a finding.
FINDINGS_EXIT = 7

# How many finding lines to print before summarising the rest. A finding line is
# three short fields, so this is a readability cap, not a disclosure one.
MAX_FINDING_LINES = 25

# `git push` flags that consume the FOLLOWING token as their value, so a
# positional-argument walk must skip both.
PUSH_VALUE_FLAGS = {
    "--repo", "-o", "--push-option", "--receive-pack", "--exec", "--upload-pack",
}

# Every local branch leaves. `--branches` is an alias of `--all` (git 2.49), and
# `--mirror` sends every ref under refs/ including refs/remotes and refs/tags.
PUSH_ALL_BRANCHES_FLAGS = {"--all", "--branches", "--mirror"}
PUSH_TAG_FLAGS = {"--tags", "--follow-tags", "--mirror"}
PUSH_DRY_RUN_FLAGS = {"--dry-run", "-n"}
PUSH_DELETE_FLAGS = {"--delete", "-d"}

# Env-var prefixes that move the repository somewhere this parse does not follow.
GIT_ENV_TARGETS = ("GIT_DIR=", "GIT_WORK_TREE=", "GIT_COMMON_DIR=")

# The raw-text fallback for a command the tokenizer cannot read. Same shape as the
# push guard's, so the two guards fail closed on the same inputs.
LOOKS_LIKE_GIT_RE = re.compile(r"\bgit\b[^\n]{0,80}\b(commit|push)\b")


# -------------------------------------------------------- field redaction (S1)

# Mirrored from secret-scan.sh's scan_text_for_secrets(). The LIVE copy is read
# out of that file at run time by _sh_patterns(), so there is one owner; these are
# the fallback for an unreadable .sh, and tests/test_secret_scan.py asserts the
# two agree so the fallback cannot go stale in silence.
FALLBACK_TOKEN_PATTERN = (
    r"\-\-\-\-\-BEGIN ([A-Z]+ )?PRIVATE KEY\-\-\-\-\-|AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|gh[opsu]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|xapp-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|"
    r"sk_live_[0-9A-Za-z]{24,}|rk_live_[0-9A-Za-z]{24,}|sk-ant-[0-9A-Za-z_-]{20,}|"
    r"sk-[A-Za-z0-9]{32,}|"
    r"eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}"
)
FALLBACK_ENV_PATTERN = (
    r"os\.environ|os\.getenv|getenv\(|process\.env|Deno\.env|System\.getenv|"
    r"GetEnvironmentVariable|dotenv|load_dotenv|config\(|settings\.|get_secret|"
    r"SecretClient|KeyVault|secretsmanager"
)
# The quote class is written as an ESCAPE rather than pasted, because a raw string
# cannot carry both quote characters and a `\"` inside one would become part of the
# character class. secret-scan.sh writes the same class as `["'"'"' ]`, which is the
# shell idiom for an apostrophe inside a single-quoted string.
_QUOTE_CLASS = "[\"' ]"
FALLBACK_ASSIGN_PATTERN = (
    r"(api[_-]?key|secret([_-]?key)?|client[_-]?secret|access[_-]?key|"
    r"auth[_-]?token|private[_-]?key|refresh[_-]?token|bearer[_-]?token|"
    r"signing[_-]?key|encryption[_-]?key|session[_-]?secret|connection[_-]?string|"
    r"password|passwd|pwd)" + _QUOTE_CLASS + r"*[:=]" + _QUOTE_CLASS
    + r"*[a-z0-9/+_=.-]{12,}"
)

REDACTED = "<redacted>"

_PATTERN_CACHE = {}


def _shell_single_quoted(text, start):
    """The shell single-quoted string beginning at text[start], or None.

    Handles the `'"'"'` idiom, which is how a single quote is written inside a
    single-quoted shell string. secret-scan.sh uses it twice in the assignment
    pattern, so a naive read to the next apostrophe truncates the pattern.
    """
    if start >= len(text) or text[start] != "'":
        return None, start
    i = start + 1
    out = []
    while i < len(text):
        if text[i] == "'":
            if text[i:i + 5] == "'\"'\"'":
                out.append("'")
                i += 5
                continue
            return "".join(out), i + 1
        out.append(text[i])
        i += 1
    return None, len(text)


def _sh_pattern_texts(path):
    """(token, env, assign) pattern texts read out of secret-scan.sh, or None.

    The file's scan_text_for_secrets() runs exactly three greps, in this order:
    `grep -Eq` over the raw text (token signatures), `grep -Ev` (the lines that
    are READING a value from the environment, which are excluded), and a second
    `grep -Eq` over the lowercased remainder (the assignment shape).
    """
    try:
        with open(path, "r") as fh:
            src = fh.read()
    except Exception:
        return None
    found = []
    i = 0
    while True:
        m = re.compile(r"grep -E([qv])\s+").search(src, i)
        if m is None:
            break
        pattern, end = _shell_single_quoted(src, m.end())
        i = m.end() if pattern is None else end
        if pattern is not None:
            found.append((m.group(1), pattern))
    tokens = [p for kind, p in found if kind == "q"]
    excludes = [p for kind, p in found if kind == "v"]
    if len(tokens) < 2 or len(excludes) < 1:
        return None
    return tokens[0], excludes[0], tokens[1]


def _sh_patterns():
    """The compiled patterns, from secret-scan.sh when it can be read."""
    if "compiled" in _PATTERN_CACHE:
        return _PATTERN_CACHE["compiled"]
    texts = None
    for d in (HOOK_DIR, REAL_HOOK_DIR):
        texts = _sh_pattern_texts(os.path.join(d, "secret-scan.sh"))
        if texts:
            break
    if not texts:
        texts = (FALLBACK_TOKEN_PATTERN, FALLBACK_ENV_PATTERN,
                 FALLBACK_ASSIGN_PATTERN)
    compiled = []
    for text, fallback in zip(texts, (FALLBACK_TOKEN_PATTERN,
                                      FALLBACK_ENV_PATTERN,
                                      FALLBACK_ASSIGN_PATTERN)):
        try:
            compiled.append(re.compile(text))
        except re.error:
            # An ERE the Python engine will not take. Use the mirrored copy
            # rather than losing the test entirely.
            compiled.append(re.compile(fallback))
    _PATTERN_CACHE["compiled"] = tuple(compiled)
    return _PATTERN_CACHE["compiled"]


def _looks_like_secret(text):
    """True when `text` matches secret-scan.sh's own secret-value patterns."""
    if not text:
        return False
    token_re, env_re, assign_re = _sh_patterns()
    if token_re.search(text):
        return True
    # Mirrors the .sh's `grep -Ev` line: a fragment that is READING a value from
    # the environment or a secret store is not itself a value.
    if env_re.search(text):
        return False
    return bool(assign_re.search(text.lower()))


def _strip_controls(text):
    """Drop control characters, so a field cannot rewrite the denial message.

    Covers C0 (including the terminal escape that starts an ANSI sequence), DEL
    and C1. A newline or a tab inside a path would break the message's shape,
    which is why they go too rather than being turned into spaces.
    """
    return "".join(
        ch for ch in text
        if ch >= " " and ch != "\x7f" and not ("\x80" <= ch <= "\x9f")
    )


def _safe(value):
    """A field that is safe to print: control-free, and <redacted> if it is a value.

    Every field this hook prints goes through here: the rule id and path out of
    gitleaks' report, the branch, the remote, and the repository path. A
    repository-relative path is chosen by whoever added the file, so it is as
    attacker-controlled as the file's contents.
    """
    text = _strip_controls("" if value is None else str(value))
    if _looks_like_secret(text):
        return REDACTED
    return text


# ---------------------------------------------------------------- shared parsing

class Unparseable(Exception):
    """The command text could not be tokenized, so nothing about it is known."""


def _parser():
    """The shared quote-aware parser, or None when it cannot be imported."""
    try:
        import _bash_command_parse as p
        return p
    except Exception:
        return None


def _commit_repos(command, cwd):
    """Extra commit-repository resolution. None in this pack: the local parse
    below resolves `git -C`, a `cd` earlier in the command and the heredoc
    commit shape on its own, and its results are the ones scanned."""
    return []

def _env_target(tokens):
    """True when a leading VAR=value assignment moves the repository (S7).

    Only the assignments in FRONT of the command word count. strip_prefixes()
    drops them before git_call() ever sees them, so `GIT_DIR=x git push` parses
    as a plain push in the shell's own directory, which is the wrong repository.
    """
    p = _parser()
    for tok in tokens:
        if p is not None and p.ENV_ASSIGN.match(tok):
            if tok.startswith(GIT_ENV_TARGETS):
                return True
            continue
        break
    return False


def _strip_redirections(args):
    """A git call's arguments without the shell's redirections and their targets.

    The shared tokenizer emits `>`, `>>`, `>&` and friends as tokens of their own but
    keeps them inside the segment, so `git push -u origin b > log 2>&1` reached the
    push reader with `> log 2 >& 1` as five more refspecs, none of which resolves, and
    the push was refused as unprovable (2026-09-11, MeitarSeating PR #23). The shell
    never passes a redirection to git, so neither does this. A file-descriptor number
    written against its operator (`2>&1`, tokenized `2`, `>&`, `1`) goes with it.
    """
    def is_operator(tok):
        return bool(tok) and set(tok) <= set("<>&|")

    out = []
    i = 0
    while i < len(args):
        tok = args[i]
        if is_operator(tok):
            i += 2          # the operator and its target
            continue
        if tok.isdigit() and i + 1 < len(args) and is_operator(args[i + 1]):
            i += 1          # the descriptor; the operator is dropped next round
            continue
        out.append(tok)
        i += 1
    return out


def _git_calls(command, cwd, wanted):
    """[{subcommand, repo, args, shape}] for every git call this command runs.

    `repo` is None when the repository could not be resolved, and `shape` then
    names what the command did that this parse does not follow (S7).

    Raises Unparseable when the text cannot be tokenized (S5). The old code
    skipped such a segment, so a bash-valid command with a $'...' string was
    allowed with nothing scanned.
    """
    p = _parser()
    if p is None:
        return []
    out = []

    def walk(text, here, depth=0):
        if depth > 3:
            return here
        # ONE tokenize of the whole text, not one per line. The tokenizer already
        # emits a newline as its own operator token and split_segments already
        # treats it as a command boundary, so the segments come back in order
        # across lines and the shell's directory threads through them just the
        # same. Splitting on lines FIRST was measurably wrong in both directions:
        # strip_heredocs removes a heredoc BODY and leaves `-m "$(cat <<'EOF'`
        # on one line and `)"` on another, so the commonest real commit shape in
        # this house (`git commit -m "$(cat <<'EOF' ... EOF)"`) read as an
        # unbalanced quote. Measured over 248 recorded commit and push commands:
        # per-line refused 24 of them (9.7%), whole-text refuses 1 (0.4%), and
        # that one is genuinely unreadable (nested quotes inside `$( )`).
        try:
            segments = p.command_segments(text)
        except p.UnparseableCommand as exc:
            raise Unparseable(str(exc))
        for tokens in segments:
            nested = p.nested_shell_command(tokens)
            if nested:
                walk(nested, here, depth + 1)
                continue
            target = p.cd_target(tokens)
            if target:
                target = os.path.expanduser(target)
                here = target if os.path.isabs(target) else os.path.join(here, target)
                continue
            call = p.git_call(tokens)
            if not call or call["subcommand"] not in wanted:
                continue
            env_moved = _env_target(tokens)
            if call["dash_c"] and not env_moved:
                repo, shape = call["dash_c"], None
            elif call["explicit_target"] or env_moved:
                repo = None
                shape = (
                    "a git %s whose repository is named by --git-dir, "
                    "--work-tree or a GIT_DIR= prefix, which this scan does "
                    "not resolve" % call["subcommand"]
                )
            else:
                repo, shape = here, None
            out.append({
                "subcommand": call["subcommand"],
                "repo": repo,
                "args": _strip_redirections(call["args"]),
                "shape": shape,
            })
        return here

    walk(command, cwd)
    return out


def _commits_everything(args):
    """True for `git commit -a` / `-am` / `--all` (S6).

    A short-flag cluster carries the `a`, so `-am` and `-av` count too. Only an
    exact `--all` counts on the long side: `--amend` is a different flag.
    """
    for tok in args:
        if tok == "--all":
            return True
        if tok.startswith("--"):
            continue
        if tok.startswith("-") and "a" in tok[1:]:
            return True
    return False


# ------------------------------------------------------------------- git helpers

def _git(repo, *args):
    """(returncode, stdout) for one read-only git call in `repo`."""
    try:
        done = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return 1, ""
    return done.returncode, done.stdout.strip()


def _lines(repo, *args):
    """(ok, [lines]) so an enumeration FAILURE is distinguishable from empty.

    Load-bearing for S2: "no refs" means nothing leaves and the push is clean,
    while "could not enumerate the refs" means the subject is unknown and the
    hook must not exit 0.
    """
    rc, out = _git(repo, *args)
    if rc != 0:
        return False, []
    return True, [line.strip() for line in out.split("\n") if line.strip()]


def _is_repo(repo):
    rc, _ = _git(repo, "rev-parse", "--git-dir")
    return rc == 0


def _verify(repo, ref):
    rc, out = _git(repo, "rev-parse", "--verify", "--quiet", ref)
    return out if rc == 0 and out else None


def _current_branch(repo):
    rc, out = _git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    return out if rc == 0 and out else None


def _local_branches(repo):
    return _lines(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads")


def _tag_refs(repo):
    return _lines(repo, "for-each-ref", "--format=%(refname)", "refs/tags")


def _all_refs(repo):
    return _lines(repo, "for-each-ref", "--format=%(refname)", "refs/")


def _configured_remotes(repo):
    return _lines(repo, "remote")


def _target_refs(repo, remote):
    """(ok, refs) of refs/remotes/<remote>/*, for a CONFIGURED remote name only.

    A URL target, or a name that is not a configured remote, has no refs here by
    definition, and asking for-each-ref about it with a URL as the pattern is not
    a question git can answer.
    """
    ok, remotes = _configured_remotes(repo)
    if not ok or remote not in remotes:
        return True, []
    return _lines(repo, "for-each-ref", "--format=%(refname)",
                  "refs/remotes/%s/" % remote)


def _glob_refs(repo, pattern):
    """(ok, refs) matching a wildcard refspec source.

    Matched against the full ref name AND the short name, because both
    `refs/heads/*:refs/heads/*` and `feature/*:feature/*` are written in
    practice. fnmatch's `*` crosses a `/` where git's does not, so this is a
    superset: it can only widen the scan, never narrow it.
    """
    ok, refs = _all_refs(repo)
    if not ok:
        return False, []
    out = []
    for full in refs:
        short = full
        for prefix in ("refs/heads/", "refs/tags/", "refs/remotes/"):
            if full.startswith(prefix):
                short = full[len(prefix):]
                break
        if fnmatch.fnmatchcase(full, pattern) or fnmatch.fnmatchcase(short, pattern):
            out.append(full)
    return True, out


def _push_target(repo, args):
    """The remote name (or URL) this push would send to.

    `--repo=<url>` / `--repo <url>` is git's way of naming the target when no
    repository argument is given, and the old code skipped it as a flag, so the
    base was resolved against `origin` instead (S3).
    """
    p = _parser()
    repo_flag = None
    for i, tok in enumerate(args):
        if tok == "--repo" and i + 1 < len(args):
            repo_flag = args[i + 1]
        elif tok.startswith("--repo="):
            repo_flag = tok.split("=", 1)[1]
    positional = p.positional_args(args, value_flags=PUSH_VALUE_FLAGS)
    if positional:
        return positional[0], positional[1:]
    if repo_flag:
        return repo_flag, []
    # The branch's configured remote, else the conventional default.
    cur = _current_branch(repo)
    if cur:
        rc, out = _git(repo, "config", "--get", "branch.%s.remote" % cur)
        if rc == 0 and out:
            return out, []
    return "origin", []


def _push_plan(repo, args):
    """What a `git push` would send, as a dict.

    Keys: dry_run, deletion, remote, tips, target_known, shape. `shape` names why
    the subject could not be proven, and is the only key that matters when it is
    set: the caller must then exit 2 rather than 0.
    """
    flags = set(a for a in args if a.startswith("-"))
    plan = {"dry_run": False, "deletion": False, "remote": None, "tips": [],
            "target_known": False, "shape": None}

    if flags & PUSH_DRY_RUN_FLAGS:
        plan["dry_run"] = True
        return plan
    if flags & PUSH_DELETE_FLAGS:
        plan["deletion"] = True
        return plan

    remote, refspecs = _push_target(repo, args)
    plan["remote"] = remote
    ok, target_refs = _target_refs(repo, remote)
    if not ok:
        plan["shape"] = "a push to %s, whose refs could not be listed" % _safe(remote)
        return plan
    plan["target_known"] = bool(target_refs)

    tips = []
    all_branches = bool(flags & PUSH_ALL_BRANCHES_FLAGS)
    tags = bool(flags & PUSH_TAG_FLAGS)
    # `git push --tags <remote>` with no refspec sends ONLY the tags. Measured
    # 2026-09-11 with `git push --dry-run --porcelain --tags origin`: one line,
    # `refs/tags/v1:refs/tags/v1`. `--follow-tags` is different: the same probe
    # shows it still taking the default refspec (it failed for want of an
    # upstream), so the current branch belongs in the subject there.
    tags_only = "--tags" in flags and not all_branches and "--follow-tags" not in flags

    if "--mirror" in flags:
        ok, refs = _all_refs(repo)
        if not ok:
            plan["shape"] = "a --mirror push whose refs could not be listed"
            return plan
        tips.extend(refs)
    else:
        if all_branches:
            ok, branches = _local_branches(repo)
            if not ok:
                plan["shape"] = "a push of every branch whose branches could not be listed"
                return plan
            tips.extend(branches)
        if tags:
            ok, tag_refs = _tag_refs(repo)
            if not ok:
                plan["shape"] = "a tag push whose tags could not be listed"
                return plan
            tips.extend(tag_refs)

    for spec in refspecs:
        bare = spec[1:] if spec.startswith("+") else spec
        if bare == ":":
            # Git's MATCHING refspec: every local branch that already has a
            # same-named ref on the TARGET. Measured with --dry-run --porcelain:
            # in a repo with main/other/topic and only origin/main present,
            # `git push origin :` sends main and nothing else.
            if not plan["target_known"]:
                plan["shape"] = (
                    "a matching refspec (:) to %s, which has no known refs here, "
                    "so which branches it would match cannot be read"
                    % _safe(remote)
                )
                return plan
            ok, branches = _local_branches(repo)
            if not ok:
                plan["shape"] = "a matching refspec (:) whose branches could not be listed"
                return plan
            prefix = "refs/remotes/%s/" % remote
            names = set(
                r[len(prefix):] for r in target_refs if r.startswith(prefix)
            )
            # The whole remaining name, not its last component: a remote's
            # `feature/x` must not count as a counterpart for a local `x`.
            tips.extend(b for b in branches if b in names)
            continue
        src = bare.split(":", 1)[0]
        if not src:
            # `:dst` deletes the remote ref, so nothing leaves.
            continue
        if any(ch in src for ch in "*?["):
            ok, matched = _glob_refs(repo, src)
            if not ok:
                plan["shape"] = "a wildcard refspec whose refs could not be listed"
                return plan
            tips.extend(matched)
            continue
        tips.append(src)

    if not refspecs and not all_branches and not tags_only:
        cur = _current_branch(repo)
        if cur:
            tips.append(cur)
        # A detached HEAD has no branch to push, and git refuses the push itself
        # ("You are not currently on a branch"), so nothing leaves.

    seen = set()
    ordered = []
    for tip in tips:
        if tip not in seen:
            seen.add(tip)
            ordered.append(tip)
    plan["tips"] = ordered
    return plan


def _unproven(shape):
    """One wording for every shape whose outgoing subject could not be proven.

    Uniform on purpose: a caller, a test and a reader all look for the same
    phrase, and the shape that follows it is what says which command did it.
    """
    return "cannot prove the outgoing subject for %s." % shape


def _outgoing_log_opts(shas, remote, target_known):
    """The `git log` options naming every commit this push would send.

    ALL the pushed tips go into ONE range, because `git log` takes several
    positive revisions and gitleaks is a process start plus a walk: one call for
    a --mirror push of 40 refs rather than 40 calls, which is the difference
    between a hook and a hang.

    Two cases, and the second is S3:
      1. the target's refs are known here -> <tips...> --not --remotes=<remote>,
         which excludes only what THAT remote already has. Measured: in a repo
         with two outgoing commits, `rev-list --count HEAD --not --remotes=origin`
         is 1 while `--remotes=nosuch` is 2, so the pattern really does scope the
         exclusion to one remote.
      2. the target has no refs here (a new remote, a URL, --repo=URL) -> the
         WHOLE history of the tips.
    Every tip is resolved to a sha by the caller, because gitleaks answers a
    range it cannot resolve with exit 0 and an empty report, a silent
    scanned-nothing indistinguishable from clean.
    """
    joined = " ".join(shas)
    if target_known:
        return "%s --not --remotes=%s" % (joined, remote)
    return joined


def _tips_label(tips):
    """A short, safe name for the refs a push would send."""
    shown = [_safe(t) for t in tips[:3]]
    if len(tips) > 3:
        shown.append("and %d more" % (len(tips) - 3))
    return ", ".join(shown)


# ----------------------------------------------------------------------- scanner

class ScannerError(Exception):
    """The scan did not produce a verdict. Never treated as clean."""


def _run_gitleaks(repo, mode_args, label):
    """Run gitleaks in `repo` and return its findings as a list of dicts.

    Raises ScannerError when there is no verdict: binary missing, timeout, an
    exit code that is neither clean nor findings, a findings exit with no report,
    or a report that will not parse.
    """
    binary = shutil.which("gitleaks")
    if not binary:
        raise ScannerError(
            "gitleaks is not installed, so %s was not scanned. Nothing else "
            "checks it: the write branch of this hook sees the content of an Edit "
            "or a Write, never what is already staged or committed. Install it "
            "with: brew install gitleaks" % label
        )

    workdir = tempfile.mkdtemp(prefix="gitleaks-hook-")
    os.chmod(workdir, 0o700)
    report = os.path.join(workdir, "report.json")
    try:
        cmd = [
            binary, "git",
            "--exit-code", str(FINDINGS_EXIT),
            "--no-banner",
            "--no-color",
            # Defence in depth. The fields carrying the secret are never read out
            # of the report below, and --redact means they are not even written.
            "--redact",
            "--report-format", "json",
            "--report-path", report,
        ] + list(mode_args) + [repo]
        try:
            done = subprocess.run(
                cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT, cwd=repo,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(
                "the scan of %s passed %d seconds and was stopped, so nothing was "
                "checked. Silence here would be indistinguishable from a clean scan."
                % (label, SCAN_TIMEOUT)
            )
        except OSError as exc:
            raise ScannerError(
                "gitleaks could not be started for %s (%s)."
                % (label, exc.__class__.__name__)
            )

        if done.returncode == 0:
            return []
        if done.returncode != FINDINGS_EXIT:
            # NOT a findings code. gitleaks uses 1 for its own failures, which is
            # why the findings code is moved to 7. The scanner's stderr is NOT
            # echoed: it can quote the file and the matched text.
            raise ScannerError(
                "gitleaks exited %d scanning %s, which is neither clean nor a "
                "finding, so the result is unknown. Its output is deliberately "
                "not reproduced here. Reproduce it yourself with:\n    gitleaks "
                "git %s %s" % (done.returncode, label,
                               _safe(" ".join(mode_args)), _safe(repo))
            )

        if not os.path.isfile(report):
            raise ScannerError(
                "gitleaks reported a finding in %s but wrote no report, so there "
                "is nothing to name." % label
            )
        try:
            os.chmod(report, 0o600)
        except OSError:
            pass
        try:
            with open(report, "r") as fh:
                data = json.load(fh)
        except Exception:
            raise ScannerError(
                "gitleaks reported a finding in %s and its report could not be "
                "read, so there is nothing to name." % label
            )
        if not isinstance(data, list):
            raise ScannerError(
                "gitleaks reported a finding in %s and its report was not the "
                "expected list of findings." % label
            )
        return data
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _describe(findings):
    """Rule id, repository-relative path and line number only.

    Deliberately reads FOUR keys and no others. Secret, Match, Line, Commit,
    Author, Email, Message and Description are never touched, so no widening of
    this function can leak a value by accident.

    S1: RuleID and File are NOT trustworthy just because they are metadata. The
    path is chosen by whoever added the file, so a file named after a live token
    puts the token in this hook's own denial message. Both go through _safe().
    """
    rows = []
    seen = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        rule = _safe(f.get("RuleID") or "unknown-rule")
        path = _safe(f.get("File") or "unknown-path")
        line = f.get("StartLine")
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = 0
        key = (rule, path, line)
        if key in seen:
            continue
        seen.add(key)
        rows.append(key)
    rows.sort()
    return rows


# -------------------------------------------------------------------- the verdict

def _subjects(command, cwd):
    """(subjects, problems, notes, skipped).

    subjects  [(kind, repo, mode_args, label), ...], deduplicated and stable.
    problems  shapes whose outgoing subject could NOT be proven. Each one is a
              scanner error, never a pass (S2, S7).
    notes     lines the denial message must carry, currently the S3 whole-history
              explanation.
    skipped   lines explaining a scan deliberately not run (S8, a dry run).
    """
    subjects = []
    problems = []
    notes = []
    skipped = []
    seen = set()

    def add(kind, repo, mode_args, label):
        path = os.path.abspath(os.path.expanduser(repo))
        key = (kind, path, tuple(mode_args))
        if key in seen:
            return
        if not os.path.isdir(path) or not _is_repo(path):
            # The git command itself would fail here, so there is nothing to guard.
            return
        seen.add(key)
        subjects.append((kind, path, list(mode_args), label))

    calls = _git_calls(command, cwd, {"commit", "push"})

    for call in calls:
        if call["shape"]:
            problems.append(_unproven(call["shape"]))

    # ---- commits. An optional external resolver is asked first (none ships with
    # this pack). This parse is then UNIONED in rather than used only for the -a
    # flag, because a resolver that
    # tokenizes one line at a time and so cannot read the commonest real commit
    # shape here: `git commit -m "$(cat <<'EOF' ... EOF)"`, where the heredoc
    # body is removed and the opening quote and its closing `)"` end up on
    # different lines. Measured 2026-09-11: that shape resolved to NO repository,
    # so the commit was allowed with nothing scanned. `add()` deduplicates, so a
    # shape both of them resolve is still scanned once.
    commit_repos = list(_commit_repos(command, cwd))
    for call in calls:
        if call["subcommand"] == "commit" and call["repo"]:
            commit_repos.append(call["repo"])
    for repo in commit_repos:
        add("commit", repo, ["--staged"], "the staged changes in %s" % _safe(repo))
    for call in calls:
        if call["subcommand"] != "commit" or not call["repo"]:
            continue
        if not _commits_everything(call["args"]):
            continue
        add(
            "commit", call["repo"], ["--pre-commit"],
            "the worktree changes -a would commit in %s" % _safe(call["repo"]),
        )

    # ---- pushes.
    for call in calls:
        if call["subcommand"] != "push" or not call["repo"]:
            continue
        path = os.path.abspath(os.path.expanduser(call["repo"]))
        if not os.path.isdir(path) or not _is_repo(path):
            continue
        plan = _push_plan(path, call["args"])
        if plan["shape"]:
            problems.append(_unproven(plan["shape"]))
            continue
        if plan["dry_run"]:
            skipped.append(
                "the secret scan skipped a `git push --dry-run`: a dry run sends "
                "nothing, so there is nothing that could leak."
            )
            continue
        if plan["deletion"]:
            continue
        remote = plan["remote"]
        resolved = []
        shas = []
        for tip in plan["tips"]:
            sha = _verify(path, tip)
            if sha is None:
                problems.append(_unproven(
                    "a push of %s to %s, which does not resolve to a commit here"
                    % (_safe(tip), _safe(remote))
                ))
                continue
            resolved.append(tip)
            if sha not in shas:
                shas.append(sha)
        if plan["tips"] and not resolved:
            # Every tip failed to resolve. Never report that as clean.
            problems.append(_unproven(
                "a push to %s, whose tips do not resolve to commits here"
                % _safe(remote)
            ))
        if not shas:
            continue
        log_opts = _outgoing_log_opts(shas, remote, plan["target_known"])
        if plan["target_known"]:
            label = (
                "the commits %s would push to %s in %s"
                % (_tips_label(resolved), _safe(remote), _safe(path))
            )
        else:
            label = (
                "the WHOLE history of %s, because %s has no known refs here, in %s"
                % (_tips_label(resolved), _safe(remote), _safe(path))
            )
            note = (
                "The target %s has no known refs in this repository (a new "
                "remote, or a URL), so the WHOLE history of the pushed tips was "
                "scanned rather than only the outgoing commits. A finding above "
                "may therefore be an old one, which this push would be copying "
                "to a new recipient." % _safe(remote)
            )
            if note not in notes:
                notes.append(note)
        add("push", path, ["--log-opts", log_opts], label)

    return subjects, problems, notes, skipped


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command.strip():
        return 0

    # The hook process runs in the session directory. The Bash tool's own shell can
    # be somewhere else entirely, and the payload carries where. The shell version
    # never read this, which is how it came to scan the wrong repository.
    cwd = payload.get("cwd") or os.getcwd()

    try:
        subjects, problems, notes, skipped = _subjects(command, cwd)
    except Unparseable:
        # S5. The tokenizer could not read the command, so nothing is known about
        # it. Fail closed exactly where the push guard does: only when the raw
        # text really looks like a git commit or push, so an unparseable command
        # with nothing to do with git is still allowed.
        if not LOOKS_LIKE_GIT_RE.search(command):
            return 0
        sys.stderr.write(
            "scanner error: command could not be parsed, so the staged change and "
            "the outgoing commits were NOT scanned. This is not a clean result.\n\n"
            "  The command looks like a git commit or push and could not be "
            "tokenized, usually an unbalanced quote or a $'...' string. Rewrite it "
            "so it parses (single quotes, or a here-document) and re-run.\n"
        )
        return 2
    except Exception:
        # Any other failure to work out the subject is not a clean result either,
        # but the blast radius is deliberately bounded to commands that look like
        # a git commit or push. This hook runs on EVERY Bash call, so a latent bug
        # in the subject resolution that blocked unconditionally would block every
        # command on the machine until somebody noticed.
        if not LOOKS_LIKE_GIT_RE.search(command):
            return 0
        sys.stderr.write(
            "scanner error: the subject of this command could not be worked out, "
            "so nothing was scanned. This is not a clean result.\n"
        )
        return 2

    if not subjects and not problems:
        if skipped:
            sys.stderr.write(skipped[0] + "\n")
        return 0

    blocks = []
    errors = list(problems)
    total = 0
    for kind, repo, mode_args, label in subjects:
        try:
            findings = _run_gitleaks(repo, mode_args, label)
        except ScannerError as exc:
            errors.append(str(exc))
            continue
        rows = _describe(findings)
        if not rows:
            continue
        total += len(rows)
        lines = ["In %s:" % label]
        for rule, path, line in rows[:MAX_FINDING_LINES]:
            lines.append("  %s  %s:%d" % (rule, path, line))
        extra = len(rows) - MAX_FINDING_LINES
        if extra > 0:
            lines.append("  ... and %d more in the same subject." % extra)
        blocks.append("\n".join(lines))

    if not blocks and not errors:
        if skipped:
            sys.stderr.write(skipped[0] + "\n")
        return 0

    parts = []
    if blocks:
        parts.append(
            "Blocked (SEC-SECRET-01): gitleaks found %d secret%s. Rule, path and "
            "line only: the scanner's own output quotes the credential, so it is "
            "never reproduced here." % (total, "" if total == 1 else "s")
        )
        parts.append("")
        parts.extend(blocks)
        if notes:
            parts.append("")
            parts.extend(notes)
        parts.append("")
        parts.append(
            "Remove the secret, rotate it if it was ever real, and re-run. Suppress "
            "a confirmed false positive via " + BASELINE + " with an owner, an "
            "expiry and `repo: <directory name of the repo>`, not inline."
        )
        if errors:
            parts.append("")
            parts.append(
                "scanner error: and one subject produced no verdict at all, so the "
                "list above may be incomplete:"
            )
            for e in errors:
                parts.append("  " + e)
    else:
        # Leading token is load-bearing: a caller must be able to tell "the scan
        # says no" from "the scan did not run".
        parts.append(
            "scanner error: the secret scan produced no verdict, so this is NOT a "
            "clean result."
        )
        parts.append("")
        for e in errors:
            parts.append("  " + e)
        if notes:
            parts.append("")
            parts.extend(notes)
        parts.append("")
        parts.append(
            "Fix the scanner, or re-run once it works. This hook blocks rather than "
            "warning because a leaked credential is not recoverable by rerunning "
            "anything."
        )

    sys.stderr.write("\n".join(parts) + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
