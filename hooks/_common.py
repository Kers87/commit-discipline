"""Shared helpers for the commit-discipline hooks.

Every hook reads one JSON object from stdin and either stays silent (allow) or prints a
PreToolUse deny decision on stdout. All hooks fail open on input they cannot parse: a guard
that crashes on odd input should not take the whole session down with it.

Environment:
  CLAUDE_PROJECT_DIR            project root (set by Claude Code for hooks)
  COMMIT_DISCIPLINE_STATE_DIR   override for the state directory (tests use this)
  CLAUDE_PLUGIN_DATA            plugin data dir (set by Claude Code); state lives below it
"""

import hashlib
import json
import os
import re
import sys

# An absolute path in a shell command: a Windows drive path, a POSIX path or a ~ path.
ABS_PATH = r'((?:[A-Za-z]:[\\/]|/|~)[^\s;&|]*)'

# Heredoc bodies are documentation, not commands: a script that *writes about* `git add -A`
# must not trip the guard.
HEREDOC = re.compile(r'<<-?\s*[\'"]?(\w+)[\'"]?[\s\S]*?\r?\n\s*\1')


def read_input():
    """Return the hook input as a dict, or None when stdin is not usable JSON."""
    try:
        raw = sys.stdin.buffer.read().decode('utf-8-sig')
        data = json.loads(raw)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def deny(reason):
    """Print a PreToolUse deny decision and stop."""
    out = {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                                  'permissionDecision': 'deny',
                                  'permissionDecisionReason': reason}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    sys.exit(0)


def norm(path, base=None):
    """Absolute, normalised, case-folded (on Windows) form of a path, or None."""
    if not path:
        return None
    try:
        p = os.path.expanduser(str(path))
        if os.sep == '\\':
            p = p.replace('/', '\\')
        if not os.path.isabs(p):
            p = os.path.join(base or os.getcwd(), p)
        return os.path.normcase(os.path.normpath(os.path.abspath(p)))
    except Exception:
        return None


def is_within(path, root):
    """True when path is root itself or lies below it (both already normalised)."""
    if not path or not root:
        return False
    root = root.rstrip('\\/')
    return path == root or path.startswith(root + os.sep)


def project_dir(data=None):
    """The project the guards protect: CLAUDE_PROJECT_DIR, else the hook cwd, else cwd."""
    for cand in (os.environ.get('CLAUDE_PROJECT_DIR'),
                 (data or {}).get('cwd'),
                 os.getcwd()):
        p = norm(cand)
        if p:
            return p
    return None


def state_dir():
    """Where the guards keep their evidence. Outside the project by default."""
    override = os.environ.get('COMMIT_DISCIPLINE_STATE_DIR')
    if override:
        return norm(override)
    data = os.environ.get('CLAUDE_PLUGIN_DATA')
    if data:
        return norm(os.path.join(data, 'state'))
    return norm(os.path.join('~', '.claude', 'commit-discipline', 'state'))


def sha256(path):
    """Hex sha256 of a file's content, or '-' when there is no such file."""
    if not path or not os.path.isfile(path):
        return '-'
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def targets_other_repo(cmd, project, case_sensitive_C=False):
    """Return (other, base) for `git -C <path>` / `cd <path>` in a command.

    other is True when the command demonstrably drives a directory outside the project;
    the guards then stay out of the way. base is the first in-project directory found,
    for resolving relative paths.
    """
    base = None
    git_c = (r'(?i:git)(?:\.exe)?\s+-C\s+' if case_sensitive_C
             else r'(?i)git(?:\.exe)?\s+-C\s+')
    for pattern in (git_c + ABS_PATH, r'(?i)\bcd\s+' + ABS_PATH):
        m = re.search(pattern, cmd)
        if m:
            target = norm(m.group(1))
            if not is_within(target, project):
                return True, None
            base = base or target
    return False, base
