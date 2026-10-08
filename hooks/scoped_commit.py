"""scoped-commit: PreToolUse guard (matcher Bash|PowerShell).

Forces path-scoped commits so that parallel Claude Code sessions in one working tree do not
commit each other's work.

Why: the git index lives in .git and has no notion of a session. Index-wide staging
(`git add -A`) or a commit that uses the index (`git commit` without paths) picks up whatever
another session just staged. Seen in practice: a commit whose message described one task
carried five files of another, and a commit that carried 23 files of a sync job and zero lines
of the change its message described (the `git add` had collided with .git/index.lock, the
error went to stderr and the commit ran anyway).

The rule: commit from the working tree with an explicit path list.
    git add <exact path>               # only needed for a NEW file
    git commit -m "..." -- <paths>     # ignores the index entirely
That form commits exactly the named paths and leaves another session's staged work untouched
in both the index and the working tree, deletions included.

Escape hatch for deliberate bulk commits: put `scope-ok: <reason>` in the command.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import HEREDOC, deny, project_dir, read_input, targets_other_repo  # noqa: E402

# A git call at a command start position: start of the command, after a shell operator, on a
# new line, or after { or ( (an if-block or subexpression). Case-insensitive, and git.exe or a
# full path to git count too; all of these slipped past an earlier version.
START = (r'(?i)(?:^|\n|;|&&|\|\||\||\{|\()\s*(?:sudo\s+)?(?:&\s*)?'
         r'(?:[^\s;&|]*[\\/])?git(?:\.exe)?\s+(?:-[Cc]\s+\S+\s+)*')

RULES = [
    (START + r'add\s+(?:[^\n;&|]*?\s)?(?:-A|--all|-u|--update|\.)(?=\s|$)',
     'index-wide staging (git add -A / . / -u) also picks up what another session has in the '
     'working tree',
     'Stage only the paths of your own change: git add <exact path>.'),
    (START + r'commit(?:\s+[^\n;&|]*?)?\s(?:-[a-zA-Z]*a[a-zA-Z]*|--all)(?=\s|$)',
     'git commit -a stages everything that changed, including the work of a parallel session',
     'Use: git commit -m "..." -- <path> [<path> ...].'),
    (START + r'commit(?:\s+[^\n;&|]*?)?\s--amend(?=\s|$)',
     'git commit --amend rewrites the last commit, and with parallel sessions the last commit '
     'is not necessarily yours',
     'Make a new commit: git commit -m "..." -- <paths>.'),
]


def block(hit, why, hint):
    deny("BLOCKED by scoped-commit: '%s'. Reason: %s. %s New file? Run git add <exact path> "
         "first. Deliberate bulk commit? Put 'scope-ok: <reason>' in the command."
         % (hit, why, hint))


def main():
    data = read_input()
    if data is None:
        return
    cmd = (data.get('tool_input') or {}).get('command')
    if not isinstance(cmd, str) or not cmd.strip():
        return

    # 1. Deliberate escape hatch.
    if re.search(r'(?i)scope-ok:\s*\S', cmd):
        return

    # 2. Cut away what is not a git call: heredoc bodies and quoted strings (a commit message
    #    that quotes the rule must not trip it).
    s = HEREDOC.sub(' ', cmd)
    s = re.sub(r'"[^"]*"', 'QSTR', s)
    s = re.sub(r"'[^']*'", 'QSTR', s)

    # 3. A command that demonstrably drives another repository is out of scope.
    other, _ = targets_other_repo(s, project_dir(data))
    if other:
        return

    # 4. Forbidden forms.
    for pattern, why, hint in RULES:
        m = re.search(pattern, s)
        if m:
            block(m.group(0).strip(' \n;&|'), why, hint)

    # 5. Every commit needs a -- path list. A bare `git commit` commits the shared index.
    for m in re.finditer(START + r'commit(?=\s|$)[^\n;&|]*', s):
        if not re.search(r'\s--\s+\S', m.group(0)):
            block(m.group(0).strip(' \n;&|'),
                  'a bare git commit uses the shared index; with a second session running you '
                  'commit its staged work too',
                  'Use: git commit -m "..." -- <path> [<path> ...].')


if __name__ == '__main__':
    main()
