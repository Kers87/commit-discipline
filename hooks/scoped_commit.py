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

Refused (0.1.2): `git add`/`git stage` with -A, -u, --all, --update (also abbreviated, also in
a cluster like -vA) or a pathspec that means the whole tree (., ./, :/, :(top), a glob, the
project root); `git commit` with -a/--all, --amend (also abbreviated), -i/--include (that
commits the index too), or without a `--` path list, or with a whole-tree path list.
Which git calls count is decided per segment by _common.git_calls: a `cd` or `git -C` to
another repository only takes the segments that really run there.

Escape hatch for deliberate bulk commits: put `scope-ok: <reason>` in the command.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (COMMIT_VALUE_LONG, COMMIT_VALUE_SHORT, deny, git_calls,  # noqa: E402
                     long_is, norm, project_dir, read_input, shell_of, short_has, split_args,
                     whole_tree)

ADD_HINT = 'Stage only the paths of your own change: git add <exact path>.'
COMMIT_HINT = 'Use: git commit -m "..." -- <path> [<path> ...].'


def block(hit, why, hint):
    deny("BLOCKED by scoped-commit: '%s'. Reason: %s. %s New file? Run git add <exact path> "
         "first. Deliberate bulk commit? Put 'scope-ok: <reason>' in the command."
         % (hit, why, hint))


def check_add(call, project):
    opts, paths, _ = split_args(call.args)
    for o in opts:
        if long_is(o, 'all', 'update') or short_has(o, 'Au') or \
                (len(o) >= 7 and long_is(o, 'no-ignore-removal')):
            block(call.text(), 'index-wide staging (git add -A / -u / --all) also picks up what '
                  'another session has in the working tree', ADD_HINT)
        if long_is(o, 'pathspec-from-file') and len(o) > 4:
            block(call.text(), 'a pathspec file hides which paths are staged', ADD_HINT)
    for t, _ in paths:
        if whole_tree(t, call.base, project):
            block(call.text(), "the path '%s' means the whole tree (., :/, a glob or the project "
                  'root), which also stages the work of a parallel session' % t, ADD_HINT)


def check_commit(call, project):
    opts, paths, dd = split_args(call.args, COMMIT_VALUE_SHORT, COMMIT_VALUE_LONG)
    for o in opts:
        if long_is(o, 'all') or short_has(o, 'a', COMMIT_VALUE_SHORT):
            block(call.text(), 'git commit -a stages everything that changed, including the work '
                  'of a parallel session', COMMIT_HINT)
        if long_is(o, 'amend'):
            block(call.text(), 'git commit --amend rewrites the last commit, and with parallel '
                  'sessions the last commit is not necessarily yours',
                  'Make a new commit: git commit -m "..." -- <paths>.')
        if (len(o) >= 4 and long_is(o, 'include')) or short_has(o, 'i', COMMIT_VALUE_SHORT):
            block(call.text(), 'git commit -i also commits what is staged in the shared index',
                  COMMIT_HINT)
    if not dd or not paths:
        block(call.text(), 'a bare git commit uses the shared index; with a second session '
              'running you commit its staged work too', COMMIT_HINT)
    for t, _ in paths:
        if whole_tree(t, call.base, project):
            block(call.text(), "the path list '-- %s' means the whole tree (., :/, a glob or the "
                  'project root), so it is not a path-scoped commit' % t, COMMIT_HINT)


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

    # 2. Every git call that can act on the project, read per segment.
    project = project_dir(data)
    try:
        calls = git_calls(cmd, project, norm(data.get('cwd')), shell_of(data))
    except Exception:
        return
    for call in calls:
        if not call.in_project:
            continue
        if call.sub in ('add', 'stage'):
            check_add(call, project)
        elif call.sub == 'commit':
            check_commit(call, project)


if __name__ == '__main__':
    main()
