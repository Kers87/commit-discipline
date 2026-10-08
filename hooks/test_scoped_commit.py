"""Tests for scoped_commit.py.

Run:  python hooks/test_scoped_commit.py
      python hooks/test_scoped_commit.py --self-test   (proves the guard CAN turn red)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testlib import HERE, Report, mutated_copy, run_hook  # noqa: E402

HOOK = os.path.join(HERE, 'scoped_commit.py')
PROJ = tempfile.mkdtemp(prefix='cd-proj-')
OTHER = tempfile.mkdtemp(prefix='cd-other-')
P = PROJ.replace('\\', '/')
O = OTHER.replace('\\', '/')
ENV = {'CLAUDE_PROJECT_DIR': PROJ}

# name, command, expected
CASES = [
    # deny: index-wide staging
    ('deny-add-A', 'git add -A && git commit -m "x" -- foo.py', 'deny'),
    ('deny-add-all-long', 'git add --all', 'deny'),
    ('deny-add-dot', 'git add .', 'deny'),
    ('deny-add-u', 'git add -u', 'deny'),
    # deny: a commit that stages by itself
    ('deny-commit-am', 'git commit -am "fix"', 'deny'),
    ('deny-commit-a-separate', 'git commit -a -m "fix"', 'deny'),
    ('deny-commit-all-long', 'git commit --all -m "fix"', 'deny'),
    # deny: commit without a path list
    ('deny-commit-bare', 'git commit -m "fix"', 'deny'),
    ('deny-commit-amend', 'git commit --amend -m "fix"', 'deny'),
    ('deny-after-semicolon', 'python scripts/x.py; git commit -m "fix"', 'deny'),
    ('deny-after-and', 'git add scripts/x.py && git commit -m "fix"', 'deny'),
    ('deny-on-new-line', 'cd %s\ngit commit -m "fix"' % P, 'deny'),
    ('deny-cd-project-first', 'cd %s && git commit -am "fix"' % P, 'deny'),
    # deny: git call variants
    ('deny-git-exe', 'git.exe commit -am "fix"', 'deny'),
    ('deny-git-full-path', 'C:\\PROGRA~1\\Git\\cmd\\git.exe commit -m "fix"', 'deny'),
    ('deny-git-posix-path', '/usr/bin/git commit -m "fix"', 'deny'),
    ('deny-git-capital', 'Git commit -m "fix"', 'deny'),
    ('deny-git-c-option', 'git -c user.name=x commit -m "fix"', 'deny'),
    ('deny-in-braces', 'if ($true) { git commit -am "fix" }', 'deny'),
    ('deny-in-parens', '(git commit -m "fix")', 'deny'),
    # allow: the prescribed form
    ('allow-path-scoped', 'git commit -m "fix" -- scripts/foo.py', 'allow'),
    ('allow-add-path-commit',
     'git add scripts/foo.py && git commit -m "x" -- scripts/foo.py docs/notes.md', 'allow'),
    ('allow-git-C-project', 'git -C %s commit -m "x" -- README.md' % P, 'allow'),
    ('allow-git-exe-scoped', 'git.exe commit -m "x" -- README.md', 'allow'),
    ('allow-braces-scoped', 'if ($true) { git commit -m "x" -- README.md }', 'allow'),
    # allow: read commands
    ('allow-status', 'git status --short', 'allow'),
    ('allow-log', 'git log --oneline -n 5', 'allow'),
    ('allow-diff-cached', 'git diff --cached --name-only', 'allow'),
    ('allow-add-targeted', 'git add scripts/foo.py', 'allow'),
    # allow: not a real git call (false positives)
    ('allow-rule-in-message', 'git commit -m "docs: git add -A is forbidden" -- README.md', 'allow'),
    ('allow-heredoc-doc', "cat > doc.md << 'EOF'\ngit add -A\ngit commit -am x\nEOF", 'allow'),
    # allow: another repository
    ('allow-other-repo-C', 'git -C %s commit -am "x"' % O, 'allow'),
    ('allow-other-repo-cd', 'cd %s && git commit -am "x"' % O, 'allow'),
    # allow: deliberate escape hatch
    ('allow-marker-add', 'git add -A   # scope-ok: deliberate sync catch-up', 'allow'),
    ('allow-marker-commit', 'git commit -m "sync up to today" # scope-ok: catch-up', 'allow'),
    # allow: fail open
    ('allow-empty-command', '', 'allow'),
]


def payload(cmd):
    return {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_input': {'command': cmd}}


def main():
    r = Report('scoped-commit: %d checks' % len(CASES))
    for name, cmd, want in CASES:
        got = run_hook(HOOK, payload(cmd), ENV)
        r.check(name, got == want, got if got != want else '')
    got = run_hook(HOOK, 'this is not json', ENV)
    r.check('allow-no-json', got == 'allow')

    if '--self-test' in sys.argv[1:]:
        r.section('self-test: break the guard and demand that the deny checks turn red')
        denies = [c for c in CASES if c[2] == 'deny']
        mutations = [
            ('guard-always-open', 'def block(hit, why, hint):\n    deny(',
             'def block(hit, why, hint):\n    return\n    deny('),
            ('escape-hatch-always-on', "if re.search(r'(?i)scope-ok:\\s*\\S', cmd):", 'if True:'),
        ]
        for mname, old, new in mutations:
            _, broken = mutated_copy('scoped_commit.py', old, new)
            if broken is None:
                r.check('self-test %s' % mname, False, 'mutation anchor not found')
                continue
            flipped = sum(run_hook(broken, payload(c[1]), ENV) == 'allow' for c in denies)
            r.check('self-test %s' % mname, flipped == len(denies),
                    '%d of %d deny checks turned red' % (flipped, len(denies)))
    r.finish()


if __name__ == '__main__':
    main()
