"""Tests for scoped_commit.py.

Run:  python hooks/test_scoped_commit.py
      python hooks/test_scoped_commit.py --self-test   (proves the guard CAN turn red)
"""

import os
import re
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


def msys(path):
    """C:/x/y -> /c/x/y (Git Bash form); None off Windows."""
    if os.name != 'nt' or not re.match(r'^[A-Za-z]:', path):
        return None
    return '/' + path[0].lower() + path[2:].replace(chr(92), '/')


MP, MO = msys(PROJ), msys(OTHER)

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
    # c-940 / 0.1.2: H-01, a cd or -C to another repo only covers its own segments
    ('H01-cd-after-add', 'git add -A; cd %s' % O, 'deny'),
    ('H01-cd-after-commit', 'git commit -m x; cd %s' % O, 'deny'),
    ('H01-two-repos', 'cd %s && git status; cd %s && git commit -am x' % (O, P), 'deny'),
    ('H01-C-other-then-bare', 'git -C %s status; git add -A' % O, 'deny'),
    ('H01-cd-back', 'cd %s; cd %s; git add -A' % (O, P), 'deny'),
    ('H01-subshell', '(cd %s && git commit -am x); git add -A' % O, 'deny'),
    ('H01-block-union', 'cd %s; { cd %s; }; git add -A' % (O, P), 'deny'),
    ('H01-C-relative-other', 'git -C %s/.. -C %s commit -am x' % (P, O), 'allow'),
    # H-03: start positions
    ('H03-env-prefix', 'X=1 git add -A', 'deny'),
    ('H03-git-editor', 'GIT_EDITOR=true git commit -m x', 'deny'),
    ('H03-then', 'if true; then git add -A; fi', 'deny'),
    ('H03-do', 'for f in a; do git add .; done', 'deny'),
    ('H03-command', 'command git add -A', 'deny'),
    ('H03-env', 'env git commit -am x', 'deny'),
    ('H03-subst', 'echo $(git add -A)', 'deny'),
    ('H03-backtick', 'echo `git add -A`', 'deny'),
    ('H03-bang', '! git commit -am x', 'deny'),
    ('H03-ps-call', '& git commit -m x', 'deny'),
    # H-04: script text that goes to a shell is a command, not documentation
    ('H04-heredoc-bash', "bash <<'EOF'\ngit add -A\nEOF", 'deny'),
    ('H04-sh-c', "sh -c 'git add -A'", 'deny'),
    ('H04-bash-c', 'bash -c "git commit -am x"', 'deny'),
    ('H04-ps-command', 'powershell -NoProfile -Command "git add -A"', 'deny'),
    ('H04-eval', 'eval "git add ."', 'deny'),
    ('H04-cat-heredoc-msg', "git commit -m \"$(cat <<'EOF'\nnote: git add -A\nEOF\n)\" -- README.md", 'allow'),
    # H-05: other spellings of the same call
    ('H05-stage', 'git stage -A', 'deny'),
    ('H05-no-pager-commit', 'git --no-pager commit -am x', 'deny'),
    ('H05-no-pager-add', 'git --no-pager add -A', 'deny'),
    ('H05-amend-abbrev', 'git commit --amen -m x -- a.md', 'deny'),
    ('H05-amend-abbrev2', 'git commit --am -m x -- a.md', 'deny'),
    ('H05-no-pager-amend', 'git --no-pager commit --amend -m x -- a.md', 'deny'),
    ('H05-add-al', 'git add --al', 'deny'),
    ('H05-add-upd', 'git add --upd', 'deny'),
    ('H05-add-cluster', 'git add -vA', 'deny'),
    ('H05-commit-include', 'git commit -i -m x -- a.md', 'deny'),
    ('H05-git-dir', 'cd %s; git --git-dir=%s/.git --work-tree=%s add -A' % (O, P, P), 'deny'),
    ('H05-msg-glued', 'git commit -mfix -- a.md', 'allow'),
    ('H05-author', 'git commit --author=x -m y -- a.md', 'allow'),
    # H-06: path lists that mean the whole tree
    ('H06-add-dot-slash', 'git add ./', 'deny'),
    ('H06-add-top', 'git add :/', 'deny'),
    ('H06-add-star', 'git add *', 'deny'),
    ('H06-commit-dot', 'git commit -m x -- .', 'deny'),
    ('H06-commit-top-magic', "git commit -m x -- ':(top)'", 'deny'),
    ('H06-commit-glob', "git commit -m x -- '*.md'", 'deny'),
    ('H06-commit-project-abs', 'git commit -m x -- %s' % P, 'deny'),
    ('H06-add-dir', 'git add scripts/', 'allow'),
    ('H06-commit-dir', 'git commit -m x -- scripts', 'allow'),
    ('H06-add-dashdash', 'git add -- scripts/foo.py', 'allow'),
    # allow: fail open
    ('allow-empty-command', '', 'allow'),
]
if MP:  # Git Bash spelling of the same directories
    CASES += [
        ('H01-msys-project', 'cd %s && git commit -am x' % MP, 'deny'),
        ('H01-msys-other', 'cd %s && git commit -am x' % MO, 'allow'),
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
