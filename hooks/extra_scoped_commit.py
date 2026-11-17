"""Slooppas c-711 op commit-discipline 0.1.2: extra gevallen voor scoped_commit.py.

Zelfde vorm als CASES in test_scoped_commit.py: (naam, commando, verwacht).
'PS:' voor de naam = PowerShell-tool. Verwacht volgt de README, niet de code.
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testlib import Report, run_hook  # noqa: E402
from test_scoped_commit import ENV, HOOK, O, OTHER, P, PROJ, payload  # noqa: E402

BS = chr(92)
PW, OW = PROJ, OTHER            # Windows-spelling met backslashes

EXTRA = [
    # opties tussen aanhalingstekens blijven opties voor git
    ('Q-add-quoted-A', "git add '-A'", 'deny'),
    ('Q-add-dq-A', 'git add "-A"', 'deny'),
    ('PS:Q-add-quoted-A', "git add '-A'", 'deny'),
    ('Q-commit-quoted-amend', 'git commit "--amend" -m x -- a.md', 'deny'),
    ('Q-commit-quoted-include', "git commit '-i' -m x -- a.md", 'deny'),
    ('Q-ansi-c-quoted', "git add $'-A'", 'deny'),
    # -S heeft een optionele, vastgeplakte waarde; het volgende woord is geen keyid
    ('S-gpg-eats-amend', 'git commit -S --amend -m x -- a.md', 'deny'),
    ('S-gpg-eats-include', 'git commit -S -i -m x -- a.md', 'deny'),
    ('S-gpg-normal', 'git commit -S -m x -- a.md', 'allow'),
    # padlijst die pas bij uitvoering bekend is
    ('V-add-subst', 'git add $(git rev-parse --show-toplevel)', 'deny'),
    ('V-add-subst-quoted', 'git add "$(git rev-parse --show-toplevel)"', 'deny'),
    ('V-add-ls-files', 'git add $(git ls-files -m)', 'deny'),
    ('V-add-pwd', 'git add "$PWD"', 'deny'),
    ('PS:V-add-pwd', 'git add $PWD', 'deny'),
    ('V-commit-pwd', 'git commit -m x -- "$PWD"', 'deny'),
    # bash: backslash binnen "..." is alleen escape voor $ ` " \ en newline
    ('DQ-cd-other-then-proj', 'cd %s && cd "%s" && git add -A' % (O, PW), 'deny'),
    ('DQ-C-proj-from-other', 'cd %s; git -C "%s" add -A' % (O, PW), 'deny'),
    ('DQ-git-exe-quoted', '"C:' + BS + 'Program Files' + BS + 'Git' + BS + 'cmd' + BS +
     'git.exe" add -A', 'deny'),
    ('DQ-cd-other-backslash', 'cd "%s" && git commit -am x' % OW, 'allow'),
    ('DQ-C-other-backslash', 'git -C "%s" commit -am x' % OW, 'allow'),
    # lege map
    ('E-C-empty', 'git -C "" add -A', 'deny'),
    ('E-cd-empty', 'cd ""; git add -A', 'deny'),
    ('PS:E-cd-empty', "cd ''; git add -A", 'deny'),
    # redirect-doel dat een $( ) is
    ('R-redirect-subst', 'echo hi > $(mktemp); git add -A', 'deny'),
    ('R-redirect-subst-commit', 'echo hi > $(mktemp); git commit -am x', 'deny'),
    ('R-procsubst', 'cat <(git add -A)', 'deny'),
    # scripttekst die via een pijp of here-string naar een shell gaat
    ('P-echo-pipe-bash', "echo 'git add -A' | bash", 'deny'),
    ('P-herestring-bash', "bash <<< 'git add -A'", 'deny'),
    ('P-cat-heredoc-pipe-bash', "cat <<'EOF' | bash\ngit add -A\nEOF", 'deny'),
    ('PS:P-pipe-iex', "'git add -A' | iex", 'deny'),
    ('P-unquoted-heredoc-subst', 'cat <<EOF\n$(git add -A)\nEOF', 'deny'),
    ('P-quoted-heredoc-doc', "cat <<'EOF'\n$(git add -A)\nEOF", 'allow'),
    ('PS:P-herestring-subexpr', '$m = @"\n$(git add -A)\n"@', 'deny'),
    ('PS:P-herestring-single-doc', "$m = @'\n$(git add -A)\n'@", 'allow'),
    # shell-opties voor -c
    ('B-bash-o-pipefail', "bash -o pipefail -c 'git add -A'", 'deny'),
    ('B-bash-c-dashdash', "bash -c -- 'git add -A'", 'deny'),
    # wrappers buiten de lijst
    ('W-timeout', 'timeout 30 git add -A', 'deny'),
    ('W-winpty', 'winpty git commit -am x', 'deny'),
    ('W-command-p', 'command -p git add -A', 'deny'),
    # xargs/find met plaatshouder
    ('X-xargs-I-braces', 'ls | xargs -I{} git add {}', 'deny'),
    ('X-xargs-I-percent', 'ls | xargs -I % git add %', 'deny'),
    ('X-xargs-sh-c', "ls | xargs -I{} sh -c 'git add {}'", 'deny'),
    ('X-find-exec', "find . -name '*.py' -exec git add {} +", 'deny'),
    # brace-expansie
    ('BR-brace-dot', 'git add {.,}', 'deny'),
    ('BR-brace-files', 'git commit -m x -- scripts/{a,b}.py', 'allow'),
    # git-opties die impliciet -u zijn
    ('A-renormalize', 'git add --renormalize', 'deny'),
    # PowerShell blokcommentaar op dezelfde regel
    ('PS:C-block-comment', '<# note #> git add -A', 'deny'),
    # Start-Process met argumenten die met een streep beginnen
    ('PS:SP-dash-first', "Start-Process git -ArgumentList '-C . add -A'", 'deny'),
    ('PS:SP-no-pager', "Start-Process git -ArgumentList '--no-pager','add','-A'", 'deny'),
    # autocorrect via -c op het commando zelf (zoals alias.*)
    ('AC-autocorrect', 'git -c help.autocorrect=immediate comit -am x', 'deny'),
    # te diep genest en 'git' niet letterlijk
    ('X-deep-split-word', '$(' * 600 + "g''it add -A" + ')' * 600, 'deny'),
    # gewoon gebruik dat door moet
    ('N-commit-heredoc-std',
     "git commit -m \"$(cat <<'EOF'\nfix: x\n\nCo-Authored-By: a <b@c>\nEOF\n)\" -- a.md", 'allow'),
    ('N-add-two-commit', 'git add a.md b.md && git commit -m x -- a.md b.md', 'allow'),
    ('N-log-pipe', 'git log --oneline | head -5', 'allow'),
    ('N-diff-then-commit', 'git diff --stat -- a.md && git commit -m x -- a.md', 'allow'),
    ('N-msg-semicolon', 'git commit -m "a; git add -A" -- a.md', 'allow'),
    ('N-msg-single-subst', "git commit -m 'about $(git add -A)' -- a.md", 'allow'),
    ('PS:N-herestring-msg', "git commit -m @'\nline git add -A\n'@ -- a.md", 'allow'),
    ('PS:N-cd-other-backslash', 'cd "%s"; git commit -am x' % OW, 'allow'),
    ('N-push', 'git push origin HEAD', 'allow'),
    ('N-stash-list', 'git stash list', 'allow'),
]


def raw(stdin):
    """Run the hook with raw bytes; return ('deny'|'allow'|'crash', exitcode)."""
    env = dict(os.environ)
    env.update(ENV)
    proc = subprocess.run([sys.executable, '-S', HOOK], input=stdin, capture_output=True,
                          env=env, timeout=120)
    out = proc.stdout.decode('utf-8', 'replace')
    if proc.returncode not in (0, 2):
        return 'crash', proc.returncode
    return ('deny' if '"deny"' in out or proc.returncode == 2 else 'allow'), proc.returncode


def main():
    r = Report('scoped-commit extra: %d checks' % len(EXTRA))
    for name, cmd, want in EXTRA:
        if name.startswith('PS:'):
            name, cmd = name[3:], 'PS:' + cmd
        try:
            got = run_hook(HOOK, payload(cmd), ENV)
        except RuntimeError as e:
            got = 'crash: ' + str(e).splitlines()[-1][:120]
        r.check(name, got == want, 'verwacht %s, kreeg %s' % (want, got) if got != want else '')

    r.section('cwd buiten het project (persistente cd naar een tweede werkmap)')
    pl = payload('git commit -am x')
    pl['cwd'] = OTHER
    got = run_hook(HOOK, pl, ENV)
    r.check('CWD-other-commit-am', got == 'allow', 'verwacht allow, kreeg %s' % got)

    r.section('rare JSON')
    cases = [
        ('J-tool-input-string', json.dumps({'tool_name': 'Bash', 'tool_input': 'git add -A'}).encode()),
        ('J-command-list', json.dumps({'tool_name': 'Bash', 'tool_input': {'command': ['git', 'add', '-A']}}).encode()),
        ('J-bom', b'\xef\xbb\xbf' + json.dumps(payload('git add -A')).encode()),
        ('J-utf16', json.dumps(payload('git add -A')).encode('utf-16')),
        ('J-top-array', b'[1,2]'),
        ('J-cwd-number', json.dumps(dict(payload('git add -A'), cwd=12)).encode()),
        ('J-deep-extra-field', ('{"x":' + '[' * 5000 + ']' * 5000 + ',' +
                                json.dumps(payload('git add -A'))[1:]).encode()),
    ]
    for name, data in cases:
        got, code = raw(data)
        print('INFO  %s -> %s (exit %d)' % (name, got, code))

    r.section('lange invoer')
    for name, cmd in [
            ('L-many-segments', 'echo a; ' * 200000 + 'git add -A'),
            ('L-one-long-word', 'echo ' + 'a' * 2000000 + '; git add -A'),
            ('L-many-quotes', 'echo ' + '"a" ' * 200000 + '; git add -A'),
            ('L-nested-299', '$(' * 299 + 'git add -A' + ')' * 299),
            ('L-many-heredocs', 'cat <<A; ' * 2000 + '\n' + 'A\n' * 2000 + 'git add -A'),
            ('L-word-600k', 'echo ' + 'a' * 600000 + '; git add -A'),
            ('L-word-1200k', 'echo ' + 'a' * 1200000 + '; git add -A')]:
        t0 = time.time()
        try:
            got = run_hook(HOOK, payload(cmd), ENV)
        except Exception as e:
            got = 'error ' + type(e).__name__
        r.check(name, got == 'deny', 'kreeg %s in %.1f s (%d tekens)' % (got, time.time() - t0, len(cmd)))
    r.finish()


if __name__ == '__main__':
    main()
