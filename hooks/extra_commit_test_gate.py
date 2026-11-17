"""Slooppas c-711 op commit-discipline 0.1.2: extra gevallen voor commit_test_gate.py.

GATE-vorm: (naam, shell, setup, commando, verwacht). LOG-vorm: (naam, payload, verwacht pad of None).
De fixture (tijdelijk git-repo in %TEMP%) komt uit test_commit_test_gate.py zelf.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_commit_test_gate as T  # noqa: E402  (bouwt de tijdelijke fixture)
from _testlib import Report, run_hook  # noqa: E402

BS = chr(92)
FOO_WIN = os.path.join(T.PROJ, 'scripts', 'foo.py')
HELP = T.make('scripts/test_helpers.py')
TEST_HELP = T.make('scripts/test_test_helpers.py')
FAKE_TSV = os.path.join(T.ROOT, 'fake.tsv')


def pre(cmd, shell, cwd=None):
    return {'hook_event_name': 'PreToolUse', 'tool_name': shell, 'cwd': cwd or T.PROJ,
            'tool_input': {'command': cmd}}


def green():
    T.set_green(T.TEST_FOO, T.FOO)


def helpers():
    T.write(HELP, 'x')
    T.write(TEST_HELP, 'x')


C = T.COMMIT_FOO
GATE = [
    # bestand wijzigt in hetzelfde commando, na de groene run, vóór de commit
    ('G-append-then-commit', 'Bash', green, 'echo y >> scripts/foo.py && ' + C, 'deny'),
    ('G-format-then-commit', 'Bash', green, 'python -m black scripts/foo.py && ' + C, 'deny'),
    ('PS:G-setcontent-then-commit', 'PowerShell', green,
     "Set-Content scripts/foo.py 'kapot'; " + C, 'deny'),
    ('G-checkout-then-commit', 'Bash', green, 'git checkout other -- scripts/foo.py && ' + C, 'deny'),
    # padlijst die pas bij uitvoering bekend is
    ('G-pwd-path', 'Bash', lambda: None, 'git commit -m x -- "$PWD/scripts/foo.py"', 'deny'),
    ('G-subst-path-quoted', 'Bash', lambda: None, 'git commit -m x -- "$(pwd)/scripts/foo.py"', 'deny'),
    ('PS:G-env-path', 'PowerShell', lambda: None,
     'git commit -m x -- "$env:CLAUDE_PROJECT_DIR' + BS + 'scripts' + BS + 'foo.py"', 'deny'),
    ('G-cd-var-relative', 'Bash', lambda: None, 'cd $D && git commit -m x -- foo.py', 'deny'),
    # bash: backslash binnen "..." blijft staan
    ('G-dq-abs-path', 'Bash', lambda: None, 'git commit -m x -- "%s"' % FOO_WIN, 'deny'),
    ('G-dq-C-project', 'Bash', lambda: None, 'git -C "%s" commit -m x -- scripts/foo.py' % T.PROJ, 'deny'),
    ('G-dq-git-exe', 'Bash', lambda: None, '"C:' + BS + 'Program Files' + BS + 'Git' + BS + 'cmd' +
     BS + 'git.exe" commit -m x -- scripts/foo.py', 'deny'),
    # lege -C
    ('G-C-empty', 'Bash', lambda: None, 'git -C "" commit -m x -- scripts/foo.py', 'deny'),
    ('G-cd-empty', 'Bash', lambda: None, 'cd ""; ' + C, 'deny'),
    # onzichtbaar voor de lexer
    ('G-unquoted-heredoc-subst', 'Bash', lambda: None, 'cat <<EOF\n$(%s)\nEOF' % C, 'deny'),
    ('G-redirect-subst', 'Bash', lambda: None, 'echo hi > $(mktemp); ' + C, 'deny'),
    ('PS:G-block-comment', 'PowerShell', lambda: None, '<# c #> ' + C, 'deny'),
    ('G-timeout-wrapper', 'Bash', lambda: None, 'timeout 60 ' + C, 'deny'),
    ('G-pipe-to-bash', 'Bash', lambda: None, "echo '%s' | bash" % C, 'deny'),
    # bronbestand waarvan de naam zelf met test_ begint
    ('G-source-named-test', 'Bash', helpers, 'git commit -m x -- scripts/test_helpers.py', 'deny'),
    # schrijven naar het bewijsbestand met aliassen en andere programma's
    ('PS:G-state-copy-alias', 'PowerShell', lambda: T.write(FAKE_TSV, 'x'),
     'copy %s %s/green-tests.tsv' % (FAKE_TSV, T.STATE_FWD), 'deny'),
    ('PS:G-state-ac-alias', 'PowerShell', lambda: None,
     "'regel' | ac %s/green-tests.tsv" % T.STATE_FWD, 'deny'),
    ('G-state-python', 'Bash', lambda: None,
     "python -c \"open('%s/green-tests.tsv','a').write('x')\"" % T.STATE_FWD, 'deny'),
    # gewoon gebruik dat door moet
    ('N-add-then-commit-green', 'Bash', green, 'git add scripts/foo.py && ' + C, 'allow'),
    ('N-heredoc-msg-green', 'Bash', green,
     "git commit -m \"$(cat <<'EOF'\nfix: x\n\nCo-Authored-By: a <b@c>\nEOF\n)\" -- scripts/foo.py", 'allow'),
    ('PS:N-backslash-path-green', 'PowerShell', green, 'git commit -m x -- scripts' + BS + 'foo.py', 'allow'),
    ('N-with-loose-green', 'Bash', green, 'git commit -m x -- scripts/foo.py scripts/loose.py', 'allow'),
    ('N-S-sign-green', 'Bash', green, 'git commit -S -m x -- scripts/foo.py', 'allow'),
    ('N-from-subdir-green', 'Bash', green, 'git commit -m x -- foo.py', 'allow'),
]
SUBDIR = {'N-from-subdir-green': os.path.join(T.PROJ, 'scripts')}

# basis-map bij een cd in een blok: wordt willekeurig gekozen?
REPEAT = [
    ('G-ps-if-cd', 'PowerShell', 'if ($true) { cd scripts }; git commit -m x -- foo.py'),
    ('G-bash-brace-cd', 'Bash', '{ cd scripts; }; git commit -m x -- foo.py'),
]


def post(cmd, tool='Bash', cwd=None):
    p = T.post(cmd)
    p['tool_name'] = tool
    if cwd:
        p['cwd'] = cwd
    return p


LOG = [
    ('L-interactive-flag', post('python -i scripts/test_foo.py'), None),
    ('L-interactive-cluster', post('python -Ii scripts/test_foo.py'), None),
    ('L-b-flag', post('python -b scripts/test_foo.py'), T.TEST_FOO),  # onschuldig, mag tellen
    ('N-dot-slash', post('python ./scripts/test_foo.py'), T.TEST_FOO),
    ('N-quoted-path', post('python "scripts/test_foo.py"'), T.TEST_FOO),
    ('N-from-subdir', post('python test_foo.py', cwd=os.path.join(T.PROJ, 'scripts')), T.TEST_FOO),
    ('N-python311', post('python3.11 scripts/test_foo.py'), T.TEST_FOO),
    ('N-ps-backslash', post('python scripts' + BS + 'test_foo.py', 'PowerShell'), T.TEST_FOO),
    ('N-ps-dot-call', post('.' + BS + 'tools' + BS + 'test-bar.ps1', 'PowerShell'), T.TEST_BAR),
    ('N-pytest-not-counted', post('python -m pytest scripts/test_foo.py'), None),
]


def main():
    r = Report('commit-test-gate extra PreToolUse: %d checks' % len(GATE))
    for name, shell, setup, cmd, want in GATE:
        T.reset()
        for f in (HELP, TEST_HELP):
            if os.path.exists(f):
                os.remove(f)
        setup()
        got = run_hook(T.HOOK, pre(cmd, shell, SUBDIR.get(name)), T.ENV)
        r.check(name.replace('PS:', ''), got == want,
                'verwacht %s, kreeg %s' % (want, got) if got != want else '')

    r.section('herhaald (20x): cd in een blok, relatief pad, test nooit gedraaid')
    for name, shell, cmd in REPEAT:
        T.reset()
        outs = [run_hook(T.HOOK, pre(cmd, shell), T.ENV) for _ in range(20)]
        r.check(name, outs.count('deny') == 20, '%d deny / %d allow' % (outs.count('deny'), outs.count('allow')))

    r.section('commit-test-gate extra PostToolUse: %d checks' % len(LOG))
    for name, payload, want in LOG:
        ok = T.run_log(T.HOOK, (name, '', payload, want))
        r.check(name, ok, 'verwacht %s' % ('niets vastgelegd' if want is None else 'vastgelegd'))
    import shutil
    shutil.rmtree(T.ROOT, ignore_errors=True)
    r.finish()


if __name__ == '__main__':
    main()
