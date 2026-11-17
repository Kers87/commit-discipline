"""Tests for commit_test_gate.py, both events.

Run:  python hooks/test_commit_test_gate.py
      python hooks/test_commit_test_gate.py --self-test   (proves per rule that it CAN turn red)
Works in a throwaway project and state dir under the system temp dir.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testlib import HERE, Report, mutated_copy, run_hook  # noqa: E402

HOOK = os.path.join(HERE, 'commit_test_gate.py')
ROOT = tempfile.mkdtemp(prefix='cd-gate-')
PROJ = os.path.join(ROOT, 'project')
STATE = os.path.join(ROOT, 'state')
OTHER = os.path.join(ROOT, 'other')
TSV = os.path.join(STATE, 'green-tests.tsv')
ENV = {'CLAUDE_PROJECT_DIR': PROJ, 'COMMIT_DISCIPLINE_STATE_DIR': STATE}
for d in (os.path.join(PROJ, 'scripts'), os.path.join(PROJ, 'tools'), STATE, OTHER):
    os.makedirs(d, exist_ok=True)


def nc(path):
    return os.path.normcase(os.path.normpath(path))


def make(rel):
    return nc(os.path.join(PROJ, rel))


FOO, TEST_FOO, LOOSE = make('scripts/foo.py'), make('scripts/test_foo.py'), make('scripts/loose.py')
BAR, TEST_BAR = make('tools/bar.ps1'), make('tools/test-bar.ps1')
ALL = [FOO, TEST_FOO, LOOSE, BAR, TEST_BAR]
OUTSIDE_TEST = os.path.join(OTHER, 'test_foo.py')


def write(path, text):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def fwd(path):
    return path.replace(os.sep, '/')


def git(*args):
    subprocess.run(['git', '-C', PROJ] + list(args), check=True, capture_output=True)


# The project is a real git repository with every file committed as 'x', so a path list that
# names a directory or a pathspec can be expanded to the files that actually changed.
for f in ALL:
    write(f, 'x')
git('init', '-q')
git('config', 'user.email', 'test@example.invalid')
git('config', 'user.name', 'test')
git('config', 'commit.gpgsign', 'false')
git('add', '--', 'scripts', 'tools')
git('commit', '-q', '-m', 'init', '--', 'scripts', 'tools')

# A fake interpreter outside any venv (H-08) and a venv interpreter (allowed).
FAKE_PY = os.path.join(ROOT, 'nep', 'python')
VENV_PY = os.path.join(ROOT, 'venv', 'Scripts', 'python.exe')
for f in (FAKE_PY, VENV_PY):
    os.makedirs(os.path.dirname(f), exist_ok=True)
    write(f, 'x')
write(os.path.join(ROOT, 'venv', 'pyvenv.cfg'), 'home = x')


def short_name(path):
    """8.3 form of an existing path on Windows, or None."""
    if os.name != 'nt':
        return None
    import ctypes
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetShortPathNameW(path, buf, 1024)
    return buf.value if n and buf.value.lower() != path.lower() else None


def sha(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def change(path):
    write(path, 'changed')


def set_mtime(path, offset):
    t = time.time() + offset
    os.utime(path, (t, t))


def set_green(test, src):
    with open(TSV, 'a', encoding='utf-8', newline='\n') as f:
        f.write('\t'.join([test, str(int(time.time())), 'test', sha(test), src, sha(src)]) + '\n')


def reset():
    if os.path.exists(TSV):
        os.remove(TSV)
    for f in ALL + [OUTSIDE_TEST]:
        write(f, 'x')


def pre(cmd):
    return {'hook_event_name': 'PreToolUse', 'tool_name': 'PowerShell', 'cwd': PROJ,
            'tool_input': {'command': cmd}}


def post(cmd, event='PostToolUse', interrupted=False, background=False):
    tinput = {'command': cmd}
    if background:
        tinput['run_in_background'] = True
    return {'hook_event_name': event, 'tool_name': 'Bash', 'cwd': PROJ, 'session_id': 'test',
            'tool_input': tinput,
            'tool_response': {'stdout': 'ok', 'stderr': '', 'interrupted': interrupted}}


STATE_FWD = STATE.replace('\\', '/')
COMMIT_FOO = 'git commit -m "x" -- scripts/foo.py'

# name, group, setup, command (None = not JSON), expected
GATE = [
    ('deny-never-run', 'gate', lambda: None, COMMIT_FOO, 'deny'),
    ('deny-source-changed', 'content', lambda: (set_green(TEST_FOO, FOO), change(FOO)), COMMIT_FOO, 'deny'),
    ('deny-test-changed', 'content', lambda: (set_green(TEST_FOO, FOO), change(TEST_FOO)), COMMIT_FOO, 'deny'),
    ('deny-mtime-set-back', 'content',
     lambda: (set_green(TEST_FOO, FOO), change(FOO), set_mtime(FOO, -5 * 3600)), COMMIT_FOO, 'deny'),
    ('deny-other-test-green', 'gate', lambda: set_green(TEST_BAR, BAR), COMMIT_FOO, 'deny'),
    ('deny-ps1-without-run', 'gate', lambda: None, 'git commit -m "x" -- tools/bar.ps1', 'deny'),
    ('deny-one-of-two', 'gate', lambda: set_green(TEST_FOO, FOO),
     'git commit -m "x" -- scripts/foo.py tools/bar.ps1', 'deny'),
    ('deny-after-and', 'gate', lambda: None, 'git add scripts/foo.py && ' + COMMIT_FOO, 'deny'),
    ('deny-heredoc-message', 'gate', lambda: None,
     'git commit -m "$(cat <<\'EOF\'\nline one\nEOF\n)" -- scripts/foo.py', 'deny'),
    ('deny-quoted-path', 'gate', lambda: None, 'git commit -m "x" -- "scripts/foo.py"', 'deny'),
    ('deny-git-c-option', 'gate', lambda: None, 'git -c user.name=x commit -m "x" -- scripts/foo.py', 'deny'),
    ('deny-git-exe', 'variant', lambda: None, 'git.exe commit -m "x" -- scripts/foo.py', 'deny'),
    ('deny-git-full-path', 'variant', lambda: None,
     'C:\\PROGRA~1\\Git\\cmd\\git.exe commit -m "x" -- scripts/foo.py', 'deny'),
    ('deny-git-capital', 'variant', lambda: None, 'Git commit -m "x" -- scripts/foo.py', 'deny'),
    ('deny-in-braces', 'nested', lambda: None, 'if ($true) { git commit -m "x" -- scripts/foo.py }', 'deny'),
    ('deny-in-parens', 'nested-paren', lambda: None, '(git commit -m "x" -- scripts/foo.py)', 'deny'),
    ('deny-unreadable-no-paths', 'unreadable', lambda: None, 'git.exe commit -am "x"', 'deny'),
    ('deny-unreadable-specfile', 'unreadable', lambda: None,
     'git commit -m "x" --pathspec-from-file=list.txt', 'deny'),
    ('deny-state-set-content', 'state', lambda: None,
     'Set-Content %s/green-tests.tsv "x"' % STATE_FWD, 'deny'),
    ('deny-state-echo', 'state', lambda: None, 'echo x >> %s/green-tests.tsv' % STATE_FWD, 'deny'),
    # c-940 / 0.1.2
    ('H01-cd-other-after', 'segment', lambda: None, COMMIT_FOO + '; cd %s' % fwd(OTHER), 'deny'),
    ('H01-cd-other-before-C-project', 'segment-C', lambda: None,
     'cd %s; git -C %s commit -m "x" -- scripts/foo.py' % (fwd(OTHER), fwd(PROJ)), 'deny'),
    ('H02-dir', 'expand', lambda: change(FOO), 'git commit -m "x" -- scripts', 'deny'),
    ('H02-dir-slash', 'expand', lambda: change(FOO), 'git commit -m "x" -- scripts/', 'deny'),
    ('H02-dot', 'expand', lambda: change(FOO), 'git commit -m "x" -- .', 'deny'),
    ('H02-glob', 'expand', lambda: change(FOO), "git commit -m \"x\" -- 'scripts/*.py'", 'deny'),
    ('H02-top-magic', 'expand', lambda: change(FOO), 'git commit -m "x" -- :/scripts/foo.py', 'deny'),
    ('H02-dir-green', '', lambda: (change(FOO), set_green(TEST_FOO, FOO)), 'git commit -m "x" -- scripts', 'allow'),
    ('H02-dir-unchanged', '', lambda: None, 'git commit -m "x" -- scripts', 'allow'),
    ('H02-dir-only-loose', '', lambda: change(LOOSE), 'git commit -m "x" -- scripts', 'allow'),
    ('H03-env-prefix', 'envprefix', lambda: None, 'X=1 ' + COMMIT_FOO, 'deny'),
    ('H03-then', 'start', lambda: None, 'if true; then %s; fi' % COMMIT_FOO, 'deny'),
    ('H03-command', 'start', lambda: None, 'command ' + COMMIT_FOO, 'deny'),
    ('H03-env', 'start', lambda: None, 'env ' + COMMIT_FOO, 'deny'),
    ('X-deep-nesting', 'toodeep', lambda: None, '$(' * 600 + COMMIT_FOO + ')' * 600, 'deny'),
    ('H04-heredoc-bash', 'shell-text', lambda: None, "bash <<'EOF'\n%s\nEOF" % COMMIT_FOO, 'deny'),
    ('H04-bash-c', 'shell-text', lambda: None, "bash -c '%s'" % COMMIT_FOO, 'deny'),
    ('allow-green-same-content', '', lambda: set_green(TEST_FOO, FOO), COMMIT_FOO, 'allow'),
    ('allow-newer-mtime-same-content', '',
     lambda: (set_green(TEST_FOO, FOO), set_mtime(FOO, 300)), COMMIT_FOO, 'allow'),
    ('allow-both-green', '', lambda: (set_green(TEST_FOO, FOO), set_green(TEST_BAR, BAR)),
     'git commit -m "x" -- scripts/foo.py tools/bar.ps1', 'allow'),
    ('allow-new-run-after-change', '',
     lambda: (set_green(TEST_FOO, FOO), change(FOO), set_green(TEST_FOO, FOO)), COMMIT_FOO, 'allow'),
    ('allow-git-exe-green', '', lambda: set_green(TEST_FOO, FOO),
     'git.exe commit -m "x" -- scripts/foo.py', 'allow'),
    ('allow-no-test-file', '', lambda: None, 'git commit -m "x" -- scripts/loose.py', 'allow'),
    ('allow-test-file-itself', '', lambda: None, 'git commit -m "x" -- scripts/test_foo.py', 'allow'),
    ('allow-no-commit', '', lambda: None, 'git status --short', 'allow'),
    ('allow-message-names-path', '', lambda: None,
     'git commit -m "fix in -- scripts/foo.py" -- scripts/loose.py', 'allow'),
    ('allow-other-repo', '', lambda: None,
     'git -C %s commit -m "x" -- foo.py' % OTHER.replace('\\', '/'), 'allow'),
    ('allow-state-read', '', lambda: None, 'Get-Content %s/green-tests.tsv' % STATE_FWD, 'allow'),
    ('allow-state-stderr-redirect', '', lambda: None,
     'git log --oneline -- %s/green-tests.tsv 2> err.txt' % STATE_FWD, 'allow'),
    ('allow-other-state-dir', '', lambda: None, 'mkdir /tmp/x/state 2>/dev/null', 'allow'),
    ('allow-no-json', '', lambda: None, None, 'allow'),
]

# name, group, payload, expected test path in the tsv (None = nothing recorded)
LOG = [
    ('log-python-bare', 'log', post('python scripts/test_foo.py'), TEST_FOO),
    ('log-python-self-test', 'log', post('python scripts/test_foo.py --self-test'), TEST_FOO),
    ('log-python3', 'log', post('python3 scripts/test_foo.py'), TEST_FOO),
    ('log-env-prefix', 'log', post('PYTHONIOENCODING=utf-8 python scripts/test_foo.py'), TEST_FOO),
    ('log-ps-file-self-test', 'log',
     post('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test-bar.ps1 -SelfTest'), TEST_BAR),
    ('log-ps-direct-absolute', 'log', post('& "%s"' % TEST_BAR), TEST_BAR),
    ('no-log-chain', 'bare', post('python scripts/test_foo.py; echo ok'), None),
    ('no-log-pipe', 'bare', post('python scripts/test_foo.py | tee out.txt'), None),
    ('no-log-or', 'bare', post('python scripts/test_foo.py || true'), None),
    ('no-log-redirect', 'bare', post('python scripts/test_foo.py > out.txt'), None),
    ('no-log-help', 'flag', post('python scripts/test_foo.py --help'), None),
    ('no-log-nonsense-flag', 'flag', post('python scripts/test_foo.py --nonsense-flag'), None),
    ('no-log-ps-other-flag', '',
     post('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test-bar.ps1 -Verbose'), None),
    ('no-log-echo', '', post('echo python scripts/test_foo.py'), None),
    ('no-log-failure-event', 'event', post('python scripts/test_foo.py', 'PostToolUseFailure'), None),
    ('no-log-interrupted', 'interrupted', post('python scripts/test_foo.py', 'PostToolUse', True), None),
    ('no-log-missing-file', '', post('python scripts/test_missing.py'), None),
    ('no-log-outside-project', '', post('python %s' % OUTSIDE_TEST.replace('\\', '/')), None),
    ('no-log-no-json', '', 'this is not json', None),
    # c-940 / 0.1.2
    ('H07-version-flag', 'iflag', post('python -V scripts/test_foo.py'), None),
    ('H07-help-flag', 'iflag', post('python -h scripts/test_foo.py'), None),
    ('H07-optimize', 'iflag', post('python -O scripts/test_foo.py'), None),
    ('H07-isolated-ok', 'log', post('python -I -B scripts/test_foo.py'), TEST_FOO),
    ('H07-py-launcher-ok', 'log', post('py -3 scripts/test_foo.py'), TEST_FOO),
    ('H08-own-python', 'interp', post('%s scripts/test_foo.py' % fwd(FAKE_PY)), None),
    ('H08-path-env', 'envpre', post('PATH=/tmp/nep python scripts/test_foo.py'), None),
    ('H08-pythonpath', 'envpre', post('PYTHONPATH=/tmp/x python scripts/test_foo.py'), None),
    ('H08-pythonoptimize', 'envpre', post('PYTHONOPTIMIZE=1 python scripts/test_foo.py'), None),
    ('H08-venv-ok', 'log', post('%s scripts/test_foo.py' % fwd(VENV_PY)), TEST_FOO),
    ('H09-background', 'background', post('python scripts/test_foo.py', background=True), None),
]


_SHORT = short_name(FOO)
if _SHORT:  # Windows 8.3 spelling of the source file
    GATE.append(('H02-short-name', 'shortname', lambda: change(FOO),
                 'git commit -m "x" -- %s' % fwd(_SHORT), 'deny'))


def run_gate(script, case):
    reset()
    case[2]()
    return run_hook(script, 'this is not json' if case[3] is None else pre(case[3]), ENV)


def run_log(script, case):
    reset()
    run_hook(script, case[2], ENV)
    content = open(TSV, encoding='utf-8').read() if os.path.exists(TSV) else ''
    if case[3] is None:
        return content.strip() == ''
    return (case[3] + '\t') in content


def main():
    r = Report('commit-test-gate PreToolUse: %d checks' % len(GATE))
    for c in GATE:
        got = run_gate(HOOK, c)
        r.check(c[0], got == c[4], got if got != c[4] else '')

    r.section('commit-test-gate PostToolUse: %d checks' % len(LOG))
    for c in LOG:
        r.check(c[0], run_log(HOOK, c))

    r.section('chain: record -> commit')
    reset()
    run_hook(HOOK, post('python scripts/test_foo.py'), ENV)
    d = open(TSV, encoding='utf-8').read().strip().split('\t')
    r.check('record carries hashes of test and source',
            len(d) == 6 and d[3] == sha(TEST_FOO) and d[4] == FOO and d[5] == sha(FOO), ' | '.join(d))
    r.check('commit after a real green run: allow', run_hook(HOOK, pre(COMMIT_FOO), ENV) == 'allow')
    change(FOO)
    r.check('commit after changing the source: deny', run_hook(HOOK, pre(COMMIT_FOO), ENV) == 'deny')

    if '--self-test' in sys.argv[1:]:
        r.section('self-test: break one rule at a time and demand that exactly its checks turn red')
        gate_groups = ['gate', 'content', 'variant', 'nested', 'nested-paren', 'unreadable', 'state',
                       'segment', 'segment-C', 'expand', 'start', 'envprefix', 'shell-text']
        if _SHORT:
            gate_groups.append('shortname')
        extra = [('no-realpath', 'gate', ['shortname'], '_common.py',
                  'r = os.path.realpath(p)', 'r = p')] if _SHORT else []
        mutations = [
            ('guard-always-open', 'gate', gate_groups, '_common.py',
             'sys.stdout.write(json.dumps(out))', 'return'),
            ('nested-blind', 'gate', ['nested', 'nested-paren'], '_common.py',
             "if c in '(){}':", 'if False:'),
            ('content-ignored', 'gate', ['content'], 'commit_test_gate.py',
             'if (test, sha256(test), full, sha256(full)) in good:', 'if test in seen:'),
            ('variants-blind', 'gate', ['variant'], '_common.py',
             "return w[:-4] if w.endswith('.exe') else w", 'return word'),
            # 0.1.2 (c-940)
            ('cd-ends-everything', 'gate', ['segment'], '_common.py',
             "                state['dirs'] = new\n            return",
             "                state['dirs'] = new\n                calls[:] = []\n            return"),
            ('git-C-ignored', 'gate', ['segment-C'], '_common.py',
             'dirs = _resolve_all(dirs, target) if _literal(target) else dirs | {UNKNOWN}',
             'dirs = dirs'),
            ('expansion-off', 'gate', ['expand'], 'commit_test_gate.py',
             '        if expand:\n', '        if False:\n'),
            ('wrappers-blind', 'gate', ['start'], '_common.py',
             "WRAPPERS = {'sudo',", "WRAPPERS = set() and {'sudo',"),
            ('env-prefix-blind', 'gate', ['envprefix'], '_common.py',
             "        if not quoted and ASSIGN.match(text):\n            k, v",
             "        if False:\n            k, v"),
            ('shell-text-is-documentation', 'gate', ['shell-text'], '_common.py',
             "SHELLS = {'bash',", "SHELLS = set() and {'bash',"),
            ('interp-flags-free', 'log', ['iflag'], 'commit_test_gate.py',
             "PYFLAGS = r'(?:-[IBuEsS]+\\s+)*'", "PYFLAGS = r'(?:-[A-Za-z]+\\s+)*'"),
            ('any-python', 'log', ['interp'], 'commit_test_gate.py',
             "    interp = m.group('interp')\n", '    return True\n'),
            ('any-env', 'log', ['envpre'], 'commit_test_gate.py',
             "if assign.split('=', 1)[0].upper() not in SAFE_ENV:", 'if False:'),
            ('background-counts', 'log', ['background'], 'commit_test_gate.py',
             "if (data.get('tool_input') or {}).get('run_in_background'):", 'if False:'),
            ('unreadable-allowed', 'gate', ['unreadable'], 'commit_test_gate.py',
             'if unreadable:', 'if False:'),
            ('state-threshold-off', 'gate', ['state'], 'commit_test_gate.py',
             "if re.search(r'(?i)' + re.escape(MARKER), cmd) and WRITES.search(cmd):", 'if False:'),
            ('logger-accepts-chain', 'log', ['bare'], 'commit_test_gate.py',
             "+ FLAGS_PY + r'\\s*$',", '+ FLAGS_PY,'),
            ('flags-free', 'log', ['flag'], 'commit_test_gate.py',
             "FLAGS_PY = r'(?P<args>(?:\\s+--self-test)?)'",
             "FLAGS_PY = r'(?P<args>(?:\\s+--?[A-Za-z][\\w-]*)*)'"),
            ('logger-counts-failure-event', 'log', ['event'], 'commit_test_gate.py',
             "if event == 'PostToolUse':", "if event.startswith('PostToolUse'):"),
            ('logger-ignores-interrupt', 'log', ['interrupted'], 'commit_test_gate.py',
             "if (data.get('tool_response') or {}).get('interrupted') is True:", 'if False:'),
            ('logger-writes-nothing', 'log', ['log'], 'commit_test_gate.py',
             "f.write(line + '\\n')", 'pass'),
        ]
        for mname, kind, groups, fname, old, new in mutations + extra:
            tmp, broken = mutated_copy(fname, old, new)
            if broken is None:
                r.check('self-test %s' % mname, False, 'mutation anchor not found')
                continue
            script = os.path.join(tmp, 'commit_test_gate.py')
            if kind == 'gate':
                target = [c for c in GATE if c[1] in groups]
                flipped = sum(run_gate(script, c) != c[4] for c in target)
            else:
                target = [c for c in LOG if c[1] in groups]
                flipped = sum(not run_log(script, c) for c in target)
            r.check('self-test %s' % mname, target and flipped == len(target),
                    '%d of %d checks turned red' % (flipped, len(target)))
            shutil.rmtree(tmp, ignore_errors=True)

    shutil.rmtree(ROOT, ignore_errors=True)
    r.finish()


if __name__ == '__main__':
    main()
