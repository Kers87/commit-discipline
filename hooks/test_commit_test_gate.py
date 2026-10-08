"""Tests for commit_test_gate.py, both events.

Run:  python hooks/test_commit_test_gate.py
      python hooks/test_commit_test_gate.py --self-test   (proves per rule that it CAN turn red)
Works in a throwaway project and state dir under the system temp dir.
"""

import hashlib
import os
import shutil
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


def post(cmd, event='PostToolUse', interrupted=False):
    return {'hook_event_name': event, 'tool_name': 'Bash', 'cwd': PROJ, 'session_id': 'test',
            'tool_input': {'command': cmd},
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
]


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
        gate_groups = ['gate', 'content', 'variant', 'nested', 'nested-paren', 'unreadable', 'state']
        mutations = [
            ('guard-always-open', 'gate', gate_groups, '_common.py',
             'sys.stdout.write(json.dumps(out))', 'return'),
            ('nested-blind', 'gate', ['nested', 'nested-paren'], 'commit_test_gate.py',
             r"START = r'(?:^|\n|;|&&|\|\||\||\{|\()", r"START = r'(?:^|\n|;|&&|\|\||\|)"),
            ('paren-stays-on-path', 'gate', ['nested-paren'], 'commit_test_gate.py',
             "p.rstrip(')}') for p in pm.group(1).strip().split() if p.rstrip(')}')",
             'p for p in pm.group(1).strip().split() if p'),
            ('content-ignored', 'gate', ['content'], 'commit_test_gate.py',
             'if (test, sha256(test), full, sha256(full)) in good:', 'if test in seen:'),
            ('variants-blind', 'gate', ['variant'], 'commit_test_gate.py',
             r"GIT = r'(?i:(?:&\s*)?(?:[^\s;&|]*[\\/])?git(?:\.exe)?)'", "GIT = r'git'"),
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
        for mname, kind, groups, fname, old, new in mutations:
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
