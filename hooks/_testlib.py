"""Small test harness shared by the hook tests. Standard library only.

Each test runs the real hook as a subprocess with a JSON payload on stdin, exactly as Claude
Code does. --self-test copies the hooks to a temp dir, breaks one rule at a time and demands
that the checks guarding that rule turn red: a test suite that cannot fail proves nothing.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run_hook(script, stdin, env=None):
    """Run a hook; return 'deny' or 'allow'."""
    full_env = dict(os.environ)
    full_env.update(env or {})
    data = stdin if isinstance(stdin, str) else json.dumps(stdin)
    proc = subprocess.run([sys.executable, script], input=data.encode('utf-8'),
                          capture_output=True, env=full_env, timeout=30)
    out = proc.stdout.decode('utf-8', 'replace')
    if proc.returncode not in (0, 2):
        raise RuntimeError('hook crashed (exit %d): %s' % (proc.returncode,
                                                          proc.stderr.decode('utf-8', 'replace')))
    try:
        decision = json.loads(out)['hookSpecificOutput']['permissionDecision']
    except Exception:
        decision = None
    return 'deny' if decision == 'deny' or proc.returncode == 2 else 'allow'


class Report:
    def __init__(self, title):
        self.fails = 0
        print('== %s ==' % title)

    def check(self, name, ok, detail=''):
        print('%s  %s%s' % ('PASS' if ok else 'FAIL', name, (' (%s)' % detail) if detail else ''))
        if not ok:
            self.fails += 1

    def section(self, title):
        print('\n== %s ==' % title)

    def finish(self):
        print()
        if self.fails == 0:
            print('GREEN - all checks passed')
            sys.exit(0)
        print('RED - %d check(s) failed' % self.fails)
        sys.exit(1)


def mutated_copy(script_name, old, new):
    """Copy the hooks dir to a temp dir with one text replacement; return (dir, script path).

    Returns (dir, None) when the mutation anchor is missing, so the self-test can report it.
    """
    tmp = tempfile.mkdtemp(prefix='cd-mut-')
    for name in os.listdir(HERE):
        if name.endswith('.py'):
            shutil.copy(os.path.join(HERE, name), tmp)
    target = os.path.join(tmp, script_name)
    with open(target, encoding='utf-8') as f:
        src = f.read()
    if old not in src:
        return tmp, None
    with open(target, 'w', encoding='utf-8', newline='\n') as f:
        f.write(src.replace(old, new))
    return tmp, target
