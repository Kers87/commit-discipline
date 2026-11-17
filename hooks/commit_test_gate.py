"""commit-test-gate: PreToolUse + PostToolUse guard (matcher Bash|PowerShell).

A commit requires a MEASURED green test instead of a claimed one.

PostToolUse - record a green test.
  A shell call that exits 0 fires PostToolUse; a non-zero exit fires PostToolUseFailure. So
  when PostToolUse fires for a BARE test call, that test passed. Bare means the whole command
  is the test call: no chain (; && || |), no redirect, no second line - otherwise the exit code
  belongs to the last command, not to the test.
  Recognised: python tests/test_x.py, powershell ... -File test-x.ps1, & "path/test-x.ps1".
  Flags: only --self-test (python) or -SelfTest (PowerShell). Any other flag does not count:
  --help also exits 0 without testing anything.
  Since 0.1.2 the call must also really run the test:
  - interpreter flags only from -I -B -u -E -s -S (and py -3.x); -V, -h, -O, -c, -m do not
    count, because they exit 0 without running the test or strip its asserts;
  - the interpreter is a bare python/python3/py, or one inside a venv (pyvenv.cfg next to its
    Scripts or bin folder); a file named python anywhere else can be anything that exits 0;
  - an env prefix only with variables from SAFE_ENV (PATH, PYTHONPATH, PYTHONOPTIMIZE and the
    like change what runs);
  - not started in the background (run_in_background exits 0 before the test ran).
  Recorded: sha256 of the test file AND of its source file (test_name.py -> name.py,
  test-name.ps1 -> name.ps1, same directory).
  Not measured: whether the test is any good. A weakened test passes too; a self-test that
  breaks the code and demands red is the answer to that.

PreToolUse rule 1 - a git commit of a file that has its OWN test file only goes through when
  there is a green run with EXACTLY the current content of file and test. Content hash, not
  mtime: an mtime can be set back with one line.
  A file without a test file passes: what cannot be measured is not demanded.
  A path list item that is not a plain file (a directory, a glob, :/ or other pathspec magic)
  is expanded by asking git which tracked files under it differ from HEAD (0.1.2); before,
  such an item was skipped and `-- scripts` committed tested files without evidence.
  A commit the guard cannot parse (no -- path list, --pathspec-from-file) is refused: what
  cannot be seen does not go through.
  No escape hatch for the model. Committing without a test is for the human, from their own
  terminal: hooks only apply to Claude's tool calls.
PreToolUse rule 2 - a shell command that names the evidence file AND writes is refused.
  Text-based and therefore bypassable; plan_gate blocks Write/Edit on the state dir.

State: <state dir>/green-tests.tsv, one TAB-separated line per green run:
  <test path> <unix time> <session> <sha256 test> <source path or -> <sha256 source or ->
"""

import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (COMMIT_VALUE_LONG, COMMIT_VALUE_SHORT, deny, git_calls,  # noqa: E402
                     is_within, norm, project_dir, read_input, sha256, shell_of, split_args,
                     state_dir)

MARKER = 'green-tests.tsv'

# Environment a test run may carry: variables that change output, not which code runs.
# PATH, PYTHONPATH, PYTHONHOME, PYTHONOPTIMIZE and the like decide WHAT runs.
SAFE_ENV = {'PYTHONIOENCODING', 'PYTHONUTF8', 'PYTHONUNBUFFERED', 'PYTHONDONTWRITEBYTECODE',
            'PYTHONHASHSEED', 'PYTHONWARNINGS', 'PYTHONFAULTHANDLER', 'LANG', 'LC_ALL',
            'LC_CTYPE', 'NO_COLOR', 'FORCE_COLOR', 'TERM', 'COLUMNS', 'TZ', 'CI'}
ENVPRE = r'(?P<env>(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|<>]+\s+)*)'
# Interpreter flags that leave the test as it is: -V and -h exit 0 without running anything,
# -O strips every assert, -c and -m run something else. Only these letters count.
PYFLAGS = r'(?:-[IBuEsS]+\s+)*'
FLAGS_PY = r'(?P<args>(?:\s+--self-test)?)'
FLAGS_PS = r'(?P<args>(?:\s+-SelfTest)?)'
FORMS = [re.compile(p, re.I) for p in (
    r'^' + ENVPRE + r'(?P<interp>(?:[^\s;&|<>]*[\\/])?(?:python(?:3(?:\.[0-9]+)?)?|py)(?:\.exe)?)\s+'
    r'(?:-3(?:\.[0-9]+)?(?:-(?:32|64))?\s+)?' + PYFLAGS +
    r'"?(?P<path>[^"\s;&|<>]*test_[A-Za-z0-9_]+\.py)"?' + FLAGS_PY + r'\s*$',
    r'^(?:&\s*)?(?:powershell|pwsh)(?:\.exe)?\s+'
    r'(?:-(?:NoProfile|NonInteractive|NoLogo)\s+|-ExecutionPolicy\s+\w+\s+)*'
    r'-File\s+"?(?P<path>[^"\s;&|<>]*test-[A-Za-z0-9_-]+\.ps1)"?' + FLAGS_PS + r'\s*$',
    r'^(?:&\s*|\.\s+)?"?(?P<path>[^"\s;&|<>]*test-[A-Za-z0-9_-]+\.ps1)"?' + FLAGS_PS + r'\s*$',
)]

WRITES = re.compile(r'(?i)(Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|'
                    r'Move-Item|Clear-Content|WriteAll|AppendAll|\btee\b|\bcp\b|\bmv\b|\brm\b|'
                    r'\btouch\b|sed\s+-i|(?<![0-9-])>)')


def source_of(test):
    """test_name.py -> name.py, test-name.ps1 -> name.ps1 (same directory)."""
    d, name = os.path.split(test)
    m = re.match(r'^test_(.+\.py)$', name, re.I) or re.match(r'^test-(.+\.ps1)$', name, re.I)
    return os.path.join(d, m.group(1)) if m else None


def test_of(path):
    """name.py -> test_name.py, name.ps1 -> test-name.ps1; None for test files themselves."""
    d, name = os.path.split(path)
    stem, ext = os.path.splitext(name)
    if ext.lower() == '.py' and not name.lower().startswith('test_'):
        return os.path.join(d, 'test_' + stem + '.py')
    if ext.lower() == '.ps1' and not name.lower().startswith('test-'):
        return os.path.join(d, 'test-' + stem + '.ps1')
    return None


def trusted_python(m, cwd):
    """True when the matched test call runs a real Python on the test (H-08).

    The environment prefix may only carry SAFE_ENV variables. The interpreter is a bare name
    (python, python3, py, found on PATH) or one inside a virtual environment: <venv>/Scripts or
    <venv>/bin with a pyvenv.cfg in <venv>. A file named python in a folder of its own does
    not count: it can be anything that exits 0.
    """
    for assign in (m.group('env') or '').split():
        if assign.split('=', 1)[0].upper() not in SAFE_ENV:
            return False
    interp = m.group('interp')
    if not re.search(r'[\\/]', interp):
        return True
    full = norm(interp, base=cwd)
    if not full or not os.path.isfile(full):
        return False
    bindir = os.path.dirname(full)
    venv = os.path.dirname(bindir)
    return (os.path.basename(bindir).lower() in ('scripts', 'bin')
            and os.path.isfile(os.path.join(venv, 'pyvenv.cfg')))


def record(data, cmd, project, tsv):
    """PostToolUse: append a green-run line when cmd is a bare test call."""
    if data.get('tool_name') not in ('Bash', 'PowerShell'):
        return
    if (data.get('tool_response') or {}).get('interrupted') is True:
        return
    # A background start exits 0 at once, before the test has run (H-09).
    if (data.get('tool_input') or {}).get('run_in_background'):
        return
    bare = cmd.strip()
    if '\n' in bare or '\r' in bare:
        return
    cwd = norm(data.get('cwd')) or project
    path = None
    for form in FORMS:
        m = form.match(bare)
        if m:
            if 'interp' in m.groupdict() and not trusted_python(m, cwd):
                return
            path = m.group('path')
            break
    if not path:
        return
    full = norm(path, base=cwd)
    if not is_within(full, project) or not os.path.isfile(full):
        return
    src = source_of(full)
    src_n = norm(src) if src else '-'
    session = data.get('session_id') or 'nosession'
    line = '\t'.join([full, str(int(time.time())), session, sha256(full), src_n, sha256(src)])
    os.makedirs(os.path.dirname(tsv), exist_ok=True)
    with open(tsv, 'a', encoding='utf-8', newline='\n') as f:
        f.write(line + '\n')


def changed_files(base, specs):
    """The files a `git commit -- <specs>` takes along, asked from git itself (H-02): the
    tracked files under those pathspecs that differ from HEAD. None when git cannot tell (no
    git, no HEAD, a bad pathspec): the caller then refuses, because what cannot be seen does
    not go through."""
    try:
        top = subprocess.run(['git', '-C', base, 'rev-parse', '--show-toplevel'],
                             capture_output=True, timeout=10)
        diff = subprocess.run(['git', '-C', base, '-c', 'core.quotepath=off', 'diff',
                               '--name-only', '-z', '--no-renames', 'HEAD', '--'] + specs,
                              capture_output=True, timeout=20)
    except Exception:
        return None
    if top.returncode != 0 or diff.returncode != 0:
        return None
    root = top.stdout.decode('utf-8', 'replace').strip()
    names = [n for n in diff.stdout.decode('utf-8', 'replace').split('\0') if n]
    return [norm(os.path.join(root, n)) for n in names]


def check_commit(data, cmd, project, tsv):
    """PreToolUse rule 1: every committed file with a test file needs a matching green run."""
    calls = [c for c in git_calls(cmd, project, norm(data.get('cwd')), shell_of(data))
             if c.in_project and c.sub == 'commit']

    files, unreadable = [], []          # files: (as written, canonical path)
    for call in calls:
        opts, specs, dd = split_args(call.args, COMMIT_VALUE_SHORT, COMMIT_VALUE_LONG)
        if any(o.startswith('--pathspec-f') for o in opts) or not dd or not specs:
            unreadable.append(call.text())
            continue
        expand = []
        for t, _ in specs:
            full = norm(t, base=call.base)
            plain = not t.startswith(':') and not re.search(r'[*?\[]', t)
            if plain and full and os.path.isfile(full):
                files.append((t, full))
            elif plain and full and not os.path.exists(full):
                continue                # a deleted file: nothing to test
            else:
                expand.append(t)        # a directory, a glob, pathspec magic
        if expand:
            changed = changed_files(call.base, expand)
            if changed is None:
                unreadable.append(call.text())
            else:
                files += [(os.path.relpath(f, project), f) for f in changed]
    if unreadable:
        deny("commit-test-gate: cannot see which files this commit takes along ('%s'). Use "
             'git commit -m "..." -- <paths>.' % "'; '".join(unreadable))
    if not files:
        return

    good, seen = set(), set()
    if os.path.isfile(tsv):
        with open(tsv, encoding='utf-8') as f:
            for line in f:
                d = line.rstrip('\n').split('\t')
                if len(d) >= 6:
                    seen.add(d[0])
                    good.add((d[0], d[3], d[4], d[5]))

    blocked = []
    for p, full in files:
        if not is_within(full, project) or not os.path.isfile(full):
            continue
        test = test_of(full)
        if not test or not os.path.isfile(test):
            continue
        rel = os.path.relpath(test, project)
        if (test, sha256(test), full, sha256(full)) in good:
            continue
        if test in seen:
            blocked.append('%s (file or test changed since the last green run of %s)' % (p, rel))
        else:
            blocked.append('%s (test %s has not run green yet)' % (p, rel))
    if blocked:
        deny('commit-test-gate: refused for %s. Run the test green first as a bare command, '
             'without chaining, redirects or flags other than --self-test / -SelfTest (e.g. '
             'python tests/test_x.py), then commit again. Committing without a test is for '
             'the human, from their own terminal.' % '; '.join(blocked))


def main():
    data = read_input()
    if data is None:
        return
    event = data.get('hook_event_name')
    cmd = (data.get('tool_input') or {}).get('command')
    if not isinstance(cmd, str) or not cmd.strip():
        return
    project = project_dir(data)
    tsv = os.path.join(state_dir(), MARKER)

    if event == 'PostToolUse':
        try:
            record(data, cmd, project, tsv)
        except Exception:
            pass
        return
    if event != 'PreToolUse':
        return

    # Rule 2: no shell writes into the evidence file.
    if re.search(r'(?i)' + re.escape(MARKER), cmd) and WRITES.search(cmd):
        deny('commit-test-gate: this command writes to %s. That file is the evidence of green '
             'test runs; only the hook itself writes it.' % MARKER)

    # Rule 1.
    try:
        check_commit(data, cmd, project, tsv)
    except SystemExit:
        raise
    except Exception:
        return


if __name__ == '__main__':
    main()
