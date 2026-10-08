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
  Recorded: sha256 of the test file AND of its source file (test_name.py -> name.py,
  test-name.ps1 -> name.ps1, same directory).
  Not measured: whether the test is any good. A weakened test passes too; a self-test that
  breaks the code and demands red is the answer to that.

PreToolUse rule 1 - a git commit of a file that has its OWN test file only goes through when
  there is a green run with EXACTLY the current content of file and test. Content hash, not
  mtime: an mtime can be set back with one line.
  A file without a test file passes: what cannot be measured is not demanded.
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
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (HEREDOC, deny, is_within, norm, project_dir, read_input,  # noqa: E402
                     sha256, state_dir, targets_other_repo)

MARKER = 'green-tests.tsv'

ENVPRE = r'(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|<>]+\s+)*'
FLAGS_PY = r'(?P<args>(?:\s+--self-test)?)'
FLAGS_PS = r'(?P<args>(?:\s+-SelfTest)?)'
FORMS = [re.compile(p, re.I) for p in (
    r'^' + ENVPRE + r'(?:[^\s;&|<>]*[\\/])?(?:python3?|py)(?:\.exe)?\s+(?:-[A-Za-z]+\s+)*'
    r'"?(?P<path>[^"\s;&|<>]*test_[A-Za-z0-9_]+\.py)"?' + FLAGS_PY + r'\s*$',
    r'^(?:&\s*)?(?:powershell|pwsh)(?:\.exe)?\s+'
    r'(?:-(?:NoProfile|NonInteractive|NoLogo)\s+|-ExecutionPolicy\s+\w+\s+)*'
    r'-File\s+"?(?P<path>[^"\s;&|<>]*test-[A-Za-z0-9_-]+\.ps1)"?' + FLAGS_PS + r'\s*$',
    r'^(?:&\s*|\.\s+)?"?(?P<path>[^"\s;&|<>]*test-[A-Za-z0-9_-]+\.ps1)"?' + FLAGS_PS + r'\s*$',
)]

GIT = r'(?i:(?:&\s*)?(?:[^\s;&|]*[\\/])?git(?:\.exe)?)'
GITOPT = r'(?:\s+-[Cc]\s+\S+|\s+--[A-Za-z][\w-]*(?:=\S+)?)*'
# A commit inside { } or ( ) counts too (an if-block or a subexpression).
START = r'(?:^|\n|;|&&|\|\||\||\{|\()\s*(?:sudo\s+)?' + GIT + GITOPT + r'\s+'

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


def record(data, cmd, project, tsv):
    """PostToolUse: append a green-run line when cmd is a bare test call."""
    if data.get('tool_name') not in ('Bash', 'PowerShell'):
        return
    if (data.get('tool_response') or {}).get('interrupted') is True:
        return
    bare = cmd.strip()
    if '\n' in bare or '\r' in bare:
        return
    path = None
    for form in FORMS:
        m = form.match(bare)
        if m:
            path = m.group('path')
            break
    if not path:
        return
    full = norm(path, base=norm(data.get('cwd')) or project)
    if not is_within(full, project) or not os.path.isfile(full):
        return
    src = source_of(full)
    src_n = norm(src) if src else '-'
    session = data.get('session_id') or 'nosession'
    line = '\t'.join([full, str(int(time.time())), session, sha256(full), src_n, sha256(src)])
    os.makedirs(os.path.dirname(tsv), exist_ok=True)
    with open(tsv, 'a', encoding='utf-8', newline='\n') as f:
        f.write(line + '\n')


def check_commit(data, cmd, project, tsv):
    """PreToolUse rule 1: every committed file with a test file needs a matching green run."""
    s = HEREDOC.sub(' ', cmd)
    s = re.sub(r'(?:-m|--message)(?:\s+|=)"[^"]*"', ' ', s)
    s = re.sub(r"(?:-m|--message)(?:\s+|=)'[^']*'", ' ', s)
    s = re.sub(r'(?:-F|--file)(?:\s+|=)\S+', ' ', s)
    s = s.replace('"', '').replace("'", '')

    other, base = targets_other_repo(s, project, case_sensitive_C=True)
    if other:
        return
    if not base:
        cwd = norm(data.get('cwd'))
        base = cwd if is_within(cwd, project) else project

    paths, unreadable = [], []
    for m in re.finditer(START + r'(?i:commit)(?=\s|$)([^\n;&|]*)', s):
        rest = m.group(1)
        if re.search(r'(?i)--pathspec-from-file', rest):
            unreadable.append(m.group(0).strip())
            continue
        pm = re.search(r'\s--\s+(.+)$', rest)
        if pm:
            paths += [p.rstrip(')}') for p in pm.group(1).strip().split() if p.rstrip(')}')]
        else:
            unreadable.append(m.group(0).strip())
    if unreadable:
        deny("commit-test-gate: cannot see which files this commit takes along ('%s'). Use "
             'git commit -m "..." -- <paths>.' % "'; '".join(unreadable))
    if not paths:
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
    for p in paths:
        full = norm(p, base=base)
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
