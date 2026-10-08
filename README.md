# commit-discipline

Three guards for Claude Code that turn commit discipline from a convention into something the
harness enforces. Each guard came out of a real incident, and each one ships with a self-test
that proves it can fail.

| Guard | Event | What it stops |
|---|---|---|
| **scoped-commit** | PreToolUse (Bash, PowerShell) | `git add -A / . / -u`, `git commit -a`, `git commit --amend` and any `git commit` without a `--` path list |
| **commit-test-gate** | PreToolUse + PostToolUse (Bash, PowerShell) | committing a file whose test has not run green against *exactly* the current content of file and test |
| **plan-gate** | PreToolUse (all tools except the core read tools) | anything but reading, searching and asking while in Plan Mode, and writes to the guards' own state in any mode |

No dependencies beyond Python 3.8+. Works on Windows, macOS and Linux.

## Install

```
/plugin marketplace add Kers87/commit-discipline
/plugin install commit-discipline@commit-discipline
```

Or try it locally without installing: `claude --plugin-dir /path/to/commit-discipline`.

## Why

### scoped-commit: parallel sessions share one git index

Running two or more Claude Code sessions in the same working tree is common. The git index
lives in `.git` and has no notion of a session, so `git add -A` or a bare `git commit` picks up
whatever the *other* session just staged. Seen in practice, in one afternoon:

- a commit whose message described one change carried five files of another;
- a commit carried 23 files of an unrelated sync job and zero lines of the change its message
  described. Its `git add` had collided with `.git/index.lock`; that error went to stderr while
  the rest of the command, including the commit, ran on.

No data was lost. What was lost is traceability: `git log` now claims things that are not true.

The fix is one form of commit that ignores the index entirely:

```
git add <exact path>               # only for a NEW file
git commit -m "..." -- <paths>     # commits the working tree of exactly these paths
```

This leaves another session's staged work untouched in both index and working tree, deletions
included, which also makes the index.lock race harmless instead of patched.

For a deliberate bulk commit, put `scope-ok: <reason>` in the command. The exception is then
visible in the transcript instead of silent.

### commit-test-gate: "tests pass" should be measured, not claimed

A model that says the tests pass is making a claim. This guard records the evidence itself:

- **PostToolUse.** Claude Code fires `PostToolUse` only for a shell call that exits 0 (a
  non-zero exit fires `PostToolUseFailure`). So when `PostToolUse` fires for a *bare* test call,
  that test passed. The guard then records the sha256 of the test file *and* of the source file
  it belongs to.
- **PreToolUse.** A `git commit` of `name.py` with a `test_name.py` next to it (or `name.ps1`
  with `test-name.ps1`) only goes through when there is a recorded green run with exactly the
  current content of both files.

Bare means the whole command is the test call: no `;`, `&&`, `||`, `|`, no redirect, no second
line, because otherwise the exit code belongs to the last command and not to the test. The only
flag that counts is `--self-test` (Python) or `-SelfTest` (PowerShell): `--help` also exits 0.

Content hashes, not timestamps: an mtime can be set back with one line.

A file without a test file passes. What cannot be measured is not demanded.

### plan-gate: Plan Mode by tool class, not by command

Blocking commands by pattern invites variants (`git.exe`, a full path, a capital `G`, a call
inside `{ }`; all of these slipped past an earlier version of the guards above). This guard
does not read commands at all. In Plan Mode the shell and the write tools simply do not exist:

- allowed: Read, Grep, Glob, WebFetch, WebSearch, asking questions, read-only subagents
  (Explore, Plan, claude-code-guide), MCP tools whose name carries a read verb and no write verb,
  and the plan file in `~/.claude/plans/`;
- everything else is denied, so a tool that did not exist yesterday is closed by default.

The phase is `permission_mode` from the hook input. The human sets it; the model can enter Plan
Mode but needs approval to leave it. A phase file of our own was tried first and rejected: as
soon as the model was allowed to write, it overwrote that file.

A hook deny holds in every permission mode, including `bypassPermissions` (measured).

In every mode, plan-gate also blocks Write and Edit on the guards' state directory. A model
that can write the evidence can open its own gate.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `COMMIT_DISCIPLINE_STATE_DIR` | `$CLAUDE_PLUGIN_DATA/state`, else `~/.claude/commit-discipline/state` | where green runs are recorded |
| `COMMIT_DISCIPLINE_PLANS_DIR` | `~/.claude/plans` | the one place Plan Mode may write |
| `COMMIT_DISCIPLINE_READONLY_AGENTS` | (none) | extra subagent names allowed in Plan Mode, comma-separated |

The guards act on the project in `CLAUDE_PROJECT_DIR`. A command that demonstrably drives
another repository (`git -C <path>` or `cd <path>` outside the project) is left alone.

## Limits, on purpose

- **The test gate measures that a test ran, not that it is good.** A weakened test passes too.
  Give your tests a self-test that breaks the code and demands red; this repo does that for its
  own guards.
- **Pairing is by name in the same directory** (`test_name.py` next to `name.py`). A test with a
  different name or in a separate `tests/` folder is not seen, and that file commits freely.
- **Text cannot catch git called from another program** (a Python `subprocess`, a Makefile).
  If you need that, add a git `pre-commit` hook that only acts when `CLAUDECODE=1`, which is set
  in Claude's tool shell and not in your own terminal.
- **There is no escape hatch for the model** in the test gate. Committing without a test is
  for the human, from their own terminal: hooks only apply to Claude's tool calls.
- **Shell writes to the evidence file are caught on text only**, so they can be bypassed. The
  hard block is on Write and Edit (plan-gate).
- **In Plan Mode an MCP tool without a recognisable read verb is closed**, even if it only
  reads. An unknown tool belongs closed.
- **No Python, no guard.** The launcher looks for `python3`, `python` and `py` (the Windows Store
  `python3` alias is skipped because it does not run) and fails open when none works.

## Tests

Each guard has a test next to it that runs the real hook as a subprocess, exactly as Claude
Code does. `--self-test` additionally breaks one rule at a time in a temp copy and demands that
precisely the checks guarding that rule turn red.

```
python hooks/test_scoped_commit.py --self-test
python hooks/test_commit_test_gate.py --self-test
python hooks/test_plan_gate.py --self-test
```

| Suite | Checks | Mutations |
|---|---|---|
| scoped-commit | 37 | 2 |
| commit-test-gate | 56 | 12 |
| plan-gate | 39 | 6 |

The tests follow the plugin's own naming convention, so with the plugin installed the
commit-test-gate guards this repository too.

## License

MIT
