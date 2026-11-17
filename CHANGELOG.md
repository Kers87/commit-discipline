# Changelog

## 0.1.2 - 2026-11-17

Repairs from an outside review of 0.1.1 (findings H-01 to H-11). Every repair has a check in
the self-test that is red on 0.1.1 and green now.

### Fixed
- A `cd` or `git -C` to another repository anywhere in a command switched both commit guards
  off for the whole command; `git add -A; cd /tmp` went through. Both guards now read the
  command per segment and only leave a git call alone when every directory it can run in lies
  outside the project (H-01). Git Bash paths (`/c/...`) are read as the Windows paths they
  are; before, `cd /c/<project>` counted as another repository.
- The test gate skipped every path list item that was not a plain existing file, so
  `git commit -m x -- scripts` committed tested files without evidence. Directories, globs and
  pathspec magic are now expanded by asking git which tracked files under them changed; an
  8.3 file name is resolved to its long name (H-02).
- A git call after `VAR=x`, `then`, `do`, `command`, `env`, `!`, inside `$( )` or backticks
  was not seen (H-03).
- Script text that goes to a shell was treated as documentation: a heredoc fed to `bash`,
  `sh -c '...'`, `powershell -Command` and `-EncodedCommand`, `eval`. It is now read as
  commands; a heredoc fed to `cat` stays text (H-04).
- scoped-commit missed `git stage`, global options before the subcommand (`--no-pager`),
  abbreviated long options (`--amen`, `--al`, `--upd`), clusters like `-vA`, and `--git-dir`.
  `git commit -i` (also commits the index) is refused too (H-05).
- Whole-tree pathspecs passed as a path list: `git add ./`, `:/`, `*`, `git commit -- .`,
  `:(top)`, a glob, the project root (H-06).
- A green run was recorded without the test having run: interpreter flags `-V`, `-h`, `-O`
  (H-07), a file named `python` in an arbitrary folder or an env prefix such as `PATH=`,
  `PYTHONPATH=`, `PYTHONOPTIMIZE=` (H-08), and a call started with `run_in_background` (H-09).
  Only `-I -B -u -E -s -S` and `py -3.x` count as flags, the interpreter is a bare
  `python`/`python3`/`py` or one inside a venv, and the env prefix is limited to variables that
  change output only.
- plan-gate compared the state directory as text, so an 8.3 name, a `\\?\` prefix or
  `\\localhost\C$` for the same directory could be written. The path is now also compared on
  disk (H-10).
- SendMessage was allowed in Plan Mode and skipped by the hook matcher; it continues an agent
  that may write (H-11).

### Changed
- The two commit guards share one reading of a shell command (`git_calls` in `_common.py`)
  instead of two regexes that disagreed on what a git call is.
- Self-tests: 86, 84 and 44 checks; 2, 22 and 8 mutations.

## 0.1.1 - 2026-11-14

### Fixed
- Hooks timed out under load on Windows, and a timed-out PreToolUse hook lets the command through. Measured cause: every hook started Python twice (probe and run), and a `.pth` file in site-packages (pip-system-certs imports pip) added about 1.1 s to each start. `run.sh` now starts the probe and the hook with `python -S` and tries `python` before `python3` (the Store alias costs ~0.3 s to rule out). Measured per hook: 2.6-3.6 s before, about 0.65 s after.

### Changed
- Hook timeout 10 s to 30 s, as a safety margin.
- The test harness runs the hooks with `-S` too, so CI proves they work without the site module.

## 0.1.0 - 2026-10-08

### Added
- `scoped-commit`: refuses index-wide staging, `commit -a`, `--amend` and commits without a `--` path list; `scope-ok: <reason>` as a visible escape hatch.
- `commit-test-gate`: records green bare test runs (sha256 of test and source) on PostToolUse and refuses a commit of a file whose test has not run green against its current content.
- `plan-gate`: Plan Mode as a read-only allowlist by tool class; Write/Edit on the guards' state blocked in every mode.
- Test suites with mutation self-tests (37, 56 and 39 checks; 2, 12 and 6 mutations), CI on Ubuntu, macOS and Windows.
