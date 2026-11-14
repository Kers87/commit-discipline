# Changelog

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
