# Changelog

## 0.1.0 - 2026-10-08

### Added
- `scoped-commit`: refuses index-wide staging, `commit -a`, `--amend` and commits without a `--` path list; `scope-ok: <reason>` as a visible escape hatch.
- `commit-test-gate`: records green bare test runs (sha256 of test and source) on PostToolUse and refuses a commit of a file whose test has not run green against its current content.
- `plan-gate`: Plan Mode as a read-only allowlist by tool class; Write/Edit on the guards' state blocked in every mode.
- Test suites with mutation self-tests (37, 56 and 39 checks; 2, 12 and 6 mutations), CI on Ubuntu, macOS and Windows.
