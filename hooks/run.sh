#!/bin/sh
# Start a hook with the first Python 3.8+ that actually runs. On Windows `python3` is often
# the Microsoft Store alias, which exists on PATH but does not run (and costs ~0.3 s to
# find that out), hence the probe and why `python` is tried first.
# No usable Python: exit 0 (fail open). The README states Python 3.8+ as a requirement.
#
# Both the probe and the hook run with -S (no site module). The hooks use only the standard
# library, and site-packages can make every start slow: a .pth file that imports a package
# (pip-system-certs imports pip) cost about 1.1 s per start on Windows. Three PreToolUse
# hooks per Bash call, each starting Python twice, then ran past the 10 s timeout under load,
# and a timed-out PreToolUse hook lets the command through.
script="$(dirname -- "$0")/$1.py"
for py in python python3 py; do
  if command -v "$py" >/dev/null 2>&1 &&
     "$py" -S -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' </dev/null >/dev/null 2>&1; then
    exec "$py" -S "$script"
  fi
done
exit 0
