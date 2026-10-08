#!/bin/sh
# Start a hook with the first Python 3.8+ that actually runs. On Windows `python3` is often
# the Microsoft Store alias, which exists on PATH but does not run, hence the probe.
# No usable Python: exit 0 (fail open). The README states Python 3.8+ as a requirement.
script="$(dirname -- "$0")/$1.py"
for py in python3 python py; do
  if command -v "$py" >/dev/null 2>&1 &&
     "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' </dev/null >/dev/null 2>&1; then
    exec "$py" "$script"
  fi
done
exit 0
