#!/usr/bin/env bash
# Run the project's tests and checks. Exit non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
SKIP=(-path ./.venv -prune -o -path ./node_modules -prune -o -path ./.git -prune -o)
has() { [ -n "$(find . "${SKIP[@]}" "$@" -print 2>/dev/null | head -1)" ]; }
ran=0
if has \( -name 'test_*.py' -o -name '*_test.py' \); then
  PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
  echo "[verify] pytest"; "$PY" -m pytest -q; ran=1
fi
if [ -f package.json ] && grep -q '"test"' package.json; then
  echo "[verify] npm test"; npm test --silent; ran=1
fi
if [ "$ran" = 0 ]; then
  if has \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.tsx' -o -name '*.go' -o -name '*.rs' \); then
    echo "[verify] FAIL: code exists but no tests found. Write tests first." >&2; exit 1
  fi
  echo "[verify] no code yet, nothing to test"
fi
echo "[verify] OK"
