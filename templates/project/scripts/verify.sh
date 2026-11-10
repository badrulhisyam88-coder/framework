#!/usr/bin/env bash
# Run the project's tests and checks. Exit non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
ran=0
if [ -f pyproject.toml ] || [ -f pytest.ini ] || [ -d tests ]; then
  PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
  if ls tests/test_*.py tests/**/test_*.py >/dev/null 2>&1 || ls test_*.py >/dev/null 2>&1; then
    echo "[verify] pytest"; "$PY" -m pytest -q; ran=1
  fi
fi
if [ -f package.json ] && grep -q '"test"' package.json; then
  echo "[verify] npm test"; npm test --silent; ran=1
fi
if [ "$ran" = 0 ]; then
  if git ls-files | grep -Eq '\.(py|js|ts|tsx|go|rs)$'; then
    echo "[verify] FAIL: code exists but no tests found. Write tests first." >&2; exit 1
  fi
  echo "[verify] no code yet, nothing to test"
fi
echo "[verify] OK"
