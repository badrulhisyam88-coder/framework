#!/usr/bin/env bash
# Merge the current branch's PR only after CI is green. Never merges main.
set -euo pipefail
branch=$(git rev-parse --abbrev-ref HEAD)
case "$branch" in main|master) echo "Refusing: on $branch. Use a feature branch." >&2; exit 1;; esac
git push -u origin "$branch"
gh pr view >/dev/null 2>&1 || gh pr create --fill
echo "Waiting for CI..."
gh pr checks --watch --fail-fast
gh pr merge --squash --delete-branch
