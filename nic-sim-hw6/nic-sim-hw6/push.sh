#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: ./push.sh https://github.com/<you>/nic-sim-hw6.git"
  exit 1
fi

REPO_URL="$1"

git init
git branch -M main
git add .
git commit -m "Initial import of NIC simulator project"
git remote add origin "$REPO_URL"
git push -u origin main
