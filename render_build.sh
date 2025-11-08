#!/usr/bin/env bash
set -euo pipefail

# Use an in-repo cache for prisma to avoid permission/race issues on /opt/render/.cache
PRISMA_CACHE_DIR="$(pwd)/.prisma-cache"
export PRISMA_PY_CACHE_DIR="$PRISMA_CACHE_DIR"

echo "[build] python & pip versions"
python --version || true
pip --version || true

echo "[build] upgrade pip and install dependencies"
pip install --no-cache-dir -U pip
pip install --no-cache-dir -r requirements.txt

echo "[build] ensure prisma python package is installed/updated"
pip install --no-cache-dir -U prisma

echo "[build] clear local prisma cache and recreate"
rm -rf "$PRISMA_CACHE_DIR" || true
mkdir -p "$PRISMA_CACHE_DIR"

echo "[build] PRISMA_PY_CACHE_DIR=$PRISMA_PY_CACHE_DIR"

echo "[build] fetch prisma binaries (using python module entrypoint)"
# Try the python module entrypoint (most reliable). --force ensures fresh download.
if python -m prisma.cli.cli py fetch --force; then
  echo "[build] prisma py fetch (python module) succeeded"
else
  echo "[build][error] prisma py fetch failed" >&2
  exit 1
fi

echo "[build] generate prisma client (using python module entrypoint)"
if python -m prisma.cli.cli generate; then
  echo "[build] prisma generate (python module) succeeded"
else
  echo "[build][error] prisma generate failed" >&2
  exit 1
fi

echo "[build] finished successfully"
