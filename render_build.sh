#!/usr/bin/env bash
set -euo pipefail

# Use an in-repo cache for prisma to avoid permission/race issues on /opt/render/.cache
PRISMA_CACHE_DIR="$(pwd)/.prisma-cache"
export PRISMA_PY_CACHE_DIR="$PRISMA_CACHE_DIR"

echo "[build] python & pip versions"
python --version || true
pip --version || true

echo "[build] install/upgrade Python dependencies"
pip install --no-cache-dir -U pip
pip install --no-cache-dir -r requirements.txt

echo "[build] ensure prisma python package is installed/updated"
pip install --no-cache-dir -U prisma

echo "[build] clear local prisma cache and recreate"
rm -rf "$PRISMA_CACHE_DIR" || true
mkdir -p "$PRISMA_CACHE_DIR"
echo "[build] PRISMA_PY_CACHE_DIR=$PRISMA_PY_CACHE_DIR"

# Debug: show which prisma binary is on PATH (if any) and its version
echo "[build] which prisma (if any):"
if command -v prisma >/dev/null 2>&1; then
  command -v prisma || true
  echo "[build] prisma --version output:"
  prisma --version || true
else
  echo "[build] prisma not found on PATH"
fi

# ---- Run prisma generate as a subprocess using the Python module entrypoint ----
# Use sys.executable -m prisma.cli.cli to guarantee we run the python package's CLI,
# in a separate process where our PRISMA_PY_CACHE_DIR env var is already set.
echo "[build] running: python -m prisma.cli.cli generate (subprocess)"
if python -m prisma.cli.cli generate; then
  echo "[build] prisma generate (python -m prisma.cli.cli) succeeded"
else
  echo "[build] python -m prisma.cli.cli generate failed; trying prisma generate (executable) as fallback" >&2
  if command -v prisma >/dev/null 2>&1; then
    PRISMA_PY_CACHE_DIR="$PRISMA_PY_CACHE_DIR" prisma generate
    echo "[build] prisma generate (prisma CLI) succeeded"
  else
    echo "[build][error] prisma generate failed and no prisma CLI found as fallback" >&2
    exit 1
  fi
fi

echo "[build] finished successfully"
