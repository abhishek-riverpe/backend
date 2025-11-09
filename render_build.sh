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

# ---- Run prisma generate directly via Python ----
python - <<'PY'
import os, sys
os.environ['PRISMA_PY_CACHE_DIR'] = os.environ.get('PRISMA_PY_CACHE_DIR', os.path.join(os.getcwd(), '.prisma-cache'))
print("[build.py] PRISMA_PY_CACHE_DIR =", os.environ['PRISMA_PY_CACHE_DIR'], file=sys.stderr)

try:
    from prisma.cli import cli as prisma_cli
    # Only run generate (fetch is no longer needed)
    print("[build.py] calling prisma_cli.main(['generate'])", file=sys.stderr)
    prisma_cli.main(['generate'])
    print("[build.py] prisma generate succeeded", file=sys.stderr)
except Exception:
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(2)
PY

echo "[build] finished successfully"
