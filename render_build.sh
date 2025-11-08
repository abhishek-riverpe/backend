#!/usr/bin/env bash
set -euo pipefail

# Use an in-repo cache for prisma to avoid permission/race issues on /opt/render/.cache
PRISMA_CACHE_DIR="$(pwd)/.prisma-cache"
# Export the env var so any subprocess inherits it (but we will import prisma in-process below)
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

# ---- Run the prisma fetch/generate using a Python wrapper in-process ----
# This guarantees PRISMA_PY_CACHE_DIR is set in the same process before prisma code loads.
python - <<'PY'
import os, sys
# ensure env var is present in this process
os.environ['PRISMA_PY_CACHE_DIR'] = os.environ.get('PRISMA_PY_CACHE_DIR', os.path.join(os.getcwd(), '.prisma-cache'))
print("[build.py] PRISMA_PY_CACHE_DIR =", os.environ['PRISMA_PY_CACHE_DIR'], file=sys.stderr)

try:
    # Import the CLI entry object and run it with args.
    # Import happens AFTER env var set so prisma will use our cache dir.
    from prisma.cli import cli as prisma_cli
    # Run "prisma py fetch --force"
    print("[build.py] calling prisma_cli.main(['py','fetch','--force'])", file=sys.stderr)
    prisma_cli.main(['py', 'fetch', '--force'])
    # Then run "prisma generate"
    print("[build.py] calling prisma_cli.main(['generate'])", file=sys.stderr)
    prisma_cli.main(['generate'])
    print("[build.py] prisma fetch and generate succeeded", file=sys.stderr)
except Exception:
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(2)
PY

echo "[build] finished successfully"
