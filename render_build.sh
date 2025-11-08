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

# 1) Prefer calling the prisma CLI (if installed) while passing the env var to the subprocess.
#    This guarantees the binary cache dir is set before the CLI code runs.
if command -v prisma >/dev/null 2>&1; then
  echo "[build] running: prisma py fetch --force (via prisma CLI)"
  PRISMA_PY_CACHE_DIR="$PRISMA_PY_CACHE_DIR" prisma py fetch --force
  echo "[build] running: prisma generate (via prisma CLI)"
  PRISMA_PY_CACHE_DIR="$PRISMA_PY_CACHE_DIR" prisma generate
  echo "[build] prisma fetch/generate via prisma CLI succeeded"
  exit 0
fi

# 2) If prisma CLI is not available on PATH, run the Python entrypoint in-process but ensure
#    the env var is set *before* importing prisma. Use a small Python wrapper to avoid runpy issues.
echo "[build] prisma CLI not found on PATH; falling back to python wrapper"
python - <<PY
import os, sys
os.environ['PRISMA_PY_CACHE_DIR'] = os.environ.get('PRISMA_PY_CACHE_DIR', os.path.join(os.getcwd(), '.prisma-cache'))
print("[build.py] PRISMA_PY_CACHE_DIR=", os.environ['PRISMA_PY_CACHE_DIR'], file=sys.stderr)
# import and call cli.main directly so the env is already set before any prisma module code runs
try:
    # import the click CLI object and call it like the CLI would
    from prisma.cli import cli as prisma_cli
    # prisma_cli is a click Group; pass args like ['py','fetch','--force']
    prisma_cli.main(['py', 'fetch', '--force'])
    prisma_cli.main(['generate'])
    print("[build.py] prisma fetch and generate succeeded", file=sys.stderr)
except Exception as e:
    print("[build.py] prisma fetch/generate failed:", e, file=sys.stderr)
    raise
PY
