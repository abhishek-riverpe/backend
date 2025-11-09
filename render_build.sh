#!/usr/bin/env bash
set -euo pipefail

# Use local cache folder inside project
PRISMA_CACHE_DIR="$(pwd)/.prisma-cache"
export PRISMA_PY_CACHE_DIR="$PRISMA_CACHE_DIR"

echo "[build] install dependencies"
pip install --no-cache-dir -U pip
pip install --no-cache-dir -r requirements.txt
pip install --no-cache-dir -U prisma

echo "[build] generate Prisma client"
python -m prisma generate --schema=./prisma/schema.prisma

echo "[build] done ✅"
