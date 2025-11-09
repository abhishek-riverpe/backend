#!/usr/bin/env bash
set -euo pipefail

echo "[start] checking openssl version..."
openssl version -a || true

# Ensure Prisma cache directory exists and is writable
export PRISMA_PY_CACHE_DIR="$(pwd)/.prisma-cache"
mkdir -p "$PRISMA_PY_CACHE_DIR"

echo "[start] regenerating Prisma client to ensure correct binary for Render"
python -m prisma generate --schema=./prisma/schema.prisma || true

echo "[start] starting FastAPI app"
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
