#!/usr/bin/env bash
set -euo pipefail

echo "[build] python & pip versions"
python --version || true
pip --version || true

echo "[build] upgrade pip and install dependencies"
pip install --no-cache-dir -U pip
pip install --no-cache-dir -r requirements.txt

echo "[build] ensure prisma python package is up-to-date"
pip install --no-cache-dir -U prisma

echo "[build] clear prisma cache and recreate cache directory"
rm -rf /opt/render/.cache/prisma-python || true
mkdir -p /opt/render/.cache/prisma-python

echo "[build] try fetching prisma binaries (prefer python module entrypoint)"
# Try python module entrypoint first (reliable) and fallback to prisma CLI if present
if python -m prisma.cli.cli py fetch --force; then
  echo "[build] prisma py fetch (python module) succeeded"
elif prisma py fetch --force; then
  echo "[build] prisma py fetch (prisma CLI) succeeded"
elif python -m prisma py fetch --force; then
  echo "[build] prisma py fetch (python -m prisma) succeeded"
else
  echo "[build][error] prisma py fetch failed" >&2
  exit 1
fi

echo "[build] generate prisma client"
if python -m prisma.cli.cli generate; then
  echo "[build] prisma generate (python module) succeeded"
elif prisma generate; then
  echo "[build] prisma generate (prisma CLI) succeeded"
elif python -m prisma generate; then
  echo "[build] prisma generate (python -m prisma) succeeded"
else
  echo "[build][error] prisma generate failed" >&2
  exit 1
fi

echo "[build] finished successfully"
