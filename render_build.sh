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

echo "[build] try fetching prisma binaries (try python module entrypoint then prisma CLI)"
if python -m prisma.cli.cli py fetch --force; then
  echo "[build] prisma py fetch via python module succeeded"
elif command -v prisma && prisma py fetch --force; then
  echo "[build] prisma py fetch via prisma CLI succeeded"
elif python -m prisma py fetch --force; then
  echo "[build] prisma py fetch via python -m prisma succeeded"
else
  echo "[build][error] prisma py fetch failed" >&2
  exit 1
fi

echo "[build] generate prisma client (try python module then prisma CLI)"
if python -m prisma.cli.cli generate; then
  echo "[build] prisma generate via python module succeeded"
elif command -v prisma && prisma generate; then
  echo "[build] prisma generate via prisma CLI succeeded"
elif python -m prisma generate; then
  echo "[build] prisma generate via python -m prisma succeeded"
else
  echo "[build][error] prisma generate failed" >&2
  exit 1
fi

echo "[build] finished successfully"
