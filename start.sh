#!/usr/bin/env bash
set -e

# 1) Ensure the Linux engine is present at runtime (cache-safe)
python -m prisma py fetch || true

# 2) Print engine paths and force executable bit (Prisma 0.15.0 API)
python - <<'PY'
import os, stat
from prisma.engine._query import BINARY_PATHS

paths = [BINARY_PATHS.query_engine, BINARY_PATHS.schema_engine]
print("Prisma engine candidates:", paths)

for p in paths:
    if p and os.path.exists(p):
        st = os.stat(p)
        os.chmod(p, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print("Made executable:", p)
    else:
        print("Not found:", p)
PY

# 3) Start the server (bind to $PORT so Render detects it)
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"