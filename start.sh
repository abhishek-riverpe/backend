#!/usr/bin/env bash
set -e

# 1) Ensure the engine exists at runtime (caches aren’t guaranteed)
python -m prisma py fetch || true

# 2) Force the query engine to be executable
python - <<'PY'
import os, stat
from prisma.engine.paths import BINARY_PATHS
p = BINARY_PATHS.query_engine
print("Prisma query engine:", p)
try:
    st = os.stat(p)
    os.chmod(p, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print("Made executable.")
except FileNotFoundError:
    print("Engine file not found at runtime.")
PY

# 3) Start your API (bind to $PORT!)
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
