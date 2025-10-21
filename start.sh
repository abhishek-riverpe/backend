#!/usr/bin/env bash
# Fail on pipeline errors but not on our optional python helper
set -e

echo "[start] prisma py fetch at runtime (cache-safe)"
python -m prisma py fetch || true

echo "[start] try to chmod prisma engines (best-effort)"
python - <<'PY'
import os, stat, sys

def safe_chmod(path: str):
    try:
        if path and os.path.exists(path):
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            print("[chmod] made executable:", path)
        else:
            print("[chmod] not found:", path)
    except Exception as e:
        print("[chmod] skipping:", e)

# Try the exact paths prisma logs usually reference on Render
candidates = [
    "/opt/render/project/src/prisma-query-engine-debian-openssl-3.0.x",
    "/opt/render/.cache/prisma-python/binaries/5.17.0/393aa359c9ad4a4bb28630fb5613f9c281cde053/prisma-query-engine-debian-openssl-3.0.x",
    "/opt/render/.cache/prisma-python/binaries/5.17.0/393aa359c9ad4a4bb28630fb5613f9c281cde053/node_modules/prisma/query-engine-debian-openssl-3.0.x",
]

# Also try to introspect paths via prisma internals, but don't fail if it changes
try:
    # prisma 0.15.x sometimes exposes this import path in stacktraces
    from prisma.engine import utils as _utils
    try:
        from prisma.engine._query import BINARY_PATHS as _BP
        candidates.append(getattr(_BP, "query_engine", None))
        candidates.append(getattr(_BP, "schema_engine", None))
    except Exception as e:
        print("[introspect] could not import BINARY_PATHS:", e)
except Exception as e:
    print("[introspect] prisma internals not available:", e)

# De-dup while preserving order
seen = set()
deduped = []
for p in candidates:
    if p and p not in seen:
        deduped.append(p)
        seen.add(p)

for p in deduped:
    safe_chmod(p)

sys.exit(0)
PY

echo "[start] launching uvicorn on \$PORT=${PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
