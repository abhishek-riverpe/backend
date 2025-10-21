#!/usr/bin/env bash
set -e

echo "[start] prisma py fetch (runtime)"
python -m prisma py fetch || true

echo "[start] locate & chmod prisma engines (recursive)"
python - <<'PY'
import os, stat, fnmatch

roots = [
    "/opt/render/.cache/prisma-python/binaries",
    "/opt/render/project/src",  # sometimes engines are symlinked here
]

patterns = [
    "*query-engine*",
    "*schema-engine*",
    "prisma-query-engine-*",
    "schema-engine-*",
]

found = []
for root in roots:
    if not os.path.exists(root):
        continue
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            for pat in patterns:
                if fnmatch.fnmatch(name, pat):
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.stat(path)
                        os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                        print("[chmod] +x", path)
                        found.append(path)
                    except Exception as e:
                        print("[chmod] skip", path, "->", e)
                    break

if not found:
    print("[warn] no prisma engines found under:", roots)
PY

echo "[start] launch uvicorn on \$PORT=${PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
