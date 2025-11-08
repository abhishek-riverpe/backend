#!/usr/bin/env bash
set -euo pipefail

echo "[start] openssl version (runtime):"
if command -v openssl >/dev/null 2>&1; then
  openssl version || true
else
  echo "openssl not found"
fi

echo "[start] ls /opt/render/.cache/prisma-python/binaries (preview):"
ls -la /opt/render/.cache/prisma-python/binaries || true

echo "[start] prisma generate (runtime)"
python -m prisma generate

echo "[start] prisma py fetch (runtime)"
python -m prisma py fetch --force

echo "[start] locate prisma engines & export env vars"
python - <<'PY'
import os, stat, fnmatch, sys

ROOTS = [
    "/opt/render/.cache/prisma-python/binaries",
    "/opt/render/project/src",
]

def find_one(patterns):
    for root in ROOTS:
        if not os.path.exists(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                for pat in patterns:
                    if fnmatch.fnmatch(name, pat):
                        return os.path.join(dirpath, name)
    return None

QUERY_PATTERNS = ["*query-engine*","prisma-query-engine-*","libquery_engine-*"]
SCHEMA_PATTERNS = ["*schema-engine*","schema-engine-*"]

def make_exec(path):
    if not path or not os.path.exists(path):
        return
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

query = find_one(QUERY_PATTERNS)
schema = find_one(SCHEMA_PATTERNS)

exports = []
if query:
    make_exec(query)
    exports.append(("PRISMA_QUERY_ENGINE_BINARY", query))
    print("[engine] query:", query)
else:
    print("[warn] query engine not found with patterns:", QUERY_PATTERNS)

if schema:
    make_exec(schema)
    exports.append(("PRISMA_SCHEMA_ENGINE_BINARY", schema))
    print("[engine] schema:", schema)
else:
    print("[warn] schema engine not found with patterns:", SCHEMA_PATTERNS)

for k, v in exports:
    print(f"::export::{k}={v}")
PY

# apply exported envs
while IFS= read -r line; do
  case "$line" in
    ::export::*)
      kv="${line#::export::}"
      key="${kv%%=*}"
      val="${kv#*=}"
      export "$key=$val"
      echo "[export] $key=$val"
      ;;
  esac
done < <(python - <<'PY'
import os, stat, fnmatch, sys

ROOTS = [
    "/opt/render/.cache/prisma-python/binaries",
    "/opt/render/project/src",
]
def find_one(patterns):
    for root in ROOTS:
        if not os.path.exists(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                for pat in patterns:
                    if fnmatch.fnmatch(name, pat):
                        return os.path.join(dirpath, name)
    return None

QUERY_PATTERNS = ["*query-engine*","prisma-query-engine-*","libquery_engine-*"]
SCHEMA_PATTERNS = ["*schema-engine*","schema-engine-*"]

def make_exec(p):
    if p and os.path.exists(p):
        st = os.stat(p)
        os.chmod(p, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

q = find_one(QUERY_PATTERNS)
s = find_one(SCHEMA_PATTERNS)
if q:
    make_exec(q); print(f"::export::PRISMA_QUERY_ENGINE_BINARY={q}")
if s:
    make_exec(s); print(f"::export::PRISMA_SCHEMA_ENGINE_BINARY={s}")
PY
)

echo "[start] print env PRISMA_QUERY_ENGINE_BINARY (if set):"
echo "${PRISMA_QUERY_ENGINE_BINARY:-<not set>}"

echo "[start] enabling prisma debug output"
export DEBUG="prisma:client"

echo "[start] launching uvicorn on \$PORT=${PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
