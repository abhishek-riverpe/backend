#!/usr/bin/env bash
set -e

echo "[start] prisma py fetch (runtime)"
python -m prisma py fetch || true

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

query = find_one(["*query-engine*", "prisma-query-engine-*"])
schema = find_one(["*schema-engine*", "schema-engine-*"])

def make_exec(path):
    if not path or not os.path.exists(path):
        return
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

if query:
    make_exec(query)
    print("[engine] query:", query)
    print(f'::export::PRISMA_QUERY_ENGINE_BINARY={query}')
else:
    print("[warn] query engine not found")

if schema:
    make_exec(schema)
    print("[engine] schema:", schema)
    print(f'::export::PRISMA_SCHEMA_ENGINE_BINARY={schema}')
else:
    print("[warn] schema engine not found")
PY

# Read the "::export::KEY=VALUE" lines and export them
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

def make_exec(path):
    if not path or not os.path.exists(path):
        return
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

query = find_one(["*query-engine*", "prisma-query-engine-*"])
schema = find_one(["*schema-engine*", "schema-engine-*"])

if query:
    make_exec(query)
    print(f"::export::PRISMA_QUERY_ENGINE_BINARY={query}")
if schema:
    make_exec(schema)
    print(f"::export::PRISMA_SCHEMA_ENGINE_BINARY={schema}")
PY
)

echo "[start] launch uvicorn on \$PORT=${PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
