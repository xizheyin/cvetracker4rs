#!/usr/bin/env bash

# 这个脚本是用来初始化 crates.io 数据库的
set -euo pipefail

DB="${POSTGRES_DB:-crates_io}"
USER="${POSTGRES_USER:-postgres}"
DUMP_DIR="/docker-entrypoint-initdb.d/dump"

echo "[init-cratesio] Waiting for dump files in $DUMP_DIR..."
for i in {1..120}; do
  if [ -f "$DUMP_DIR/schema.sql" ] && [ -f "$DUMP_DIR/import.sql" ]; then
    break
  fi
  sleep 2
done

if [ ! -f "$DUMP_DIR/schema.sql" ] || [ ! -f "$DUMP_DIR/import.sql" ]; then
  echo "[init-cratesio] ERROR: dump files not found after waiting" >&2
  ls -la "$DUMP_DIR" || true
  exit 1
fi

# Initialize schema
echo "[init-cratesio] Restoring schema into database '$DB'..."
cd "$DUMP_DIR"
psql -v ON_ERROR_STOP=1 -U "$USER" -d "$DB" -f "schema.sql"

# Import data
echo "[init-cratesio] Importing data from dump..."
psql -v ON_ERROR_STOP=1 -U "$USER" -d "$DB" -f "import.sql"

# Optional: analyze
echo "[init-cratesio] Running VACUUM ANALYZE..."
psql -v ON_ERROR_STOP=1 -U "$USER" -d "$DB" -c "VACUUM ANALYZE;"

echo "[init-cratesio] Import completed successfully."