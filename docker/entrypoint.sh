#!/bin/sh
set -e
# Map environment variables to CLI args for the backend (optional).
WEB_HOST="${WEB_HOST:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-8080}"
SYSLOG_HOST="${SYSLOG_HOST:-0.0.0.0}"
SYSLOG_PORT="${SYSLOG_PORT:-5514}"
DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://localhost/netwall}"
SERVE_FRONTEND="${SERVE_FRONTEND:-true}"
FRONTEND_DIR="${FRONTEND_DIR:-/app/backend/frontend_dist}"
LOG_LEVEL="${LOG_LEVEL:-info}"

exec python -m app \
  --web-host "$WEB_HOST" \
  --web-port "$WEB_PORT" \
  --syslog-host "$SYSLOG_HOST" \
  --syslog-port "$SYSLOG_PORT" \
  --database-url "$DATABASE_URL" \
  --serve-frontend \
  --frontend-dir "$FRONTEND_DIR" \
  --log-level "$LOG_LEVEL"
