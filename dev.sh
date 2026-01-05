#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"
source venv/bin/activate

PORT=8001

echo "➡️  Freeing port $PORT (if needed)..."
lsof -ti tcp:$PORT | xargs kill -9 2>/dev/null || true

echo "✅ Starting PhishWatch on http://127.0.0.1:$PORT"
exec uvicorn app.main:app --reload --host 127.0.0.1 --port $PORT
