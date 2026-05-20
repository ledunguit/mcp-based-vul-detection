#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "Starting backend with auto-reload..."
echo "Backend will restart when Python files change in src/"
echo ""

watchmedo auto-restart \
  --directory=./src \
  --pattern="*.py" \
  --recursive \
  -- python -m src.memory_leak_app.server --host 127.0.0.1 --port 8090
