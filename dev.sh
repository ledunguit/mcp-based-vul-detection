#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=========================================="
echo "MCP-Vul Development Environment"
echo "=========================================="
echo ""
echo "Services:"
echo "  Frontend: http://localhost:5173"
echo "  Backend:  http://127.0.0.1:8090"
echo ""
echo "Note: MCP servers must be running in Docker"
echo "Run: docker compose -f ../docker-compose.thesis-demo.yml up memory-static-analysis dynamic-analysis"
echo ""
echo "Press Ctrl+C to stop all services"
echo "=========================================="
echo ""

# Cleanup function
cleanup() {
  echo ""
  echo "Stopping services..."
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  wait $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  echo "All services stopped"
}

trap cleanup EXIT INT TERM

# Start backend with auto-reload
echo "[Backend] Starting with auto-reload..."
watchmedo auto-restart \
  --directory=./src \
  --pattern="*.py" \
  --recursive \
  -- python -m src.memory_leak_app.server --host 127.0.0.1 --port 8090 &
BACKEND_PID=$!

# Wait a bit for backend to start
sleep 2

# Start frontend dev server
echo "[Frontend] Starting dev server..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

# Wait for both processes
wait
