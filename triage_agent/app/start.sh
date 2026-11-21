#!/bin/bash
# Starts the DLP AI web app (this directory's main.py) on port 8420.
# Usage: ./start.sh
set -euo pipefail
cd "$(dirname "$0")"

PIDFILE="../dlp_ai.pid"
LOGFILE="../app.log"
PORT=8420

# Already tracked and alive?
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Already running (PID $(cat "$PIDFILE"))."
    exit 0
fi

# Untracked but already listening on 8420 (e.g. started manually)? Match the real
# python3-launched process specifically — see stop.sh for why a looser pattern can
# match a non-socket-holding wrapper process instead.
EXISTING_PID=$(pgrep -f "python3.*uvicorn main:app.*--port $PORT" | head -1 || true)
if [ -n "$EXISTING_PID" ]; then
    echo "$EXISTING_PID" > "$PIDFILE"
    echo "Found an already-running instance (PID $EXISTING_PID) not started by this script — adopted it."
    exit 0
fi

nohup ../venv/bin/uvicorn main:app --host 0.0.0.0 --port "$PORT" > "$LOGFILE" 2>&1 &
echo $! > "$PIDFILE"
disown

sleep 2
if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Started (PID $(cat "$PIDFILE")). Logs: $LOGFILE"
else
    echo "Failed to start — check $LOGFILE"
    rm -f "$PIDFILE"
    exit 1
fi
