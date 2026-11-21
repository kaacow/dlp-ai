#!/bin/bash
# Stops the DLP AI web app (port 8420) started by start.sh.
# Usage: ./stop.sh
set -euo pipefail
cd "$(dirname "$0")"

PIDFILE="../dlp_ai.pid"
PORT=8420

PID=""
if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
fi
if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    # Fall back to matching the actual python3-launched uvicorn process, not just
    # any process whose command line happens to contain matching text — a `bash -c
    # "... nohup uvicorn ..."` wrapper (e.g. from a manual launch) matches
    # "uvicorn main:app...--port 8420" too, but isn't the process holding the
    # socket, so killing it silently does nothing. Requiring "python3" before
    # "uvicorn" in the pattern selects the real interpreter process. This box also
    # runs other uvicorn apps (ports 8421, 8422), so the port must stay in the
    # pattern too.
    PID=$(pgrep -f "python3.*uvicorn main:app.*--port $PORT" | head -1 || true)
fi

if [ -z "$PID" ]; then
    echo "Not running."
    rm -f "$PIDFILE"
    exit 0
fi

kill "$PID"
for i in $(seq 1 10); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 1
done
if kill -0 "$PID" 2>/dev/null; then
    echo "Still alive after 10s, force killing..."
    kill -9 "$PID"
fi

rm -f "$PIDFILE"
echo "Stopped (was PID $PID)."
