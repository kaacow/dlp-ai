#!/bin/bash
# Stops the DLP AI Console (port 8424) started by start.sh.
# Usage: ./stop.sh
set -euo pipefail
cd "$(dirname "$0")"

PIDFILE="../dlp_console.pid"
PORT=8424

PID=""
if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
fi
if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    # Fall back to matching the actual python3-launched uvicorn process, not just
    # any process whose command line happens to contain matching text — a `bash -c
    # "... nohup uvicorn ..."` wrapper matches "uvicorn main:app...--port 8424" too,
    # but isn't the process holding the socket, so killing it silently does nothing.
    # Requiring "python3" before "uvicorn" selects the real interpreter process.
    # This box also runs other uvicorn apps on other ports, so the port must stay
    # in the pattern too.
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
