#!/bin/bash
# Starts the DLP AI Console (this directory's main.py) on port 8424.
# Usage: ./start.sh
set -euo pipefail
cd "$(dirname "$0")"

PIDFILE="../dlp_console.pid"
LOGFILE="../app.log"
PORT=8424

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Already running (PID $(cat "$PIDFILE"))."
    exit 0
fi

# Match the real python3-launched process specifically — a looser pattern can
# match a non-socket-holding wrapper process instead (see stop.sh).
EXISTING_PID=$(pgrep -f "python3.*uvicorn main:app.*--port $PORT" | head -1 || true)
if [ -n "$EXISTING_PID" ]; then
    echo "$EXISTING_PID" > "$PIDFILE"
    echo "Found an already-running instance (PID $EXISTING_PID) not started by this script — adopted it."
    exit 0
fi

# The Mail Exfil feature's Exchange automation launches a real (non-headless)
# browser via Playwright, which needs a working X display — it can't run
# headless because Exchange webmail's UI automation was built/tuned against a
# real rendered window. DISPLAY defaults to :0, the logged-in
# graphical session on this box (confirmed via the old standalone service's
# process environment) — without exporting it here, a plain SSH+nohup start
# has no DISPLAY at all and every Exchange run fails with "Missing X server".
export DISPLAY="${DISPLAY:-:0}"
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
