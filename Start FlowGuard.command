#!/bin/zsh
set -eu
cd "$(dirname "$0")"
if [[ ! -x .venv/bin/python ]]; then
  echo "Run bash scripts/setup.sh in this folder first."
  read -r "?Press Enter to close."
  exit 1
fi
if .venv/bin/python -c 'import json,urllib.request; d=json.load(urllib.request.urlopen("http://127.0.0.1:8765/api/bootstrap",timeout=1)); assert "simulation_defaults" in d' >/dev/null 2>&1; then
  open "http://127.0.0.1:8765/"
  echo "FlowGuard is already running at http://127.0.0.1:8765/"
  exit 0
fi
echo "Starting FlowGuard. Keep this terminal open during your presentation."
echo "Press Control+C to stop the dashboard."
.venv/bin/python demo/server.py &
flowguard_pid=$!
trap 'kill "$flowguard_pid" 2>/dev/null || true' EXIT INT TERM
for attempt in {1..40}; do
  if .venv/bin/python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8765/api/bootstrap",timeout=0.25)' >/dev/null 2>&1; then
    open "http://127.0.0.1:8765/"
    break
  fi
  if ! kill -0 "$flowguard_pid" 2>/dev/null; then
    echo "The local server exited. Check the error above."
    read -r "?Press Enter to close."
    exit 1
  fi
  sleep 0.2
done
wait "$flowguard_pid"
