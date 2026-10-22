#!/usr/bin/env bash
set -euo pipefail

BIN="${1:?usage: smoke.sh path/to/netscan.exe}"
PORT="${SMOKE_PORT:-19191}"
DATA="$(mktemp -d)"
export NETSCAN_DATA_DIR="$DATA"

cat > "$DATA/config.json" <<JSON
{"http":{"addr":"127.0.0.1","port":$PORT}}
JSON

cleanup() {
  STATUS=$?
  set +e
  if [ -n "${PID:-}" ]; then
    WINPID="$(cat "/proc/$PID/winpid" 2>/dev/null)"
    if [ -n "$WINPID" ]; then
      taskkill //F //PID "$WINPID" > /dev/null 2>&1
    fi
    kill "$PID" 2>/dev/null
    for _ in $(seq 1 20); do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.25
    done
    wait "$PID" 2>/dev/null
  fi
  tail -20 "$DATA/stdout.log" 2>/dev/null
  for _ in $(seq 1 10); do
    rm -rf "$DATA" 2>/dev/null
    [ -d "$DATA" ] || break
    sleep 0.5
  done
  exit "$STATUS"
}

"$BIN" -headless -config "$DATA/config.json" > "$DATA/stdout.log" 2>&1 &
PID=$!
trap cleanup EXIT

BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 40); do
  if curl -fsS "$BASE/healthz" > /dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
curl -fsS "$BASE/healthz" | grep -q '"app":"netscan"'

curl -fsS "$BASE/" | grep -q "NetScan"
curl -fsS "$BASE/app.js" | grep -q "calcState"
curl -fsS "$BASE/api/status" | grep -q '"state_string"'
curl -fsS "$BASE/api/targets" | grep -q '"layer"'
curl -fsS "$BASE/api/events" > /dev/null

curl -fsS "$BASE/api/samples?limit=5" > /dev/null
curl -fsS "$BASE/api/export/events.csv" > /dev/null

echo "smoke ok"
