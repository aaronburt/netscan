#!/usr/bin/env bash
set -euo pipefail

BIN="${1:?usage: smoke.sh path/to/netscan.exe}"
PORT="${SMOKE_PORT:-19191}"
DATA="$(mktemp -d)"
export NETSCAN_DATA_DIR="$DATA"

cat > "$DATA/config.json" <<JSON
{"http":{"addr":"127.0.0.1","port":$PORT}}
JSON

"$BIN" -headless -config "$DATA/config.json" > "$DATA/stdout.log" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; cat "$DATA/stdout.log" 2>/dev/null | tail -20; rm -rf "$DATA"' EXIT

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
