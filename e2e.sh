#!/usr/bin/env bash
# End-to-end smoke test: backend + WAF (enforce mode) + all four traffic scenarios.
# Usage: scripts/e2e.sh [duration_s] [extra SENTINEL_* env assignments...]
#   scripts/e2e.sh 40
#   scripts/e2e.sh 40 SENTINEL_MODEL_PATH=models/behavior.json SENTINEL_BEHAVIOR_THRESHOLD=0.4
set -u
cd "$(dirname "$0")/.."
D="${1:-40}"; shift || true
OUT="$(mktemp -d)"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT

setsid nohup uvicorn backend.app:app --port 9000 --log-level warning >"$OUT/backend.log" 2>&1 </dev/null &
PIDS+=($!)
env SENTINEL_UPSTREAM_URL=http://127.0.0.1:9000 SENTINEL_TRUST_FORWARDED_FOR=true \
    SENTINEL_SECRET=dev-only "$@" \
    setsid nohup uvicorn sentinel.main:app_factory --factory --port 8080 --log-level warning \
    >"$OUT/waf.log" 2>&1 </dev/null &
PIDS+=($!)
sleep 3
curl -sf localhost:8080/_sentinel/health >/dev/null || { echo "WAF failed to start"; cat "$OUT/waf.log"; exit 1; }

python -m simulate.attacks http://localhost:8080 > "$OUT/attacks.out" 2>&1
python -m simulate.legit      --clients 25 --duration "$D" > "$OUT/legit.out" 2>&1 &  P1=$!
python -m simulate.graymarket --clients 20 --duration "$D" --evasion basic  > "$OUT/gray.out"  2>&1 &  P2=$!
python -m simulate.graymarket --clients 15 --duration "$D" --evasion assets > "$OUT/gray2.out" 2>&1 &  P3=$!
python -m simulate.flood      --clients 4  --duration 8 > "$OUT/flood.out" 2>&1
wait $P1 $P2 $P3

tail -1 "$OUT/attacks.out"
for f in legit gray gray2 flood; do tr '\n' ' ' < "$OUT/$f.out" | sed 's/  */ /g'; echo; done
curl -s localhost:8080/_sentinel/api/metrics | python -c "import sys,json; m=json.load(sys.stdin); print('totals', m['totals'], 'by_detector', m['by_detector'], 'final threshold', m['current_threshold'])"
