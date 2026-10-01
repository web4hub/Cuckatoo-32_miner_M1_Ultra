#!/usr/bin/env bash
# run.sh — ONE command: stratum scheduler/proxy + mine34_live through it.
#
# mine34_live (the tuned baseline miner) is never modified. It connects to the scheduler instead of
# the real node. The scheduler tracks height, relays jobs, and DROPS stale submits (height advanced)
# so they never count as "too late" misses. Ctrl-C tears the whole stack down together.
#
# The siphash steer oracle was shelved (zero real-key signal -- see quarantine/dead-siphash-oracle/
# and GOAL.md). This launcher is steering-free: one concern, the baseline lane.
#
#   ./run.sh                 # mine forever through the scheduler
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR"

# --- config (env-overridable) ---
SCHED_PORT="${SCHED_PORT:-3410}"
NODE_HOST="${M1_STRATUM_HOST:-127.0.0.1}"
NODE_PORT="${M1_STRATUM_PORT:-3416}"      # the REAL node stratum port
EDGE_BITS="${EDGE_BITS:-32}"; ROUNDS="${ROUNDS:-160}"; MAXGRAPHS="${MAXGRAPHS:-0}"
LOGIN="${M1_STRATUM_LOGIN:-m1miner}"; PASS="${M1_STRATUM_PASSWORD:-x}"
SDK="$(xcrun --show-sdk-path)"

# --- build if needed (mine34_live untouched; scheduler is standalone) ---
[ -x ./mine34_live ] || make
[ -x ./scheduler/m1_scheduler ] || xcrun clang -O2 -isysroot "$SDK" -o scheduler/m1_scheduler scheduler/m1_scheduler.c

# --- preflight: real node reachable ---
if command -v nc >/dev/null 2>&1; then
  nc -z -G3 "$NODE_HOST" "$NODE_PORT" || { echo "FATAL: grin node $NODE_HOST:$NODE_PORT unreachable (node + treasury wallet up?)"; exit 1; }
fi

# --- free the proxy port (kill any stale scheduler so this run is hands-off) ---
pkill -f 'scheduler/m1_scheduler' 2>/dev/null; sleep 0.3

# --- launch scheduler (pass-through: height track + stale-submit drop) ---
echo ">> scheduler: 127.0.0.1:$SCHED_PORT -> node $NODE_HOST:$NODE_PORT"
M1_SCHED_LISTEN="$SCHED_PORT" M1_SCHED_NODE_HOST="$NODE_HOST" M1_SCHED_NODE_PORT="$NODE_PORT" \
  M1_SCHED_PIN=0 ./scheduler/m1_scheduler & SCHED_PID=$!
trap 'echo; echo ">> shutting down stack"; kill "${MINER_PID:-0}" "$SCHED_PID" 2>/dev/null; wait 2>/dev/null' INT TERM EXIT
for _ in $(seq 1 25); do (command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$SCHED_PORT" 2>/dev/null) && break; sleep 0.2; done

# --- launch the miner THROUGH the scheduler ---
echo ">> miner: ./mine34_live C$EDGE_BITS rounds=$ROUNDS maxgraphs=$MAXGRAPHS via :$SCHED_PORT"
M1_STRATUM_HOST=127.0.0.1 M1_STRATUM_PORT="$SCHED_PORT" M1_STRATUM_LOGIN="$LOGIN" M1_STRATUM_PASSWORD="$PASS" \
  ./mine34_live "$EDGE_BITS" "$ROUNDS" "$MAXGRAPHS" & MINER_PID=$!

wait "$MINER_PID"
