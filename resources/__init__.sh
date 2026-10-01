#!/usr/bin/env bash
# start.sh: launch the mining stack in a detached tmux session.
# Requires a synced grin node with stratum on NODE_HOST:NODE_PORT and tmux installed.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR"

SESSION="${SESSION:-m1fast}"
SCHED_PORT="${SCHED_PORT:-3410}"
NODE_HOST="${NODE_HOST:-127.0.0.1}"
NODE_PORT="${NODE_PORT:-3416}"
EDGE_BITS="${EDGE_BITS:-32}"
ROUNDS="${ROUNDS:-160}"
MAXGRAPHS="${MAXGRAPHS:-0}"
LOGIN="${LOGIN:-m1miner}"

# Proven solver configuration. These are speed settings, not instrumentation:
# d2 early abort at round 64 (recall 1 verified), 16 rounds per command buffer,
# next nonce L1 prefire both post-peel and at the cut.
export M1_D2="${M1_D2:-abort}" M1_D2_CUT="${M1_D2_CUT:-64}" M1_RBATCH="${M1_RBATCH:-16}" \
       M1_L1PRE="${M1_L1PRE:-1}" M1_L1PRE_CUT="${M1_L1PRE_CUT:-1}" M1_D2_WITNESS="${M1_D2_WITNESS:-1}"

command -v tmux >/dev/null || { echo "tmux not found"; exit 1; }
if command -v nc >/dev/null 2>&1; then
  nc -z -G3 "$NODE_HOST" "$NODE_PORT" || { echo "node stratum $NODE_HOST:$NODE_PORT unreachable"; exit 1; }
fi
tmux has-session -t "$SESSION" 2>/dev/null && { echo "session $SESSION already running (./stop.sh first)"; exit 1; }

mkdir -p logs
TS="$(date +%Y%m%d-%H%M%S)"
tmux new-session -d -s "$SESSION" "cd '$DIR' && \
  M1_SCHED_LISTEN=$SCHED_PORT M1_SCHED_NODE_HOST=$NODE_HOST M1_SCHED_NODE_PORT=$NODE_PORT ./bin/m1_scheduler > logs/sched-$TS.log 2>&1 & \
  sleep 1; \
  M1_STRATUM_HOST=127.0.0.1 M1_STRATUM_PORT=$SCHED_PORT M1_STRATUM_LOGIN=$LOGIN M1_STRATUM_PASSWORD=x \
  ./bin/mine34_live $EDGE_BITS $ROUNDS $MAXGRAPHS > logs/miner-$TS.log 2>&1; \
  kill %1 2>/dev/null"
sleep 2
tmux has-session -t "$SESSION" && echo "started: tmux session $SESSION, logs/miner-$TS.log" || { echo "failed to start"; exit 1; }
