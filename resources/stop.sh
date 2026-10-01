#!/usr/bin/env bash
# stop.sh: tear down the mining stack started by start.sh.
set -u
SESSION="${SESSION:-m1fast}"
if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
  echo "stopped tmux session $SESSION"
else
  echo "session $SESSION not running"
fi
pkill -f 'bin/m1_scheduler' 2>/dev/null
exit 0
