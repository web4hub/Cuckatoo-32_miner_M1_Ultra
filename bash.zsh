./start.sh            # detached: logs to ./logs/miner-<ts>.log, pidfile, auto-restart
./start.sh -f         # foreground (live console)
tail -f logs/miner-*.log
./stop.sh             # clean SIGTERM -> SIGKILL escalation + orphan sweep
