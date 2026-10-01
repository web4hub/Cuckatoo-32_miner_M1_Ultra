make            # mine34_live, mine34_range_harness, m1_scheduler, strat_probe
make analyze    # clang static analyzer over every source; the gate is zero findings
make clean
# 0. (only if copied/downloaded through quarantine)
xattr -dr com.apple.quarantine .
chmod +x *.sh mine34_live debug/strat_probe scheduler/m1_scheduler

# 1. verify package integrity
shasum -a 256 -c SHA256SUMS

# 2. confirm the node is serving a real, non-zero-height job
./debug/strat_probe 127.0.0.1 3416     # expect result:"ok" + height>0

# 3. run (foreground, telemetry/steering OFF): C32 / 160 rounds / forever
./run-no-telemetry.sh

#    bounded smoke test (10 graphs):
./run-no-telemetry.sh 32 160 10
