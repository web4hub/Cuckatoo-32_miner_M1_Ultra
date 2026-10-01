# Proof runs

This directory holds the raw output of the measurement gates so the headline
numbers can be checked against primary evidence rather than summaries. All
runs are on a Mac Studio M1 Ultra, 128 GB, macOS, Cuckatoo-32, 160 trim
rounds configured, early abort at round 64.

## The gate

One command, fully deterministic, no node needed:

    M1_D2=abort M1_D2_CUT=64 M1_RBATCH=16 M1_L1PRE=1 M1_L1PRE_CUT=1 \
    M1_D2_WITNESS=1 M1_FIXED_PREPOW=00 \
    ./bin/v2/mine34_live 32 160 100

The pre_pow is pinned to the byte 0x00 and nonces run 0..99, so every run and
every build sees the same 100 graphs. Speed is read from the final line: drop
the cold first graph, average the remaining 99.

## Files

    gate_v1_100graphs.log         the gate run on bin/v1 (the original fast drop)
    gate_v2_100graphs.log         the gate run on bin/v2 (built from this source)
    receipts_v2_100graphs.jsonl   per-graph receipts from the v2 run (telemetry on)

The receipts file has two lines per graph: a mine34_d2.v1 line with the
verdict input sizes and timings (survivors emitted at the cut, adjacency
arcs, candidate count, abort decision), and a mine34_hot_mine_result.v1 line
with the outcome (cycle found, verified, submitted). Telemetry costs nothing
measurable; the gate logs with and without it agree on pace.

## What the runs show

Both gates mined all 100 graphs and found the same two 42-cycles, at nonce 45
and nonce 74, each verified in process by the reference verifier (POW_OK in
the logs). In the receipts: 98 graphs abort on a zero-candidate proof at
round 64, and the two candidate graphs are keys 45 and 74, whose candidates
lift to verified cycles.

The v1 and v2 binaries were further compared line by line on this gate:
identical survivor counts, identical arc counts, identical candidate verdicts
on every printed graph. v2 differs from v1 only by the source cleanup, two
dead-store removals, one defensive guard, and line-buffered logging; the
solver path is the same, and these logs are the receipt for that.

Wall clock for the 100 graphs lands within noise across runs (144.0 s, 144.6 s,
145.2 s in the three runs recorded here, the third with telemetry on), which
is 0.70 to 0.71 graphs per second warm.

## Live cross-check

The same binary mining against a real grin node (through the scheduler,
start.sh defaults) ran 300 graphs in 431 s wall including the cold start,
about 1.42 s per graph, found 6 cycles, and the node accepted the submitted
shares ("Got share" lines in the node's own log, zero "submitted too late").
Process memory was sampled every 30 s across the run and stayed flat to the
kilobyte, which is the regression check for the historical command-buffer
accumulation issue.
