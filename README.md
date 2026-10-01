# M1 Grin Miner — Binary Release (Apple M1 Ultra / Metal)

A standalone Grin **Cuckatoo-32** miner for Apple Silicon: full graph solve on
Apple Metal, with a stratum job/submit pipeline and a headless launcher.

This package is a **binary release**, shared to demonstrate that the miner works
end-to-end on real mainnet jobs — GPU solve, local `POW_OK` verification, and
node-accepted C32 shares. **We intend to release the source and discuss the
methods soon**; this early drop is just to show the working result. Happy to
walk through any of it.

- Build: `a67866a`
- Target: Apple Silicon macOS, arm64, Apple Metal
- Validated against: `grin 5.4.0` / `grin-wallet 5.4.0-alpha.1`, mainnet

---

## 1. What's in this package

```bash
mine34_live              compiled arm64 miner (Metal solver + stratum + submit)
run.sh                   simple foreground run (honors env / args)
run-no-telemetry.sh      foreground run with telemetry + steering forced OFF
start.sh                 headless launcher (detached, pidfile, auto-restart)
stop.sh                  clean stop (SIGTERM -> SIGKILL + orphan sweep)
miner.conf               all runtime config (KEY=VALUE; safe defaults)
debug/strat_probe        stratum readiness probe (login + job-height check)
scheduler/m1_scheduler   optional local stratum scheduler/proxy
README.md                this file
SHA256SUMS               checksums for every file above
```

Source is not included in this drop — it will follow with a write-up of the
approach. The binaries are fully compiled, so **no Xcode, clang, or `make` is
needed to run them.**

## 2. Host requirements

- Apple Silicon Mac, intended for **M1 Ultra**.
- macOS **arm64, 15.0 or newer** (built against SDK 26.2, min macOS 15.0).
- Apple **Metal** available (system framework; nothing to install).
- Enough **unified memory** for Cuckatoo-32 — the binary reports `mem~74GB`.
- Local `grin` / `grin-wallet` 5.4.0 with a mainnet **node + treasury wallet**
  running (see §4). The miner does not create node/wallet state.

The miner links only system frameworks: `Metal`, `Foundation`,
`CoreFoundation`, `libobjc`, `libSystem`.

## 3. Quick start

```shell
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
```

Expected startup:

```mm
cuckatoo32 FAST miner: nb=32768 coarse=128 fine_n=256 rounds=160 maxkeys=... mem~74GB
LIVE: logged in to 127.0.0.1:3416 as m1miner (C32, 160 rounds)
NEW JOB height=... job_id=...
key 1: ... WALL 1.8...
```

If you see `STRATUM_LOGIN_FAIL 127.0.0.1:3416` instead, the node side isn't
ready — see §4.

## 4. Node + wallet prerequisites

The miner needs a grin 5.4.0 mainnet node whose **stratum** is up **and**
building real block templates, which requires the **treasury wallet** to be
listening so the node can fetch a coinbase. Expected local ports:

- wallet foreign listener: `127.0.0.1:3417`
- node owner API:          `127.0.0.1:3413` `127.0.0.1:3333`
- node stratum:            `127.0.0.1:3416`

Bring up the **wallet listener first, then the node.** The node's
`grin-server.toml` needs `wallet_listener_url = "http://127.0.0.1:3417"` (matching
the wallet's `api_listen_port`), `enable_stratum_server = true`, and
`stratum_server_addr = "127.0.0.1:3416"`.

Readiness means a **real non-zero job height**, not just an open port — confirm
with `./debug/strat_probe 127.0.0.1 3416`. If the miner prints
`STRATUM_LOGIN_FAIL`, it's almost always node-side (the node can't reach the
treasury wallet, so stratum has no job).

## 5. Configure

Edit `miner.conf` (`KEY=VALUE`, shell-sourceable). Defaults mine a local node
with **steerer and telemetry OFF**:

- `M1_STRATUM_HOST` / `_PORT` / `_LOGIN` / `_PASSWORD`
- `EDGE_BITS=32` (real Cuckatoo size), `ROUNDS=160`
- `MAXGRAPHS=0` (run forever; the warm loop lives inside the binary)
- `M1_STEER` — blank (experimental; left OFF for this release)
- `M1_TELEMETRY_PATH` — blank (zero-cost OFF)

Env vars override the file, e.g. `M1_STRATUM_HOST=10.0.0.5 ./run.sh`.

## 6. Run headless (supervised)

```shell
./start.sh            # detached: logs to ./logs/miner-<ts>.log, pidfile, auto-restart
./start.sh -f         # foreground (live console)
tail -f logs/miner-*.log
./stop.sh             # clean SIGTERM -> SIGKILL escalation + orphan sweep
```

## 7. Verifying submits (node-side is authoritative)

The miner prints `42-CYCLE found! ... verify=POW_OK` → `SUBMITTING share` →
`SUBMIT resp: ...`. Note `SUBMIT resp` means *received*, not *accepted* — the
node returns `result:ok` on receipt even for a stale share. The authoritative
verdict is in the node log:

```sh
grep -E 'Got share|submitted too late' ~/.local/share/grin/node/grin-server.log
```

- `Got share at height H ... submitted by m1miner` = accepted.
- `Share at height H ... submitted too late`       = stale.

## 8. Validation evidence

Validated live against a local grin 5.4.0 node + wallet.

**Throughput** (warm hot-path; cold graph 0 excluded):

```pwsh
target floor:       0.53 graphs/second
validated average:  0.540887 graphs/second  (27 warm samples, ~1.85 s/graph)
cold key 0:         5.160 s  (program start + Metal setup + first-touch, excluded)
```

Representative warm per-graph timings: `key 1..5` ≈ 1.846–1.863 s; steady
`key 50..1100` ≈ 1.83–1.86 s.

**Correctness** (every recovered candidate verified before submit, using the
ported Tromp `verify()`):

```rs
found=22 ok=22 fail=0 submitted=22  across 1124 graphs
node_accepted_current_run=22  node_reject_errors_current_run=0
```

The node log showed the corresponding accepted C32 shares
(`Got share at height ... edge_bits 32 ... submitted by m1miner`).

Scope: the miner reports at most one valid 42-cycle per graph (the share-mining
path) — this demonstrates the reported shares are valid and node-accepted; it is
not an exhaustive per-graph cycle enumeration.


## 9. Verify package files

```shell
shasum -a 256 -c SHA256SUMS
file mine34_live          # -> Mach-O 64-bit executable arm64
```

---
