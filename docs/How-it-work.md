# How the miner works

This is a walkthrough of the solver from problem statement to submitted share.
Everything stated as a number here was measured on the Mac Studio M1 Ultra this
miner was tuned on, with the methodology noted where it matters.

## The problem

Grin's Cuckatoo-32 proof of work asks for a 42-cycle in an enormous random
bipartite graph. The graph has 2^31 nodes on each side and 2^32 edges. Edge e
has endpoints u = siphash(2e) and v = siphash(2e+1), masked to the node range,
with the four siphash keys derived from the block header and the nonce. Most
graphs contain no 42-cycle at all, so mining is a scan: derive keys for a
nonce, search the graph, move to the next nonce, until a cycle is found whose
hash also meets the network difficulty.

The standard approach, and the one used here, is edge trimming. An edge that
touches a degree-1 node (a leaf) cannot lie on a cycle, so it can be removed.
Removing edges creates new leaves, so the process iterates, shrinking the
graph toward its 2-core, the part where every node has degree at least 2. Any
42-cycle survives every round of this by definition. Once the survivor set is
small, a conventional cycle search finishes the job.

At edge bits 32 this is mostly a memory problem. The working set is a 93 GB
arena, every trim round streams a large fraction of it, and the machine's
memory bandwidth, not its arithmetic, sets the floor on how fast a graph can
be processed. The M1 Ultra is interesting for this workload precisely because
its unified memory is both large enough to hold the arena and fast enough to
stream it competitively.

## The pipeline

One graph flows through five stages, all but the last on the GPU.

1. Seed, level 1. Generate all 2^32 edges, compute one endpoint each by
   siphash, and scatter every edge into one of 128 coarse buckets keyed by the
   high bits of that endpoint. This stage is pure streaming write plus hashing.

2. Seed, level 2. Redistribute the coarse buckets into the fine arena: 32768
   fine buckets, one per GPU threadgroup, each depth-capped. A fine slot holds
   the edge index plus the low bits of the endpoint within the bucket. This
   arena is the 93 GB working set.

3. Trim rounds. Each round processes one fine bucket per threadgroup. The
   bucket marks each occupied endpoint slot in a threadgroup-local bitmap,
   then keeps an edge only if its paired slot is also occupied. The pairing
   reflects Cuckatoo's node layout, where an endpoint and its sibling differ
   in the low bit, so the test is exactly the liveness check that drops leaf
   edges. Survivors get their opposite endpoint recomputed and are re-bucketed
   by it for the next round, alternating the u side and the v side. The
   survivor population falls steeply in the early rounds and crawls in the
   late ones.

4. Early-abort verdict. At round 64 the solver stops and asks one exact
   question of the survivor set: does its edge-adjacency (edges joined through
   a shared node under the Cuckatoo pairing) contain a closed walk of length
   21, the length a 42-cycle must produce there? The mechanism is to emit the
   survivor endpoints, build two open-addressing hash multimaps (u to edge and
   v to edge), join on the paired key to produce the adjacency arcs, and run a
   depth-bounded search for a closed walk, stopping at the first find because
   only existence matters. If no such walk exists, the graph provably contains
   no 42-cycle and is abandoned on the spot. About 98 percent of graphs leave
   here, which is why the abort is worth so much wall time.

5. Recover and verify. Graphs that pass the verdict either have their
   candidate walk lifted directly back to 42 concrete edge identities, or they
   complete the remaining trim rounds and a 2-core peel, after which the host
   recovers the cycle with a union-find pass. Either way the result is checked
   in process with the reference verifier before the miner reports or submits
   anything. A solution that does not verify is discarded, though in practice
   this path exists as a guard rather than an event.

## Why the speed is exact

Every optimization in this build preserves the survivor sequence or removes
work that provably cannot matter. Nothing gates on a statistic or a heuristic.

- The early abort fires only on a proof of non-existence. Its recall was
  checked exhaustively against the full-trim solver: in the two largest gate
  runs, all 13 of 13 and all 282 of 282 cycles found by the baseline were
  also found with the abort enabled, and every one passed the verifier.

- Round batching folds 16 trim rounds into one Metal command buffer, with the
  buffer clears riding along as blit operations. This collapsed per-graph
  synchronization overhead from about 50 ms to about 5 ms. The survivor
  sequence is byte-identical to the unbatched path, so this is pure overhead
  removal.

- Seed prefire uses GPU-idle windows. While the host is busy with the
  post-peel tail of one graph, or while the verdict for an aborting graph is
  being computed, the next nonce's seed stage is already running on a second
  command queue with its own key buffer. If the current graph turns out to
  need its fallback path, the prefired work is simply discarded. No path does
  extra work; idle time is filled.

- The siphash kernel is a hand-lowered two-by-32-bit formulation with a
  reduced final round. Every call site masks the result to at most 32 bits,
  so the discarded half of the last round cancels exactly and skipping it is
  free. The output was checked bit for bit against the reference on full
  dumps, and the kernel measures about 13 percent faster, around 32 billion
  siphashes per second.

The correctness gate used throughout development is worth stating because it
is the repo's standard for any future change: after a candidate optimization,
the survivor set per round must be byte-identical to the previous code on a
fixed-seed gate, and recall against the full-trim solver must be unchanged.
A change that fails the gate does not ship, regardless of how much time it
saves.

## The scheduler

m1_scheduler is a small single-process stratum proxy that sits between the
miner and the node. It forwards traffic, tracks the block height, and drops
any submit whose height the chain has already passed, so stale shares never
reach the node. It can also pin one job per block height when an external
tool needs the miner and itself to agree on exactly which pre_pow is being
mined. The miner binary is unaware of it; it simply connects to the
scheduler's port instead of the node's.

## Performance and how it was measured

The headline number is 0.704 graphs per second warm, 1.421 s mean wall per
graph, measured over a 100-graph fixed-seed gate with the cold first graph
excluded and both cycle and non-cycle graphs included. The same protocol on
the same hardware gave 0.5558 graphs per second for the baseline this work
started from, a 27 percent improvement. The first graph after launch costs up
to about 6 s while the arena is faulted in, which is why warm and cold are
reported separately.

Fixed-seed means the pre_pow is pinned and nonces run 0 upward, so any two
runs, or any two solver builds, see the same sequence of graphs and their
outputs can be compared per nonce. The range harness exists to make this
comparison easy against arbitrary inputs, including headers in the format
other Cuckatoo solvers consume.

## Where the remaining time goes

Warm wall per graph divides into the seed phase, the trim rounds up to the
cut, the verdict, and, for the rare surviving graph, the full tail. The trim
phase is bandwidth-bound and sits at the machine's sustainable streaming
rate for most rounds; the early rounds and the seed have measured headroom
between their achieved traffic and what the chip sustains elsewhere in the
same process, and that gap is the most concrete remaining target. The verdict
itself costs little, and moving it earlier than round 64 is attractive in
principle but only with the same exactness it has now: the proof must remain
a proof at the earlier cut, or it does not move.
