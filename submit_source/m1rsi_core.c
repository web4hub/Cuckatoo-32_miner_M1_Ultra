#include "m1ultra_grin_rsi.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline uint64_t m1rsi_rotl64(uint64_t x, uint32_t b) {
    return (x << b) | (x >> (64u - b));
}

static inline void m1rsi_sip_round(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3) {
    *v0 += *v1;
    *v2 += *v3;
    *v1 = m1rsi_rotl64(*v1, 13u) ^ *v0;
    *v3 = m1rsi_rotl64(*v3, 16u) ^ *v2;
    *v0 = m1rsi_rotl64(*v0, 32u);
    *v2 += *v1;
    *v0 += *v3;
    *v1 = m1rsi_rotl64(*v1, 17u) ^ *v2;
    *v3 = m1rsi_rotl64(*v3, 21u) ^ *v0;
    *v2 = m1rsi_rotl64(*v2, 32u);
}

uint64_t m1rsi_siphash24(M1RsiKeys keys, uint64_t nonce) {
    uint64_t v0 = keys.k0;
    uint64_t v1 = keys.k1;
    uint64_t v2 = keys.k2;
    uint64_t v3 = keys.k3 ^ nonce;
    m1rsi_sip_round(&v0, &v1, &v2, &v3);
    m1rsi_sip_round(&v0, &v1, &v2, &v3);
    v0 ^= nonce;
    v2 ^= 0xffull;
    m1rsi_sip_round(&v0, &v1, &v2, &v3);
    m1rsi_sip_round(&v0, &v1, &v2, &v3);
    m1rsi_sip_round(&v0, &v1, &v2, &v3);
    m1rsi_sip_round(&v0, &v1, &v2, &v3);
    return (v0 ^ v1) ^ (v2 ^ v3);
}

uint64_t m1rsi_nonce_limit(uint32_t edge_bits) {
    if (edge_bits >= 64u) return ~0ull;
    return 1ull << edge_bits;
}

uint32_t m1rsi_endpoint(M1RsiKeys keys, uint32_t edge_bits, uint64_t edge, uint32_t side) {
    const uint64_t mask = edge_bits == 32u ? 0xffffffffull : ((1ull << edge_bits) - 1ull);
    return (uint32_t)(m1rsi_siphash24(keys, edge * 2ull + (uint64_t)(side & 1u)) & mask);
}

uint32_t m1rsi_endpoint_pair(uint32_t endpoint) {
    return endpoint >> 1u;
}

uint32_t m1rsi_endpoint_low(uint32_t endpoint) {
    return endpoint & 1u;
}

uint32_t m1rsi_relation_id(uint32_t edge_bits, uint32_t side, uint32_t endpoint) {
    const uint32_t pair = m1rsi_endpoint_pair(endpoint);
    const uint32_t side_bit = (side & 1u) << (edge_bits - 1u);
    return side_bit | pair;
}

M1RsiMemoryPlan m1rsi_memory_plan(uint32_t edge_bits) {
    M1RsiMemoryPlan p;
    memset(&p, 0, sizeof(p));
    p.edge_bits = edge_bits;
    if (edge_bits == 0u || edge_bits > 32u) return p;
    p.nonce_sites = 1ull << edge_bits;
    p.endpoint_sites_per_side = 1ull << edge_bits;
    p.head_bytes_per_side = p.endpoint_sites_per_side * sizeof(uint32_t);
    p.next_bytes_per_side = p.nonce_sites * sizeof(uint32_t);
    p.lock_bytes_per_side = ((p.endpoint_sites_per_side + 31ull) >> 5u) * sizeof(uint32_t);
    p.head_valid_bytes_per_side = (p.endpoint_sites_per_side + 7ull) >> 3u;
    p.next_valid_bytes_per_side = (p.nonce_sites + 7ull) >> 3u;
    p.total_index_bytes = 2ull * (p.head_bytes_per_side + p.next_bytes_per_side + p.lock_bytes_per_side + p.head_valid_bytes_per_side + p.next_valid_bytes_per_side);
    p.total_index_gib = (double)p.total_index_bytes / (1024.0 * 1024.0 * 1024.0);
    return p;
}

static uint32_t verify_sorted_distinct_range(const M1RsiJob *job, const M1RsiProof42 *proof, M1RsiReceipt *r) {
    const uint64_t limit = m1rsi_nonce_limit(job->edge_bits);
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        if (proof->nonces[i] >= limit) {
            if (r) { r->range_ok = 0u; r->status = M1RSI_STATUS_RANGE; }
            return M1RSI_STATUS_RANGE;
        }
        if (i != 0u && proof->nonces[i - 1u] >= proof->nonces[i]) {
            if (r) {
                r->sorted_distinct_ok = 0u;
                r->status = (proof->nonces[i - 1u] == proof->nonces[i]) ? M1RSI_STATUS_DUPLICATE : M1RSI_STATUS_NON_SORTED;
            }
            return (proof->nonces[i - 1u] == proof->nonces[i]) ? M1RSI_STATUS_DUPLICATE : M1RSI_STATUS_NON_SORTED;
        }
    }
    if (r) { r->range_ok = 1u; r->sorted_distinct_ok = 1u; }
    return M1RSI_STATUS_OK;
}

uint32_t m1rsi_verify42_scaffold_cycle(const M1RsiJob *job, const M1RsiProof42 *proof, M1RsiReceipt *receipt) {
    M1RsiReceipt local;
    if (!job || !proof) return M1RSI_STATUS_BAD_ARGUMENT;
    if (!receipt) receipt = &local;
    memset(receipt, 0, sizeof(*receipt));
    receipt->edge_bits = job->edge_bits;
    receipt->proof_size = job->proof_size;
    M1RsiMemoryPlan plan = m1rsi_memory_plan(job->edge_bits);
    receipt->nonce_sites = plan.nonce_sites;
    receipt->relation_slots = (job->edge_bits == 0u || job->edge_bits > 32u) ? 0ull : (2ull * (1ull << (job->edge_bits - 1u)));
    receipt->scaffold_coordinate_submitted = 0u;

    if (job->edge_bits == 0u || job->edge_bits > 32u) { receipt->status = M1RSI_STATUS_BAD_EDGE_BITS; return receipt->status; }
    if (job->proof_size != M1RSI_PROOFSIZE) { receipt->status = M1RSI_STATUS_BAD_PROOF_SIZE; return receipt->status; }

    uint32_t st = verify_sorted_distinct_range(job, proof, receipt);
    if (st != M1RSI_STATUS_OK) return st;

    uint32_t endpoints[M1RSI_PROOFSIZE][2];
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        endpoints[i][0] = m1rsi_endpoint(job->keys, job->edge_bits, proof->nonces[i], 0u);
        endpoints[i][1] = m1rsi_endpoint(job->keys, job->edge_bits, proof->nonces[i], 1u);
    }

    uint32_t mate_index[M1RSI_PROOFSIZE][2];
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        mate_index[i][0] = 0xffffffffu;
        mate_index[i][1] = 0xffffffffu;
    }

    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        for (uint32_t side = 0u; side < 2u; ++side) {
            const uint32_t ep = endpoints[i][side];
            const uint32_t pair = ep >> 1u;
            const uint32_t want_low = (ep & 1u) ^ 1u;
            uint32_t count = 0u;
            uint32_t found = 0xffffffffu;
            for (uint32_t j = 0; j < M1RSI_PROOFSIZE; ++j) {
                if (i == j) continue;
                const uint32_t epj = endpoints[j][side];
                if ((epj >> 1u) == pair && (epj & 1u) == want_low) {
                    ++count;
                    found = j;
                }
            }
            if (count != 1u) {
                receipt->endpoint_degree_ok = 0u;
                receipt->status = M1RSI_STATUS_ENDPOINT_DEGREE;
                return receipt->status;
            }
            mate_index[i][side] = found;
        }
    }
    receipt->endpoint_degree_ok = 1u;

    uint32_t visited[M1RSI_PROOFSIZE];
    memset(visited, 0, sizeof(visited));
    uint32_t idx = 0u;
    uint32_t side = 0u;
    for (uint32_t step = 0; step < M1RSI_PROOFSIZE; ++step) {
        if (idx >= M1RSI_PROOFSIZE || visited[idx]) {
            receipt->single_cycle_ok = 0u;
            receipt->status = M1RSI_STATUS_NOT_SINGLE_CYCLE;
            return receipt->status;
        }
        visited[idx] = 1u;
        idx = mate_index[idx][side];
        side ^= 1u;
    }
    if (idx != 0u || side != 0u) {
        receipt->single_cycle_ok = 0u;
        receipt->status = M1RSI_STATUS_NOT_SINGLE_CYCLE;
        return receipt->status;
    }

    receipt->single_cycle_ok = 1u;
    receipt->exact_cycle_ok = 1u;
    receipt->status = M1RSI_STATUS_OK;
    return M1RSI_STATUS_OK;
}

static int m1rsi_cmp_u64_core(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/*
 * Deterministic scaffold-order reconstruction from the exact 42 nonce labels.
 *
 * This is the algebraic ordering lane the mining scaffold was meant to provide:
 * it does not search the full graph, it does not trim, and it does not guess an
 * ordering.  It builds the 42-label induced relation table under the live Grin
 * SipHash key, then follows the same-side opposite-low mate law:
 *
 *   (edge, side) -> bucket(side, pair(endpoint(edge, side)), low^1) -> mate_edge.
 *
 * The candidate set is accepted only if every step has a unique mate, the walk
 * closes after exactly 42 edges, and the sorted proof passes the exact verifier.
 * The ordered_nonces output is the scaffold traversal order.  The submit payload
 * remains the sorted exact proof labels.
 */
uint32_t m1rsi_reconstruct42_scaffold_order(const M1RsiJob *job, const uint64_t unordered_nonces[M1RSI_PROOFSIZE], uint64_t ordered_nonces[M1RSI_PROOFSIZE], M1RsiReceipt *receipt) {
    if (!job || !unordered_nonces || !ordered_nonces) return M1RSI_STATUS_BAD_ARGUMENT;
    if (job->edge_bits == 0u || job->edge_bits > 32u) return M1RSI_STATUS_BAD_EDGE_BITS;
    if (job->proof_size != M1RSI_PROOFSIZE) return M1RSI_STATUS_BAD_PROOF_SIZE;

    M1RsiProof42 sorted;
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) sorted.nonces[i] = unordered_nonces[i];
    qsort(sorted.nonces, M1RSI_PROOFSIZE, sizeof(uint64_t), m1rsi_cmp_u64_core);

    uint32_t st = m1rsi_verify42_scaffold_cycle(job, &sorted, receipt);
    if (st != M1RSI_STATUS_OK) return st;

    uint32_t endpoints[M1RSI_PROOFSIZE][2];
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        endpoints[i][0] = m1rsi_endpoint(job->keys, job->edge_bits, sorted.nonces[i], 0u);
        endpoints[i][1] = m1rsi_endpoint(job->keys, job->edge_bits, sorted.nonces[i], 1u);
    }

    uint32_t idx = 0u;
    uint32_t side = 0u;
    uint32_t visited[M1RSI_PROOFSIZE];
    memset(visited, 0, sizeof(visited));

    for (uint32_t step = 0; step < M1RSI_PROOFSIZE; ++step) {
        if (idx >= M1RSI_PROOFSIZE || visited[idx]) return M1RSI_STATUS_NOT_SINGLE_CYCLE;
        visited[idx] = 1u;
        ordered_nonces[step] = sorted.nonces[idx];

        const uint32_t ep = endpoints[idx][side];
        const uint32_t pair = ep >> 1u;
        const uint32_t want_low = (ep & 1u) ^ 1u;
        uint32_t count = 0u;
        uint32_t next_idx = 0xffffffffu;
        for (uint32_t j = 0; j < M1RSI_PROOFSIZE; ++j) {
            if (j == idx) continue;
            const uint32_t epj = endpoints[j][side];
            if ((epj >> 1u) == pair && (epj & 1u) == want_low) {
                ++count;
                next_idx = j;
            }
        }
        if (count != 1u) return M1RSI_STATUS_ENDPOINT_DEGREE;
        idx = next_idx;
        side ^= 1u;
    }

    if (idx != 0u || side != 0u) return M1RSI_STATUS_NOT_SINGLE_CYCLE;
    return M1RSI_STATUS_OK;
}

#define M1RSI_BOUNDARY_NONE 0xffffffffu
#define M1RSI_BOUNDARY_CPU_MAX_EDGE_BITS 20u
#define M1RSI_BOUNDARY_MAX_RUNGS 1048576ull
#define M1RSI_BOUNDARY_MAX_DFS_STEPS 8000000ull
#define M1RSI_BOUNDARY_RUNG_COUNT 21u

typedef struct M1RsiBoundaryEdge {
    uint32_t u;
    uint32_t v;
    uint8_t alive;
} M1RsiBoundaryEdge;

typedef struct M1RsiBoundaryRung {
    uint32_t edge0;
    uint32_t edge1;
    uint32_t h0;
    uint32_t h1;
} M1RsiBoundaryRung;

typedef struct M1RsiBoundaryPortRef {
    uint32_t rung;
    uint32_t next;
    uint8_t port;
    uint8_t reserved0;
    uint16_t reserved1;
} M1RsiBoundaryPortRef;

typedef struct M1RsiBoundaryOrder {
    uint32_t rung;
    uint32_t score;
} M1RsiBoundaryOrder;

typedef struct M1RsiBoundaryDfs {
    const M1RsiJob *job;
    const M1RsiBoundaryRung *rungs;
    const M1RsiBoundaryPortRef *ports;
    const uint32_t *head_boundary;
    uint8_t *used_rung;
    uint8_t *used_edge;
    uint32_t path[M1RSI_BOUNDARY_RUNG_COUNT];
    M1RsiProof42 *out_proof;
    M1RsiReceipt *receipt;
    M1RsiBoundarySupportStats *stats;
} M1RsiBoundaryDfs;

static int m1rsi_cmp_boundary_order(const void *a, const void *b) {
    const M1RsiBoundaryOrder *x = (const M1RsiBoundaryOrder *)a;
    const M1RsiBoundaryOrder *y = (const M1RsiBoundaryOrder *)b;
    if (x->score != y->score) return (x->score > y->score) - (x->score < y->score);
    return (x->rung > y->rung) - (x->rung < y->rung);
}

static uint32_t m1rsi_boundary_edge_endpoint(const M1RsiBoundaryEdge *edges, uint32_t edge, uint32_t side) {
    return (side == 0u) ? edges[edge].u : edges[edge].v;
}

static uint32_t m1rsi_boundary_try_candidate(M1RsiBoundaryDfs *ctx) {
    M1RsiProof42 proof;
    M1RsiReceipt local_receipt;
    memset(&proof, 0, sizeof(proof));
    for (uint32_t i = 0u; i < M1RSI_BOUNDARY_RUNG_COUNT; ++i) {
        const M1RsiBoundaryRung *r = &ctx->rungs[ctx->path[i]];
        proof.nonces[i * 2u] = (uint64_t)r->edge0;
        proof.nonces[i * 2u + 1u] = (uint64_t)r->edge1;
    }
    qsort(proof.nonces, M1RSI_PROOFSIZE, sizeof(uint64_t), m1rsi_cmp_u64_core);
    if (ctx->stats) {
        ctx->stats->candidate_cycles += 1u;
        ctx->stats->exact_verify_calls += 1u;
    }
    uint32_t st = m1rsi_verify42_scaffold_cycle(ctx->job, &proof, &local_receipt);
    if (st != M1RSI_STATUS_OK || local_receipt.exact_cycle_ok == 0u) return M1RSI_STATUS_NO_CYCLE;
    if (ctx->out_proof) *ctx->out_proof = proof;
    if (ctx->receipt) *ctx->receipt = local_receipt;
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_boundary_dfs(M1RsiBoundaryDfs *ctx, uint32_t start_h, uint32_t exit_h, uint32_t depth) {
    if (!ctx || depth == 0u || depth > M1RSI_BOUNDARY_RUNG_COUNT) return M1RSI_STATUS_BAD_ARGUMENT;
    if (ctx->stats) {
        ctx->stats->dfs_steps += 1u;
        if (ctx->stats->dfs_steps > M1RSI_BOUNDARY_MAX_DFS_STEPS) return M1RSI_STATUS_OVERFLOW;
    }
    if (depth == M1RSI_BOUNDARY_RUNG_COUNT) {
        if ((exit_h ^ 1u) != start_h) return M1RSI_STATUS_NO_CYCLE;
        if (ctx->stats) ctx->stats->zero_boundary_closures += 1u;
        return m1rsi_boundary_try_candidate(ctx);
    }

    const uint32_t need = exit_h ^ 1u;
    for (uint32_t ref = ctx->head_boundary[need]; ref != M1RSI_BOUNDARY_NONE; ref = ctx->ports[ref].next) {
        const M1RsiBoundaryPortRef *p = &ctx->ports[ref];
        const uint32_t ri = p->rung;
        const M1RsiBoundaryRung *r = &ctx->rungs[ri];
        if (ctx->used_rung[ri]) continue;
        if (ctx->used_edge[r->edge0] || ctx->used_edge[r->edge1]) continue;
        ctx->used_rung[ri] = 1u;
        ctx->used_edge[r->edge0] = 1u;
        ctx->used_edge[r->edge1] = 1u;
        ctx->path[depth] = ri;
        if (ctx->stats) {
            ctx->stats->fragment_joins += 1u;
            const uint32_t fragment_edges = (depth + 1u) * 2u;
            if (fragment_edges == 4u) ctx->stats->fragments_len4 += 1u;
            else if (fragment_edges == 8u) ctx->stats->fragments_len8 += 1u;
            else if (fragment_edges == 16u) ctx->stats->fragments_len16 += 1u;
            else if (fragment_edges == 32u) ctx->stats->fragments_len32 += 1u;
        }
        const uint32_t next_exit = (p->port == 0u) ? r->h1 : r->h0;
        uint32_t st = m1rsi_boundary_dfs(ctx, start_h, next_exit, depth + 1u);
        if (st == M1RSI_STATUS_OK || st == M1RSI_STATUS_OVERFLOW) return st;
        ctx->used_rung[ri] = 0u;
        ctx->used_edge[r->edge0] = 0u;
        ctx->used_edge[r->edge1] = 0u;
    }
    return M1RSI_STATUS_NO_CYCLE;
}

static uint32_t m1rsi_boundary_build_endpoint_heads(
    const M1RsiBoundaryEdge *edges,
    size_t edge_count,
    size_t endpoint_count,
    uint32_t side,
    uint32_t **out_head,
    uint32_t **out_next
) {
    if (!edges || !out_head || !out_next || side > 1u) return M1RSI_STATUS_BAD_ARGUMENT;
    *out_head = NULL;
    *out_next = NULL;
    uint32_t *head = (uint32_t *)malloc(endpoint_count * sizeof(uint32_t));
    uint32_t *next = (uint32_t *)malloc(edge_count * sizeof(uint32_t));
    if (!head || !next) {
        free(head);
        free(next);
        return M1RSI_STATUS_OVERFLOW;
    }
    for (size_t i = 0u; i < endpoint_count; ++i) head[i] = M1RSI_BOUNDARY_NONE;
    for (size_t e = 0u; e < edge_count; ++e) {
        next[e] = M1RSI_BOUNDARY_NONE;
        if (!edges[e].alive) continue;
        const uint32_t h = m1rsi_boundary_edge_endpoint(edges, (uint32_t)e, side);
        next[e] = head[h];
        head[h] = (uint32_t)e;
    }
    *out_head = head;
    *out_next = next;
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_boundary_count_contraction_rungs(
    const M1RsiBoundaryEdge *edges,
    size_t edge_count,
    size_t endpoint_count,
    uint32_t contract_side,
    uint64_t *out_count
) {
    if (!edges || !out_count || contract_side > 1u) return M1RSI_STATUS_BAD_ARGUMENT;
    *out_count = 0u;
    uint32_t *head = NULL;
    uint32_t *next = NULL;
    uint32_t status = m1rsi_boundary_build_endpoint_heads(edges, edge_count, endpoint_count, contract_side, &head, &next);
    if (status != M1RSI_STATUS_OK) return status;

    uint64_t count = 0u;
    for (uint32_t pair = 0u; pair < (uint32_t)(endpoint_count >> 1u); ++pair) {
        const uint32_t h0 = pair << 1u;
        const uint32_t h1 = h0 | 1u;
        for (uint32_t a = head[h0]; a != M1RSI_BOUNDARY_NONE; a = next[a]) {
            for (uint32_t b = head[h1]; b != M1RSI_BOUNDARY_NONE; b = next[b]) {
                (void)a;
                (void)b;
                count += 1u;
                if (count > M1RSI_BOUNDARY_MAX_RUNGS) {
                    free(head);
                    free(next);
                    return M1RSI_STATUS_OVERFLOW;
                }
            }
        }
    }
    *out_count = count;
    free(head);
    free(next);
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_boundary_search_contraction(
    const M1RsiJob *job,
    const M1RsiBoundaryEdge *edges,
    size_t edge_count,
    size_t endpoint_count,
    uint32_t contract_side,
    uint64_t rung_count_u64,
    M1RsiProof42 *out_proof,
    M1RsiReceipt *receipt,
    M1RsiBoundarySupportStats *stats
) {
    if (!job || !edges || !out_proof || contract_side > 1u) return M1RSI_STATUS_BAD_ARGUMENT;
    const uint32_t boundary_side = contract_side ^ 1u;
    uint32_t *head_contract = NULL;
    uint32_t *next_contract = NULL;
    M1RsiBoundaryRung *rungs = NULL;
    uint32_t *head_boundary = NULL;
    uint32_t *port_count = NULL;
    M1RsiBoundaryPortRef *ports = NULL;
    M1RsiBoundaryOrder *order = NULL;
    uint8_t *used_rung = NULL;
    uint8_t *used_edge = NULL;
    uint32_t status = M1RSI_STATUS_INTERNAL;

    status = m1rsi_boundary_build_endpoint_heads(edges, edge_count, endpoint_count, contract_side, &head_contract, &next_contract);
    if (status != M1RSI_STATUS_OK) goto done;
    if (rung_count_u64 < M1RSI_BOUNDARY_RUNG_COUNT) { status = M1RSI_STATUS_NO_CYCLE; goto done; }

    rungs = (M1RsiBoundaryRung *)calloc((size_t)rung_count_u64, sizeof(M1RsiBoundaryRung));
    port_count = (uint32_t *)calloc(endpoint_count, sizeof(uint32_t));
    if (!rungs || !port_count) { status = M1RSI_STATUS_OVERFLOW; goto done; }
    uint32_t ri = 0u;
    for (uint32_t pair = 0u; pair < (uint32_t)(endpoint_count >> 1u); ++pair) {
        const uint32_t h0 = pair << 1u;
        const uint32_t h1 = h0 | 1u;
        for (uint32_t a = head_contract[h0]; a != M1RSI_BOUNDARY_NONE; a = next_contract[a]) {
            for (uint32_t b = head_contract[h1]; b != M1RSI_BOUNDARY_NONE; b = next_contract[b]) {
                rungs[ri].edge0 = a;
                rungs[ri].edge1 = b;
                rungs[ri].h0 = m1rsi_boundary_edge_endpoint(edges, a, boundary_side);
                rungs[ri].h1 = m1rsi_boundary_edge_endpoint(edges, b, boundary_side);
                port_count[rungs[ri].h0] += 1u;
                port_count[rungs[ri].h1] += 1u;
                ri += 1u;
            }
        }
    }
    if ((uint64_t)ri != rung_count_u64) { status = M1RSI_STATUS_INTERNAL; goto done; }

    head_boundary = (uint32_t *)malloc(endpoint_count * sizeof(uint32_t));
    ports = (M1RsiBoundaryPortRef *)calloc((size_t)rung_count_u64 * 2u, sizeof(M1RsiBoundaryPortRef));
    order = (M1RsiBoundaryOrder *)calloc((size_t)rung_count_u64, sizeof(M1RsiBoundaryOrder));
    used_rung = (uint8_t *)calloc((size_t)rung_count_u64, sizeof(uint8_t));
    used_edge = (uint8_t *)calloc(edge_count, sizeof(uint8_t));
    if (!head_boundary || !ports || !order || !used_rung || !used_edge) { status = M1RSI_STATUS_OVERFLOW; goto done; }
    for (size_t i = 0u; i < endpoint_count; ++i) head_boundary[i] = M1RSI_BOUNDARY_NONE;
    for (uint32_t i = 0u; i < (uint32_t)rung_count_u64; ++i) {
        const uint32_t p0 = i * 2u;
        const uint32_t p1 = p0 + 1u;
        ports[p0].rung = i; ports[p0].port = 0u; ports[p0].next = head_boundary[rungs[i].h0]; head_boundary[rungs[i].h0] = p0;
        ports[p1].rung = i; ports[p1].port = 1u; ports[p1].next = head_boundary[rungs[i].h1]; head_boundary[rungs[i].h1] = p1;
        order[i].rung = i;
        order[i].score = port_count[rungs[i].h0 ^ 1u] + port_count[rungs[i].h1 ^ 1u];
    }
    qsort(order, (size_t)rung_count_u64, sizeof(M1RsiBoundaryOrder), m1rsi_cmp_boundary_order);

    M1RsiBoundaryDfs ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.job = job;
    ctx.rungs = rungs;
    ctx.ports = ports;
    ctx.head_boundary = head_boundary;
    ctx.used_rung = used_rung;
    ctx.used_edge = used_edge;
    ctx.out_proof = out_proof;
    ctx.receipt = receipt;
    ctx.stats = stats;

    status = M1RSI_STATUS_NO_CYCLE;
    for (uint32_t oi = 0u; oi < (uint32_t)rung_count_u64; ++oi) {
        const uint32_t start_ri = order[oi].rung;
        const M1RsiBoundaryRung *r = &rungs[start_ri];
        for (uint32_t port = 0u; port < 2u; ++port) {
            memset(used_rung, 0, (size_t)rung_count_u64 * sizeof(uint8_t));
            memset(used_edge, 0, edge_count * sizeof(uint8_t));
            used_rung[start_ri] = 1u;
            used_edge[r->edge0] = 1u;
            used_edge[r->edge1] = 1u;
            ctx.path[0] = start_ri;
            const uint32_t start_h = (port == 0u) ? r->h0 : r->h1;
            const uint32_t exit_h = (port == 0u) ? r->h1 : r->h0;
            status = m1rsi_boundary_dfs(&ctx, start_h, exit_h, 1u);
            if (status == M1RSI_STATUS_OK || status == M1RSI_STATUS_OVERFLOW) goto done;
        }
    }

done:
    free(head_contract);
    free(next_contract);
    free(rungs);
    free(head_boundary);
    free(port_count);
    free(ports);
    free(order);
    free(used_rung);
    free(used_edge);
    return status;
}

uint32_t m1rsi_boundary_support_mine42(const M1RsiJob *job, M1RsiProof42 *out_proof, M1RsiReceipt *receipt, M1RsiBoundarySupportStats *stats) {
    if (stats) memset(stats, 0, sizeof(*stats));
    if (receipt) memset(receipt, 0, sizeof(*receipt));
    if (out_proof) memset(out_proof, 0, sizeof(*out_proof));
    if (!job || !out_proof) {
        if (stats) stats->status = M1RSI_STATUS_BAD_ARGUMENT;
        if (receipt) receipt->status = M1RSI_STATUS_BAD_ARGUMENT;
        return M1RSI_STATUS_BAD_ARGUMENT;
    }
    if (job->proof_size != M1RSI_PROOFSIZE) {
        if (stats) { stats->status = M1RSI_STATUS_BAD_PROOF_SIZE; stats->edge_bits = job->edge_bits; }
        if (receipt) receipt->status = M1RSI_STATUS_BAD_PROOF_SIZE;
        return M1RSI_STATUS_BAD_PROOF_SIZE;
    }
    if (job->edge_bits == 0u || job->edge_bits > M1RSI_BOUNDARY_CPU_MAX_EDGE_BITS) {
        if (stats) { stats->status = M1RSI_STATUS_BAD_EDGE_BITS; stats->edge_bits = job ? job->edge_bits : 0u; }
        if (receipt) receipt->status = M1RSI_STATUS_BAD_EDGE_BITS;
        return M1RSI_STATUS_BAD_EDGE_BITS;
    }

    const uint64_t edge_count_u64 = m1rsi_nonce_limit(job->edge_bits);
    const uint64_t endpoint_count_u64 = edge_count_u64;
    if (edge_count_u64 == 0u || edge_count_u64 > (uint64_t)SIZE_MAX / sizeof(M1RsiBoundaryEdge)) {
        if (stats) stats->status = M1RSI_STATUS_RANGE;
        if (receipt) receipt->status = M1RSI_STATUS_RANGE;
        return M1RSI_STATUS_RANGE;
    }
    const size_t edge_count = (size_t)edge_count_u64;
    const size_t endpoint_count = (size_t)endpoint_count_u64;
    M1RsiBoundaryEdge *edges = NULL;
    uint32_t *u_counts = NULL;
    uint32_t *v_counts = NULL;
    uint32_t status = M1RSI_STATUS_INTERNAL;

    if (stats) {
        stats->edge_bits = job->edge_bits;
        stats->edges_scanned = edge_count_u64;
    }

    edges = (M1RsiBoundaryEdge *)calloc(edge_count, sizeof(M1RsiBoundaryEdge));
    u_counts = (uint32_t *)calloc(endpoint_count, sizeof(uint32_t));
    v_counts = (uint32_t *)calloc(endpoint_count, sizeof(uint32_t));
    if (!edges || !u_counts || !v_counts) { status = M1RSI_STATUS_OVERFLOW; goto done; }

    for (uint64_t e = 0u; e < edge_count_u64; ++e) {
        edges[e].u = m1rsi_endpoint(job->keys, job->edge_bits, e, 0u);
        edges[e].v = m1rsi_endpoint(job->keys, job->edge_bits, e, 1u);
        edges[e].alive = 1u;
    }

    while (1) {
        memset(u_counts, 0, endpoint_count * sizeof(uint32_t));
        memset(v_counts, 0, endpoint_count * sizeof(uint32_t));
        for (size_t e = 0u; e < edge_count; ++e) {
            if (!edges[e].alive) continue;
            u_counts[edges[e].u] += 1u;
            v_counts[edges[e].v] += 1u;
        }
        uint64_t killed = 0u;
        for (size_t e = 0u; e < edge_count; ++e) {
            if (!edges[e].alive) continue;
            if (u_counts[edges[e].u ^ 1u] == 0u || v_counts[edges[e].v ^ 1u] == 0u) {
                edges[e].alive = 0u;
                killed += 1u;
            }
        }
        if (stats) {
            stats->peel_rounds += 1u;
            stats->killed_edges += killed;
        }
        if (killed == 0u) break;
        if (stats && stats->peel_rounds > (uint32_t)edge_count) { status = M1RSI_STATUS_INTERNAL; goto done; }
    }

    uint64_t survivor_edges = 0u;
    for (size_t e = 0u; e < edge_count; ++e) if (edges[e].alive) survivor_edges += 1u;
    if (stats) stats->survivor_edges = survivor_edges;
    if (survivor_edges < M1RSI_PROOFSIZE) { status = M1RSI_STATUS_NO_CYCLE; goto done; }

    uint64_t u_rungs = 0u;
    uint64_t v_rungs = 0u;
    status = m1rsi_boundary_count_contraction_rungs(edges, edge_count, endpoint_count, 0u, &u_rungs);
    if (status != M1RSI_STATUS_OK) goto done;
    status = m1rsi_boundary_count_contraction_rungs(edges, edge_count, endpoint_count, 1u, &v_rungs);
    if (status != M1RSI_STATUS_OK) goto done;
    if (stats) {
        stats->u_rungs = u_rungs;
        stats->v_rungs = v_rungs;
        stats->fragments_len2 = u_rungs + v_rungs;
    }
    if (u_rungs < M1RSI_BOUNDARY_RUNG_COUNT && v_rungs < M1RSI_BOUNDARY_RUNG_COUNT) {
        status = M1RSI_STATUS_NO_CYCLE;
        goto done;
    }

    status = M1RSI_STATUS_NO_CYCLE;
    if (u_rungs >= M1RSI_BOUNDARY_RUNG_COUNT) {
        status = m1rsi_boundary_search_contraction(job, edges, edge_count, endpoint_count, 0u, u_rungs, out_proof, receipt, stats);
        if (status == M1RSI_STATUS_OK || status == M1RSI_STATUS_OVERFLOW) goto done;
    }
    if (v_rungs >= M1RSI_BOUNDARY_RUNG_COUNT) {
        status = m1rsi_boundary_search_contraction(job, edges, edge_count, endpoint_count, 1u, v_rungs, out_proof, receipt, stats);
        if (status == M1RSI_STATUS_OK || status == M1RSI_STATUS_OVERFLOW) goto done;
    }

done:
    if (stats) stats->status = status;
    if (receipt && status != M1RSI_STATUS_OK) {
        receipt->status = status;
        receipt->edge_bits = job->edge_bits;
        receipt->proof_size = job->proof_size;
    }
    free(edges);
    free(u_counts);
    free(v_counts);
    return status;
}

static uint32_t m1rsi_lace_min_bits(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

static uint32_t m1rsi_lace_endpoint_pair_matches_bits(const M1RsiJob *job, uint64_t edge_a, uint64_t edge_b, uint32_t side, uint32_t bits) {
    if (bits == 0u) return 1u;
    const uint32_t ea = m1rsi_endpoint(job->keys, job->edge_bits, edge_a, side);
    const uint32_t eb = m1rsi_endpoint(job->keys, job->edge_bits, edge_b, side);
    const uint32_t mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
    return ((ea ^ eb) & mask) == 1u;
}

static uint32_t m1rsi_lace_residual_zero_bits(const M1RsiJob *job, const uint64_t edges[M1RSI_PROOFSIZE], uint32_t bits) {
    for (uint32_t j = 0u; j < M1RSI_BOUNDARY_RUNG_COUNT; ++j) {
        const uint32_t even = j * 2u;
        const uint32_t odd = even + 1u;
        const uint32_t next_even = (odd + 1u) % M1RSI_PROOFSIZE;
        if (!m1rsi_lace_endpoint_pair_matches_bits(job, edges[even], edges[odd], 1u, bits)) return 0u;
        if (!m1rsi_lace_endpoint_pair_matches_bits(job, edges[odd], edges[next_even], 0u, bits)) return 0u;
    }
    return 1u;
}

static uint32_t m1rsi_lace_edges_are_distinct(const uint64_t edges[M1RSI_PROOFSIZE]) {
    for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
        for (uint32_t j = i + 1u; j < M1RSI_PROOFSIZE; ++j) {
            if (edges[i] == edges[j]) return 0u;
        }
    }
    return 1u;
}

static void m1rsi_lace_make_candidate_proof(const uint64_t edges[M1RSI_PROOFSIZE], M1RsiProof42 *proof) {
    memset(proof, 0, sizeof(*proof));
    for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) proof->nonces[i] = edges[i];
    qsort(proof->nonces, M1RSI_PROOFSIZE, sizeof(uint64_t), m1rsi_cmp_u64_core);
}


static uint64_t m1rsi_lace_mix64(uint64_t z) {
    z += 0x9e3779b97f4a7c15ull;
    z = (z ^ (z >> 30u)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27u)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31u);
}

static uint64_t m1rsi_lace_gray64(uint64_t x) {
    return x ^ (x >> 1u);
}

static uint32_t m1rsi_lace_env_u32(const char *name, uint32_t fallback, uint32_t min_value, uint32_t max_value) {
    const char *raw = getenv(name);
    if (!raw || !*raw) return fallback;
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(raw, &end, 10);
    if (end) {
        while (*end && isspace((unsigned char)*end)) ++end;
    }
    if (end == raw || errno == ERANGE || (end && *end)) return fallback;
    if (value < (unsigned long)min_value) value = (unsigned long)min_value;
    if (value > (unsigned long)max_value) value = (unsigned long)max_value;
    return (uint32_t)value;
}

static uint64_t m1rsi_lace_env_u64(const char *name, uint64_t fallback, uint64_t min_value, uint64_t max_value) {
    const char *raw = getenv(name);
    if (!raw || !*raw) return fallback;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(raw, &end, 10);
    if (end) {
        while (*end && isspace((unsigned char)*end)) ++end;
    }
    if (end == raw || errno == ERANGE || (end && *end)) return fallback;
    uint64_t out = (uint64_t)value;
    if (out < min_value) out = min_value;
    if (out > max_value) out = max_value;
    return out;
}

static uint32_t m1rsi_lace_delta_side(uint32_t delta_index) {
    return (delta_index & 1u) ? 0u : 1u;
}

static uint32_t m1rsi_lace_edge_distinct_prefix(const uint64_t *edges, uint32_t count, uint64_t candidate) {
    for (uint32_t i = 0u; i < count; ++i) {
        if (edges[i] == candidate) return 0u;
    }
    return 1u;
}

typedef struct M1RsiLaceDualLowIndex {
    uint32_t bits;
    uint32_t mask;
    uint32_t *slots;
    uint64_t bucket_count;
    uint64_t scan_count;
    uint64_t filled;
} M1RsiLaceDualLowIndex;

typedef struct M1RsiLaceSparseLiftIndex {
    uint32_t bits;
    uint32_t mask;
    uint32_t way_count;
    uint32_t bridge_edges;
    uint32_t endpoint_count;
    void *mapped_blob;
    size_t mapped_size;
    uint32_t *side_edges[2];
    uint32_t *side_other[2];
    uint64_t *dual_keys;
    uint32_t *dual_edges;
    uint64_t dual_capacity;
    uint64_t dual_mask;
    uint64_t scan_count;
    uint64_t side_filled[2];
    uint64_t dual_filled;
} M1RsiLaceSparseLiftIndex;

typedef struct M1RsiLaceSparseLiftCache {
    uint32_t valid;
    uint32_t bits;
    uint32_t edge_bits;
    uint32_t way_count;
    uint32_t bridge_edges;
    uint64_t scan_count;
    M1RsiKeys keys;
    M1RsiLaceSparseLiftIndex idx;
} M1RsiLaceSparseLiftCache;

typedef struct M1RsiLaceBridgeCatalogEntry {
    uint32_t edge_a;
    uint32_t edge_b;
    uint32_t start_u;
    uint32_t target_current;
} M1RsiLaceBridgeCatalogEntry;

typedef struct M1RsiLaceBridgeCatalogCache {
    uint32_t valid;
    uint32_t bits;
    uint32_t return_bits;
    uint32_t edge_bits;
    uint32_t way_count;
    uint32_t bridge_edges;
    uint64_t sparse_scan_count;
    uint32_t probe_count;
    uint32_t capacity;
    uint32_t count;
    M1RsiKeys keys;
    M1RsiLaceBridgeCatalogEntry *entries;
} M1RsiLaceBridgeCatalogCache;

typedef struct M1RsiLacePathMitmState {
    uint32_t key;
    uint64_t edges[M1RSI_PROOFSIZE];
} M1RsiLacePathMitmState;

typedef struct M1RsiLacePathMitmEndpointCacheEntry {
    uint32_t valid;
    uint32_t endpoint_key;
    uint64_t support_ordinal;
    uint32_t count;
    M1RsiLacePathMitmState *states;
} M1RsiLacePathMitmEndpointCacheEntry;

typedef struct M1RsiLacePathMitmEndpointCache {
    uint32_t valid;
    uint32_t bits;
    uint32_t return_bits;
    uint32_t edge_bits;
    uint32_t way_count;
    uint32_t bridge_edges;
    uint32_t fanout;
    uint32_t left_steps;
    uint32_t capacity;
    uint64_t budget_bytes;
    uint64_t slot_bytes;
    uint32_t next_slot[2];
    uint64_t sparse_scan_count;
    M1RsiKeys keys;
    M1RsiLacePathMitmEndpointCacheEntry *entries[2];
} M1RsiLacePathMitmEndpointCache;

typedef struct M1RsiLaceSparseConfigOverride {
    uint32_t active;
    uint32_t bridge_edges;
    uint32_t way_count;
    uint64_t scan_count;
    uint32_t index_threads;
    uint32_t template_threads;
    uint32_t pick_bits;
    uint32_t return_bits;
    uint32_t bridge_first_probes;
    uint32_t bridge_catalog_cap;
    uint32_t path_mitm_fanout;
    uint32_t path_mitm_left;
    uint32_t path_mitm_threads;
    uint32_t endpoint_cache_cap;
    uint32_t template_restarts;
} M1RsiLaceSparseConfigOverride;

typedef struct M1RsiLaceSparseLiftIndexFileHeader {
    uint64_t magic;
    uint32_t version;
    uint32_t header_bytes;
    uint32_t bits;
    uint32_t edge_bits;
    uint32_t way_count;
    uint32_t bridge_edges;
    uint32_t endpoint_count;
    uint32_t mask;
    uint64_t endpoint_slots;
    uint64_t scan_count;
    uint64_t side_filled[2];
    uint64_t dual_capacity;
    uint64_t dual_mask;
    uint64_t dual_filled;
    uint64_t key_words[4];
} M1RsiLaceSparseLiftIndexFileHeader;

#define M1RSI_LACE_SPARSE_INDEX_MAGIC 0x314944495350434cull /* "LCPSIDI1" little-endian marker */
#define M1RSI_LACE_SPARSE_INDEX_VERSION 1u

static M1RsiLaceSparseLiftCache g_lace_sparse_lift_cache;
static M1RsiLaceBridgeCatalogCache g_lace_bridge_catalog_cache;
static M1RsiLacePathMitmEndpointCache g_lace_path_mitm_endpoint_cache;
static _Thread_local M1RsiLaceSparseConfigOverride g_lace_sparse_config_override;

static uint64_t m1rsi_lace_key_mix(const M1RsiJob *job) {
    if (!job) return 0u;
    return job->keys.k0 ^ m1rsi_rotl64(job->keys.k1, 17u) ^
           m1rsi_rotl64(job->keys.k2, 31u) ^ m1rsi_rotl64(job->keys.k3, 47u) ^
           (job->stratum_nonce * 0x9e3779b97f4a7c15ull);
}

static void m1rsi_lace_dual_index_free(M1RsiLaceDualLowIndex *idx) {
    if (!idx) return;
    free(idx->slots);
    memset(idx, 0, sizeof(*idx));
}

static uint64_t m1rsi_lace_pow2_at_least(uint64_t value) {
    uint64_t out = 1ull;
    while (out < value && out < (1ull << 63u)) out <<= 1u;
    return out;
}

static void m1rsi_lace_sparse_lift_index_free(M1RsiLaceSparseLiftIndex *idx) {
    if (!idx) return;
    if (idx->mapped_blob && idx->mapped_size != 0u) {
        munmap(idx->mapped_blob, idx->mapped_size);
    } else {
        free(idx->side_edges[0]);
        free(idx->side_edges[1]);
        free(idx->side_other[0]);
        free(idx->side_other[1]);
        free(idx->dual_keys);
        free(idx->dual_edges);
    }
    memset(idx, 0, sizeof(*idx));
}

static void m1rsi_lace_bridge_catalog_cache_free(M1RsiLaceBridgeCatalogCache *cache) {
    if (!cache) return;
    free(cache->entries);
    memset(cache, 0, sizeof(*cache));
}

static void m1rsi_lace_path_mitm_endpoint_cache_free(M1RsiLacePathMitmEndpointCache *cache) {
    if (!cache) return;
    for (uint32_t dir = 0u; dir < 2u; ++dir) {
        if (cache->entries[dir]) {
            for (uint32_t i = 0u; i < cache->capacity; ++i) free(cache->entries[dir][i].states);
            free(cache->entries[dir]);
        }
    }
    memset(cache, 0, sizeof(*cache));
}

static uint32_t m1rsi_lace_keys_equal(M1RsiKeys a, M1RsiKeys b) {
    return a.k0 == b.k0 && a.k1 == b.k1 && a.k2 == b.k2 && a.k3 == b.k3;
}

static uint32_t m1rsi_lace_popcount32(uint32_t x) {
    uint32_t n = 0u;
    while (x) {
        n += x & 1u;
        x >>= 1u;
    }
    return n;
}

static uint32_t m1rsi_lace_host_cpu_count(void);

static uint64_t m1rsi_lace_sparse_lift_max_scan(const M1RsiJob *job) {
    if (!job || job->edge_bits == 0u || job->edge_bits > 32u) return 1u;
    return job->edge_bits == 32u ? (1ull << 32u) : (1ull << job->edge_bits);
}

static uint64_t m1rsi_lace_sparse_lift_default_scan(uint32_t bits) {
    return bits >= 30u ? (1ull << 32u) : (bits >= 28u ? (1ull << 28u) : (bits >= 24u ? (1ull << 25u) : (bits >= 20u ? (1ull << 24u) : (bits >= 16u ? (1ull << 24u) : (1ull << 22u)))));
}

static uint32_t m1rsi_lace_sparse_lift_desired_bridge_edges(uint32_t bits) {
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.bridge_edges != 0u) {
        return g_lace_sparse_config_override.bridge_edges > 2u ? 2u : g_lace_sparse_config_override.bridge_edges;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_BRIDGE_EDGES", bits >= 28u ? 2u : 1u, 1u, 2u);
}

static uint64_t m1rsi_lace_sparse_lift_endpoint_count64(uint32_t bits) {
    return bits >= 32u ? (1ull << 32u) : (1ull << bits);
}

static uint32_t m1rsi_lace_sparse_lift_endpoint_count_field(uint32_t bits) {
    return bits >= 32u ? 0u : (1u << bits);
}

static uint64_t m1rsi_lace_sparse_lift_endpoint_slots(uint32_t bits, uint32_t ways) {
    return m1rsi_lace_sparse_lift_endpoint_count64(bits) * (uint64_t)ways;
}

static uint32_t m1rsi_lace_sparse_lift_desired_way_count(uint32_t bits) {
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.way_count != 0u) {
        return g_lace_sparse_config_override.way_count > 16u ? 16u : g_lace_sparse_config_override.way_count;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_LIFT_WAYS", bits >= 32u ? 1u : 4u, 1u, 16u);
}

static uint64_t m1rsi_lace_sparse_lift_desired_scan_count(const M1RsiJob *job, uint32_t bits) {
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.scan_count != 0ull) {
        const uint64_t max_scan = m1rsi_lace_sparse_lift_max_scan(job);
        return g_lace_sparse_config_override.scan_count > max_scan ? max_scan : g_lace_sparse_config_override.scan_count;
    }
    return m1rsi_lace_env_u64(
        "M1RSI_LACE_SPARSE_LIFT_SCAN",
        m1rsi_lace_sparse_lift_default_scan(bits),
        1u,
        m1rsi_lace_sparse_lift_max_scan(job));
}

static uint32_t m1rsi_lace_sparse_index_thread_count(uint32_t bits, uint32_t bridge_edges) {
    uint32_t fallback = (bits >= 24u && bridge_edges >= 2u) ? m1rsi_lace_host_cpu_count() : 1u;
    if (fallback > 32u) fallback = 32u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.index_threads != 0u) {
        uint32_t threads = g_lace_sparse_config_override.index_threads;
        if (threads > 64u) threads = 64u;
        return threads == 0u ? 1u : threads;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_INDEX_THREADS", fallback, 1u, 64u);
}

static uint32_t m1rsi_lace_sparse_lift_index_path(const M1RsiJob *job, uint32_t bits, char *out, size_t out_size) {
    if (!job || !out || out_size == 0u) return 0u;
    out[0] = '\0';
    const char *exact = getenv("M1RSI_LACE_SPARSE_INDEX_FILE");
    if (exact && *exact) {
        int n = snprintf(out, out_size, "%s", exact);
        return (n > 0 && (size_t)n < out_size) ? 1u : 0u;
    }
    const char *dir = getenv("M1RSI_LACE_SPARSE_INDEX_DIR");
    if (!dir || !*dir) return 0u;
    const uint32_t ways = m1rsi_lace_sparse_lift_desired_way_count(bits);
    const uint32_t bridge_edges = m1rsi_lace_sparse_lift_desired_bridge_edges(bits);
    const uint64_t scan = m1rsi_lace_sparse_lift_desired_scan_count(job, bits);
    const uint64_t key_tag = m1rsi_lace_key_mix(job);
    int n = snprintf(out,
                     out_size,
                     "%s/lace_sparse_b%u_e%u_w%u_br%u_s%llu_k%016llx_%016llx_%016llx_%016llx_%016llx.bin",
                     dir,
                     bits,
                     job->edge_bits,
                     ways,
                     bridge_edges,
                     (unsigned long long)scan,
                     (unsigned long long)key_tag,
                     (unsigned long long)job->keys.k0,
                     (unsigned long long)job->keys.k1,
                     (unsigned long long)job->keys.k2,
                     (unsigned long long)job->keys.k3);
    return (n > 0 && (size_t)n < out_size) ? 1u : 0u;
}

static uint64_t m1rsi_lace_sparse_lift_index_expected_size(uint64_t endpoint_slots, uint64_t dual_capacity) {
    const uint64_t header = (uint64_t)sizeof(M1RsiLaceSparseLiftIndexFileHeader);
    const uint64_t side_arrays = endpoint_slots * 4ull * (uint64_t)sizeof(uint32_t);
    const uint64_t dual_arrays = dual_capacity * ((uint64_t)sizeof(uint64_t) + (uint64_t)sizeof(uint32_t));
    if (side_arrays / (uint64_t)sizeof(uint32_t) != endpoint_slots * 4ull) return 0u;
    if (dual_capacity && dual_arrays / dual_capacity != ((uint64_t)sizeof(uint64_t) + (uint64_t)sizeof(uint32_t))) return 0u;
    if (header + side_arrays < header) return 0u;
    if (header + side_arrays + dual_arrays < header + side_arrays) return 0u;
    return header + side_arrays + dual_arrays;
}

static uint32_t m1rsi_lace_sparse_lift_write_all(int fd, const void *data, uint64_t bytes) {
    const unsigned char *p = (const unsigned char *)data;
    while (bytes != 0u) {
        const size_t chunk = bytes > (1ull << 26u) ? (size_t)(1ull << 26u) : (size_t)bytes;
        ssize_t n = write(fd, p, chunk);
        if (n <= 0) return 0u;
        p += (size_t)n;
        bytes -= (uint64_t)n;
    }
    return 1u;
}

static uint64_t m1rsi_lace_sparse_lift_pretouch_map(const void *map, size_t bytes) {
    if (!map || bytes == 0u) return 0u;
    const volatile unsigned char *p = (const volatile unsigned char *)map;
    const size_t page = 4096u;
    uint64_t checksum = 0u;
    for (size_t off = 0u; off < bytes; off += page) checksum += (uint64_t)p[off];
    checksum += (uint64_t)p[bytes - 1u];
    return checksum;
}

static uint32_t m1rsi_lace_sparse_lift_try_load_file(const M1RsiJob *job, uint32_t bits, const char *path, M1RsiLaceSparseLiftIndex *idx) {
    if (!job || !path || !*path || !idx) return 0u;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0u;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= (off_t)sizeof(M1RsiLaceSparseLiftIndexFileHeader)) {
        close(fd);
        return 0u;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0u;
#ifdef MADV_RANDOM
    (void)madvise(map, (size_t)st.st_size, MADV_RANDOM);
#endif

    const M1RsiLaceSparseLiftIndexFileHeader *hdr = (const M1RsiLaceSparseLiftIndexFileHeader *)map;
    const uint32_t desired_ways = m1rsi_lace_sparse_lift_desired_way_count(bits);
    const uint32_t desired_bridge_edges = m1rsi_lace_sparse_lift_desired_bridge_edges(bits);
    const uint64_t desired_scan = m1rsi_lace_sparse_lift_desired_scan_count(job, bits);
    const uint32_t endpoint_count_field = m1rsi_lace_sparse_lift_endpoint_count_field(bits);
    const uint64_t endpoint_slots = m1rsi_lace_sparse_lift_endpoint_slots(bits, desired_ways);
    const uint64_t expected = m1rsi_lace_sparse_lift_index_expected_size(endpoint_slots, hdr->dual_capacity);
    const uint32_t ok =
        hdr->magic == M1RSI_LACE_SPARSE_INDEX_MAGIC &&
        hdr->version == M1RSI_LACE_SPARSE_INDEX_VERSION &&
        hdr->header_bytes == (uint32_t)sizeof(M1RsiLaceSparseLiftIndexFileHeader) &&
        hdr->bits == bits &&
        hdr->edge_bits == job->edge_bits &&
        hdr->way_count == desired_ways &&
        hdr->bridge_edges == desired_bridge_edges &&
        hdr->endpoint_count == endpoint_count_field &&
        hdr->mask == (bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u)) &&
        hdr->endpoint_slots == endpoint_slots &&
        hdr->scan_count == desired_scan &&
        hdr->key_words[0] == job->keys.k0 &&
        hdr->key_words[1] == job->keys.k1 &&
        hdr->key_words[2] == job->keys.k2 &&
        hdr->key_words[3] == job->keys.k3 &&
        expected != 0u &&
        (uint64_t)st.st_size >= expected;
    if (!ok) {
        munmap(map, (size_t)st.st_size);
        return 0u;
    }

    const uint32_t pretouch = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_INDEX_PRETOUCH", bits >= 32u ? 1u : 0u, 0u, 1u);
    uint64_t pretouch_checksum = 0u;
    if (pretouch) {
#ifdef MADV_WILLNEED
        (void)madvise(map, (size_t)expected, MADV_WILLNEED);
#endif
        pretouch_checksum = m1rsi_lace_sparse_lift_pretouch_map(map, (size_t)expected);
    }

    memset(idx, 0, sizeof(*idx));
    idx->bits = hdr->bits;
    idx->mask = hdr->mask;
    idx->way_count = hdr->way_count;
    idx->bridge_edges = hdr->bridge_edges;
    idx->endpoint_count = hdr->endpoint_count;
    idx->scan_count = hdr->scan_count;
    idx->side_filled[0] = hdr->side_filled[0];
    idx->side_filled[1] = hdr->side_filled[1];
    idx->dual_capacity = hdr->dual_capacity;
    idx->dual_mask = hdr->dual_mask;
    idx->dual_filled = hdr->dual_filled;
    idx->mapped_blob = map;
    idx->mapped_size = (size_t)st.st_size;

    unsigned char *p = (unsigned char *)map + sizeof(M1RsiLaceSparseLiftIndexFileHeader);
    const uint64_t side_bytes = endpoint_slots * (uint64_t)sizeof(uint32_t);
    idx->side_edges[0] = (uint32_t *)p; p += side_bytes;
    idx->side_edges[1] = (uint32_t *)p; p += side_bytes;
    idx->side_other[0] = (uint32_t *)p; p += side_bytes;
    idx->side_other[1] = (uint32_t *)p; p += side_bytes;
    if (idx->dual_capacity != 0u) {
        idx->dual_keys = (uint64_t *)p; p += idx->dual_capacity * (uint64_t)sizeof(uint64_t);
        idx->dual_edges = (uint32_t *)p;
    }
    fprintf(stderr,
            "m1rsi: lace_sparse_lift_index_file_hit bits=%u ways=%u bridge_edges=%u scanned=%llu bytes=%llu pretouch=%u pretouch_checksum=%llu path=%s graph_materialized=0 fixed_endpoint_preimage=0\n",
            bits,
            desired_ways,
            desired_bridge_edges,
            (unsigned long long)desired_scan,
            (unsigned long long)expected,
            pretouch,
            (unsigned long long)pretouch_checksum,
            path);
    return 1u;
}

static uint32_t m1rsi_lace_sparse_lift_save_file(const M1RsiJob *job, const M1RsiLaceSparseLiftIndex *idx, const char *path) {
    if (!job || !idx || idx->mapped_blob || !path || !*path || !idx->side_edges[0] || !idx->side_edges[1] ||
        !idx->side_other[0] || !idx->side_other[1]) {
        return 0u;
    }
    const uint64_t endpoint_slots = m1rsi_lace_sparse_lift_endpoint_slots(idx->bits, idx->way_count);
    const uint64_t expected = m1rsi_lace_sparse_lift_index_expected_size(endpoint_slots, idx->dual_capacity);
    if (expected == 0u) return 0u;

    char tmp_path[4096];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp_path)) return 0u;
    int fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) return 0u;

    M1RsiLaceSparseLiftIndexFileHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = M1RSI_LACE_SPARSE_INDEX_MAGIC;
    hdr.version = M1RSI_LACE_SPARSE_INDEX_VERSION;
    hdr.header_bytes = (uint32_t)sizeof(hdr);
    hdr.bits = idx->bits;
    hdr.edge_bits = job->edge_bits;
    hdr.way_count = idx->way_count;
    hdr.bridge_edges = idx->bridge_edges;
    hdr.endpoint_count = idx->endpoint_count;
    hdr.mask = idx->mask;
    hdr.endpoint_slots = endpoint_slots;
    hdr.scan_count = idx->scan_count;
    hdr.side_filled[0] = idx->side_filled[0];
    hdr.side_filled[1] = idx->side_filled[1];
    hdr.dual_capacity = idx->dual_capacity;
    hdr.dual_mask = idx->dual_mask;
    hdr.dual_filled = idx->dual_filled;
    hdr.key_words[0] = job->keys.k0;
    hdr.key_words[1] = job->keys.k1;
    hdr.key_words[2] = job->keys.k2;
    hdr.key_words[3] = job->keys.k3;

    const uint64_t side_bytes = endpoint_slots * (uint64_t)sizeof(uint32_t);
    uint32_t ok =
        m1rsi_lace_sparse_lift_write_all(fd, &hdr, (uint64_t)sizeof(hdr)) &&
        m1rsi_lace_sparse_lift_write_all(fd, idx->side_edges[0], side_bytes) &&
        m1rsi_lace_sparse_lift_write_all(fd, idx->side_edges[1], side_bytes) &&
        m1rsi_lace_sparse_lift_write_all(fd, idx->side_other[0], side_bytes) &&
        m1rsi_lace_sparse_lift_write_all(fd, idx->side_other[1], side_bytes);
    if (ok && idx->dual_capacity != 0u) {
        ok = m1rsi_lace_sparse_lift_write_all(fd, idx->dual_keys, idx->dual_capacity * (uint64_t)sizeof(uint64_t)) &&
             m1rsi_lace_sparse_lift_write_all(fd, idx->dual_edges, idx->dual_capacity * (uint64_t)sizeof(uint32_t));
    }
    if (ok) fsync(fd);
    if (close(fd) != 0) ok = 0u;
    if (ok && rename(tmp_path, path) == 0) {
        fprintf(stderr,
                "m1rsi: lace_sparse_lift_index_file_store bits=%u ways=%u bridge_edges=%u scanned=%llu bytes=%llu path=%s graph_materialized=0 fixed_endpoint_preimage=0\n",
                idx->bits,
                idx->way_count,
                idx->bridge_edges,
                (unsigned long long)idx->scan_count,
                (unsigned long long)expected,
                path);
        return 1u;
    }
    unlink(tmp_path);
    return 0u;
}

static void m1rsi_lace_sparse_lift_insert_side(M1RsiLaceSparseLiftIndex *idx, uint32_t side, uint32_t endpoint, uint32_t other_endpoint, uint32_t edge) {
    if (!idx || side > 1u || !idx->side_edges[side]) return;
    const uint64_t base = (uint64_t)(endpoint & idx->mask) * (uint64_t)idx->way_count;
    for (uint32_t w = 0u; w < idx->way_count; ++w) {
        if (idx->side_edges[side][base + (uint64_t)w] == 0xffffffffu) {
            idx->side_edges[side][base + (uint64_t)w] = edge;
            if (idx->side_other[side]) idx->side_other[side][base + (uint64_t)w] = other_endpoint;
            idx->side_filled[side] += 1u;
            return;
        }
    }
}

static uint32_t m1rsi_lace_sparse_lift_insert_side_atomic(M1RsiLaceSparseLiftIndex *idx, uint32_t side, uint32_t endpoint, uint32_t other_endpoint, uint32_t edge) {
    if (!idx || side > 1u || !idx->side_edges[side]) return 0u;
    const uint64_t base = (uint64_t)(endpoint & idx->mask) * (uint64_t)idx->way_count;
    for (uint32_t w = 0u; w < idx->way_count; ++w) {
        uint32_t *slot = &idx->side_edges[side][base + (uint64_t)w];
        if (__sync_bool_compare_and_swap(slot, 0xffffffffu, edge)) {
            if (idx->side_other[side]) idx->side_other[side][base + (uint64_t)w] = other_endpoint;
            return 1u;
        }
    }
    return 0u;
}

typedef struct M1RsiLaceSparseIndexWorker {
    const M1RsiJob *job;
    M1RsiLaceSparseLiftIndex *idx;
    uint64_t edge_start;
    uint64_t stride;
    uint64_t edge_mask;
    uint64_t begin;
    uint64_t end;
    uint64_t side_filled[2];
} M1RsiLaceSparseIndexWorker;

static void *m1rsi_lace_sparse_index_worker_main(void *raw) {
    M1RsiLaceSparseIndexWorker *w = (M1RsiLaceSparseIndexWorker *)raw;
    if (!w || !w->job || !w->idx) return NULL;
    for (uint64_t i = w->begin; i < w->end; ++i) {
        const uint64_t edge = (w->edge_start + (w->stride * i)) & w->edge_mask;
        if (edge == 0xffffffffull) continue;
        const uint32_t v_endpoint = m1rsi_endpoint(w->job->keys, w->job->edge_bits, edge, 1u);
        const uint32_t u_endpoint = m1rsi_endpoint(w->job->keys, w->job->edge_bits, edge, 0u);
        const uint32_t v_low = v_endpoint & w->idx->mask;
        const uint32_t u_low = u_endpoint & w->idx->mask;
        w->side_filled[1] += m1rsi_lace_sparse_lift_insert_side_atomic(w->idx, 1u, v_low, u_endpoint, (uint32_t)edge);
        w->side_filled[0] += m1rsi_lace_sparse_lift_insert_side_atomic(w->idx, 0u, u_low, v_endpoint, (uint32_t)edge);
    }
    return NULL;
}

static uint32_t m1rsi_lace_sparse_lift_pick_side(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t score_bits,
    uint64_t salt,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edge,
    uint32_t *out_other_endpoint) {
    if (!job || !idx || side > 1u || !idx->side_edges[side] || !out_edge || idx->way_count == 0u) return 0u;
    if (score_bits < idx->bits) score_bits = idx->bits;
    if (score_bits > job->edge_bits) score_bits = job->edge_bits;
    const uint32_t score_mask = score_bits >= 32u ? 0xffffffffu : ((1u << score_bits) - 1u);
    const uint64_t base = (uint64_t)(want_endpoint & idx->mask) * (uint64_t)idx->way_count;
    const uint32_t start = (uint32_t)(m1rsi_lace_mix64(salt) % (uint64_t)idx->way_count);
    uint32_t best_score = UINT32_MAX;
    uint64_t best_edge = 0u;
    uint32_t best_other = 0u;
    uint32_t found = 0u;
    for (uint32_t attempt = 0u; attempt < idx->way_count; ++attempt) {
        const uint32_t w = (start + attempt) % idx->way_count;
        const uint32_t candidate32 = idx->side_edges[side][base + (uint64_t)w];
        if (candidate32 == 0xffffffffu) continue;
        const uint64_t candidate = (uint64_t)candidate32 & edge_mask;
        if (!m1rsi_lace_edge_distinct_prefix(edges, edge_count, candidate)) continue;
        const uint32_t candidate_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, candidate, side);
        const uint32_t diff = (candidate_endpoint ^ want_endpoint) & score_mask;
        const uint32_t score = m1rsi_lace_popcount32(diff);
        if (!found || score < best_score) {
            best_score = score;
            best_edge = candidate;
            best_other = idx->side_other[side] ? idx->side_other[side][base + (uint64_t)w] : 0u;
            found = 1u;
            if (score == 0u) break;
        }
    }
    if (!found) return 0u;
    *out_edge = best_edge;
    if (out_other_endpoint) *out_other_endpoint = best_other;
    return 1u;
}

typedef struct M1RsiLaceBridge2Pick {
    uint64_t edge_a;
    uint64_t edge_b;
    uint32_t score;
} M1RsiLaceBridge2Pick;

/*
 * terminal_bridge_obligation_helper: the final two-edge bridge is a born
 * verifier obligation, not a lower-bit support hint.  Keep the side endpoint
 * and sibling-other-endpoint tests in one place so beam and scalar template
 * generation cannot diverge or silently accept a bridge below return_bits.
 */
static uint32_t m1rsi_lace_sparse_lift_pick_side_bridge2(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t side,
    uint32_t want_endpoint_a,
    uint32_t want_endpoint_b,
    uint32_t score_bits,
    uint32_t require_score_zero,
    uint64_t salt,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    M1RsiLaceBridge2Pick *out) {
    if (!job || !idx || side > 1u || !idx->side_edges[side] || !idx->side_other[side] ||
        !out || idx->way_count == 0u) {
        return 0u;
    }
    if (score_bits < idx->bits) score_bits = idx->bits;
    if (score_bits > job->edge_bits) score_bits = job->edge_bits;
    const uint32_t score_mask = score_bits >= 32u ? 0xffffffffu : ((1u << score_bits) - 1u);
    const uint64_t base_a = (uint64_t)(want_endpoint_a & idx->mask) * (uint64_t)idx->way_count;
    const uint64_t base_b = (uint64_t)(want_endpoint_b & idx->mask) * (uint64_t)idx->way_count;
    const uint32_t start_a = (uint32_t)(m1rsi_lace_mix64(salt ^ 0x6132627269646765ull) % (uint64_t)idx->way_count);
    const uint32_t start_b0 = (uint32_t)(m1rsi_lace_mix64(salt ^ 0x6232627269646765ull) % (uint64_t)idx->way_count);
    uint32_t best_score = UINT32_MAX;
    M1RsiLaceBridge2Pick best;
    memset(&best, 0, sizeof(best));
    uint32_t found = 0u;
    for (uint32_t attempt_a = 0u; attempt_a < idx->way_count; ++attempt_a) {
        const uint32_t wa = (start_a + attempt_a) % idx->way_count;
        const uint32_t candidate_a32 = idx->side_edges[side][base_a + (uint64_t)wa];
        if (candidate_a32 == 0xffffffffu) continue;
        const uint64_t candidate_a = (uint64_t)candidate_a32 & edge_mask;
        if (!m1rsi_lace_edge_distinct_prefix(edges, edge_count, candidate_a)) continue;
        const uint32_t endpoint_a_full = m1rsi_endpoint(job->keys, job->edge_bits, candidate_a, side);
        const uint32_t other_a = idx->side_other[side][base_a + (uint64_t)wa];
        for (uint32_t attempt_b = 0u; attempt_b < idx->way_count; ++attempt_b) {
            const uint32_t wb = (start_b0 + attempt_b) % idx->way_count;
            const uint32_t candidate_b32 = idx->side_edges[side][base_b + (uint64_t)wb];
            if (candidate_b32 == 0xffffffffu) continue;
            const uint64_t candidate_b = (uint64_t)candidate_b32 & edge_mask;
            if (candidate_b == candidate_a) continue;
            if (!m1rsi_lace_edge_distinct_prefix(edges, edge_count, candidate_b)) continue;
            const uint32_t endpoint_b_full = m1rsi_endpoint(job->keys, job->edge_bits, candidate_b, side);
            const uint32_t other_b = idx->side_other[side][base_b + (uint64_t)wb];
            if (((other_a ^ other_b) & idx->mask) != 1u) continue;
            const uint32_t diff_a = (endpoint_a_full ^ want_endpoint_a) & score_mask;
            const uint32_t diff_b = (endpoint_b_full ^ want_endpoint_b) & score_mask;
            const uint32_t diff_bridge = ((other_a ^ other_b) ^ 1u) & score_mask;
            const uint32_t score = m1rsi_lace_popcount32(diff_a) + m1rsi_lace_popcount32(diff_b) + m1rsi_lace_popcount32(diff_bridge);
            if (!found || score < best_score) {
                best_score = score;
                best.edge_a = candidate_a;
                best.edge_b = candidate_b;
                best.score = score;
                found = 1u;
                if (score == 0u) break;
            }
        }
        if (found && best_score == 0u) break;
    }
    if (!found) return 0u;
    if (require_score_zero && best.score != 0u) return 0u;
    *out = best;
    return 1u;
}

static uint32_t m1rsi_lace_sparse_lift_lookup_dual(
    const M1RsiLaceSparseLiftIndex *idx,
    uint64_t key,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edge);

typedef struct M1RsiLaceSparseBeamState {
    uint64_t edges[M1RSI_PROOFSIZE];
    uint32_t edge_count;
    uint32_t current_endpoint;
    uint32_t start_u_endpoint;
    uint32_t score;
} M1RsiLaceSparseBeamState;

static int m1rsi_lace_sparse_beam_state_cmp(const void *a, const void *b) {
    const M1RsiLaceSparseBeamState *sa = (const M1RsiLaceSparseBeamState *)a;
    const M1RsiLaceSparseBeamState *sb = (const M1RsiLaceSparseBeamState *)b;
    if (sa->score < sb->score) return -1;
    if (sa->score > sb->score) return 1;
    if (sa->edges[sa->edge_count ? sa->edge_count - 1u : 0u] < sb->edges[sb->edge_count ? sb->edge_count - 1u : 0u]) return -1;
    if (sa->edges[sa->edge_count ? sa->edge_count - 1u : 0u] > sb->edges[sb->edge_count ? sb->edge_count - 1u : 0u]) return 1;
    return 0;
}

static uint32_t m1rsi_lace_sparse_template_beam_width(const M1RsiLaceSparseLiftIndex *idx) {
    (void)idx;
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_BEAM", 1u, 1u, 1024u);
}

static uint32_t m1rsi_lace_sparse_default_pick_bits(const M1RsiJob *job, const M1RsiLaceSparseLiftIndex *idx) {
    if (!job || !idx || idx->bits == 0u || job->edge_bits == 0u || idx->bits > job->edge_bits) return 0u;
    uint32_t pick_bits = idx->bits;
    if (idx->bits >= 28u && pick_bits + 2u > pick_bits) pick_bits += 2u;
    if (pick_bits > job->edge_bits) pick_bits = job->edge_bits;
    return pick_bits;
}

static uint32_t m1rsi_lace_sparse_pick_bits(const M1RsiJob *job, const M1RsiLaceSparseLiftIndex *idx) {
    const uint32_t fallback = m1rsi_lace_sparse_default_pick_bits(job, idx);
    if (fallback == 0u) return 0u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.pick_bits != 0u) {
        uint32_t pick_bits = g_lace_sparse_config_override.pick_bits;
        if (pick_bits < idx->bits) pick_bits = idx->bits;
        if (pick_bits > job->edge_bits) pick_bits = job->edge_bits;
        return pick_bits;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_PICK_BITS", fallback, idx->bits, job->edge_bits);
}

static uint32_t m1rsi_lace_sparse_return_bits(const M1RsiJob *job, const M1RsiLaceSparseLiftIndex *idx) {
    if (!job || !idx || idx->bits == 0u || job->edge_bits == 0u || idx->bits > job->edge_bits) return 0u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.return_bits != 0u) {
        uint32_t return_bits = g_lace_sparse_config_override.return_bits;
        if (return_bits < idx->bits) return_bits = idx->bits;
        if (return_bits > job->edge_bits) return_bits = job->edge_bits;
        return return_bits;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_RETURN_BITS", idx->bits, idx->bits, job->edge_bits);
}

static uint32_t m1rsi_lace_sparse_bridge_first_probes(const M1RsiLaceSparseLiftIndex *idx) {
    const uint32_t default_probes = (idx && idx->bridge_edges >= 2u && idx->bits >= 28u) ? (1u << 20u) : 0u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.bridge_first_probes != 0u) {
        uint32_t probes = g_lace_sparse_config_override.bridge_first_probes;
        if (probes > (1u << 30u)) probes = 1u << 30u;
        return probes;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_BRIDGE_FIRST_PROBES", default_probes, 0u, 1u << 30u);
}

static uint32_t m1rsi_lace_sparse_bridge_catalog_capacity(uint32_t probe_count) {
    uint32_t fallback = probe_count < (1u << 16u) ? probe_count : (1u << 16u);
    if (fallback == 0u) fallback = 1u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.bridge_catalog_cap != 0u) {
        uint32_t cap = g_lace_sparse_config_override.bridge_catalog_cap;
        if (cap > (1u << 24u)) cap = 1u << 24u;
        return cap == 0u ? 1u : cap;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_BRIDGE_CATALOG_CAP", fallback, 1u, 1u << 24u);
}

static uint32_t m1rsi_lace_sparse_path_mitm_fanout(const M1RsiLaceSparseLiftIndex *idx) {
    const uint32_t fallback = (idx && idx->bridge_edges >= 2u) ? (1u << 13u) : 0u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.path_mitm_fanout != 0u) {
        uint32_t fanout = g_lace_sparse_config_override.path_mitm_fanout;
        if (fanout > (1u << 20u)) fanout = 1u << 20u;
        return fanout;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_PATH_MITM_FANOUT", fallback, 0u, 1u << 20u);
}

static uint32_t m1rsi_lace_sparse_path_mitm_left_steps(void) {
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.path_mitm_left != 0u) {
        uint32_t left = g_lace_sparse_config_override.path_mitm_left;
        if (left < 1u) left = 1u;
        if (left > M1RSI_PROOFSIZE - 4u) left = M1RSI_PROOFSIZE - 4u;
        return left;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_PATH_MITM_LEFT", 19u, 1u, M1RSI_PROOFSIZE - 4u);
}

typedef struct M1RsiLaceLocalDemandCandidate {
    uint64_t edge;
    uint32_t other_endpoint;
} M1RsiLaceLocalDemandCandidate;

enum {
    M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS = 2048u,
    M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_SLOTS = 4096u,
    M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_WAYS = 64u
};

typedef struct M1RsiLaceLocalDemandBucketCacheEntry {
    uint64_t key_mix;
    uint64_t edge_mask;
    uint32_t want_low;
    uint32_t bits;
    uint32_t side;
    uint32_t source_metal;
    uint32_t count;
    uint64_t edges[M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_WAYS];
    uint32_t other_endpoints[M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_WAYS];
} M1RsiLaceLocalDemandBucketCacheEntry;

typedef struct M1RsiLaceLocalTemplateCache {
    uint32_t valid;
    uint32_t edge_bits;
    uint32_t lift_bits;
    uint64_t edge_mask;
    uint64_t base_start;
    M1RsiKeys keys;
    uint32_t count;
    uint32_t capacity;
    M1RsiLaceTemplate42 *templates;
} M1RsiLaceLocalTemplateCache;

#define M1RSI_LACE_LOCAL_TEMPLATE_CACHE_SLOTS 8u

static pthread_mutex_t g_m1rsi_lace_local_demand_bucket_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static M1RsiLaceLocalDemandBucketCacheEntry g_m1rsi_lace_local_demand_bucket_cache[M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_SLOTS];
static pthread_mutex_t g_m1rsi_lace_local_template_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static M1RsiLaceLocalTemplateCache g_m1rsi_lace_local_template_cache[M1RSI_LACE_LOCAL_TEMPLATE_CACHE_SLOTS];
static uint32_t g_m1rsi_lace_local_template_cache_next;

typedef struct M1RsiLaceLocalDemandWorker {
    const M1RsiJob *job;
    const uint64_t *prefix_edges;
    M1RsiLaceLocalDemandCandidate *out;
    atomic_uint *out_count;
    atomic_uint *stop_flag;
    uint64_t edge_start;
    uint64_t stride;
    uint64_t edge_mask;
    uint32_t side;
    uint32_t want_endpoint;
    uint32_t bits;
    uint32_t mask;
    uint32_t prefix_count;
    uint32_t cap;
    uint32_t begin;
    uint32_t end;
    uint32_t stop_at_first;
} M1RsiLaceLocalDemandWorker;

__attribute__((weak)) uint32_t m1rsi_metal_lace_local_demand_fill(const M1RsiJob *job, uint32_t side, uint32_t want_endpoint, uint32_t bits, uint64_t edge_start, uint64_t stride, uint64_t edge_mask, const uint64_t *prefix_edges, uint32_t prefix_count, uint64_t *out_edges, uint32_t *out_other_endpoints, uint32_t cap, uint32_t trials, uint32_t *out_count, uint32_t *out_overflow) {
    (void)job;
    (void)side;
    (void)want_endpoint;
    (void)bits;
    (void)edge_start;
    (void)stride;
    (void)edge_mask;
    (void)prefix_edges;
    (void)prefix_count;
    (void)out_edges;
    (void)out_other_endpoints;
    (void)cap;
    (void)trials;
    if (out_count) *out_count = 0u;
    if (out_overflow) *out_overflow = 0u;
    return M1RSI_STATUS_INTERNAL;
}

__attribute__((weak)) uint32_t m1rsi_metal_lace_local_demand_fill_pair(const M1RsiJob *job, uint32_t side_a, uint32_t want_endpoint_a, uint32_t side_b, uint32_t want_endpoint_b, uint32_t bits, uint64_t edge_start_a, uint64_t stride_a, uint64_t edge_start_b, uint64_t stride_b, uint64_t edge_mask, const uint64_t *prefix_edges, uint32_t prefix_count, uint64_t *out_edges_a, uint32_t *out_other_endpoints_a, uint32_t cap_a, uint64_t *out_edges_b, uint32_t *out_other_endpoints_b, uint32_t cap_b, uint32_t trials, uint32_t *out_count_a, uint32_t *out_overflow_a, uint32_t *out_count_b, uint32_t *out_overflow_b) {
    (void)job;
    (void)side_a;
    (void)want_endpoint_a;
    (void)side_b;
    (void)want_endpoint_b;
    (void)bits;
    (void)edge_start_a;
    (void)stride_a;
    (void)edge_start_b;
    (void)stride_b;
    (void)edge_mask;
    (void)prefix_edges;
    (void)prefix_count;
    (void)out_edges_a;
    (void)out_other_endpoints_a;
    (void)cap_a;
    (void)out_edges_b;
    (void)out_other_endpoints_b;
    (void)cap_b;
    (void)trials;
    if (out_count_a) *out_count_a = 0u;
    if (out_overflow_a) *out_overflow_a = 0u;
    if (out_count_b) *out_count_b = 0u;
    if (out_overflow_b) *out_overflow_b = 0u;
    return M1RSI_STATUS_INTERNAL;
}

__attribute__((weak)) uint32_t m1rsi_metal_lace_local_demand_bridge_close(const M1RsiJob *job, uint32_t side_a, uint32_t want_endpoint_a, uint32_t side_b, uint32_t want_endpoint_b, uint32_t bits, uint64_t edge_start_a, uint64_t stride_a, uint64_t edge_start_b, uint64_t stride_b, uint64_t edge_mask, const uint64_t *prefix_edges, uint32_t prefix_count, uint32_t cap, uint32_t trials, uint64_t *out_edge_a, uint64_t *out_edge_b, uint32_t *out_count_a, uint32_t *out_overflow_a, uint32_t *out_count_b, uint32_t *out_overflow_b) {
    (void)job;
    (void)side_a;
    (void)want_endpoint_a;
    (void)side_b;
    (void)want_endpoint_b;
    (void)bits;
    (void)edge_start_a;
    (void)stride_a;
    (void)edge_start_b;
    (void)stride_b;
    (void)edge_mask;
    (void)prefix_edges;
    (void)prefix_count;
    (void)cap;
    (void)trials;
    if (out_edge_a) *out_edge_a = 0u;
    if (out_edge_b) *out_edge_b = 0u;
    if (out_count_a) *out_count_a = 0u;
    if (out_overflow_a) *out_overflow_a = 0u;
    if (out_count_b) *out_count_b = 0u;
    if (out_overflow_b) *out_overflow_b = 0u;
    return M1RSI_STATUS_INTERNAL;
}

__attribute__((weak)) uint32_t m1rsi_metal_lace_local_demand_chain_prefix(const M1RsiJob *job, uint32_t bits, uint64_t seed, uint64_t key_mix, uint64_t edge_mask, uint32_t chain_pairs, uint32_t trials, uint64_t *out_edges, uint32_t *out_current_endpoint, uint32_t *out_start_u_endpoint, uint32_t *out_steps, uint32_t *out_failed_step) {
    (void)job;
    (void)bits;
    (void)seed;
    (void)key_mix;
    (void)edge_mask;
    (void)chain_pairs;
    (void)trials;
    if (out_edges) memset(out_edges, 0, M1RSI_PROOFSIZE * sizeof(uint64_t));
    if (out_current_endpoint) *out_current_endpoint = 0u;
    if (out_start_u_endpoint) *out_start_u_endpoint = 0u;
    if (out_steps) *out_steps = 0u;
    if (out_failed_step) *out_failed_step = 0u;
    return M1RSI_STATUS_INTERNAL;
}

__attribute__((weak)) uint32_t m1rsi_metal_lace_local_demand_chain_bridge_close(const M1RsiJob *job, uint32_t bits, uint64_t seed, uint64_t key_mix, uint64_t edge_mask, uint32_t chain_pairs, uint32_t chain_trials, uint32_t bridge_trials, uint32_t cap, uint64_t *out_edges, uint32_t *out_steps, uint32_t *out_failed_step, uint32_t *out_count_a, uint32_t *out_overflow_a, uint32_t *out_count_b, uint32_t *out_overflow_b) {
    (void)job;
    (void)bits;
    (void)seed;
    (void)key_mix;
    (void)edge_mask;
    (void)chain_pairs;
    (void)chain_trials;
    (void)bridge_trials;
    (void)cap;
    if (out_edges) memset(out_edges, 0, M1RSI_PROOFSIZE * sizeof(uint64_t));
    if (out_steps) *out_steps = 0u;
    if (out_failed_step) *out_failed_step = 0u;
    if (out_count_a) *out_count_a = 0u;
    if (out_overflow_a) *out_overflow_a = 0u;
    if (out_count_b) *out_count_b = 0u;
    if (out_overflow_b) *out_overflow_b = 0u;
    return M1RSI_STATUS_INTERNAL;
}

static uint32_t m1rsi_lace_local_demand_enabled(uint32_t bits) {
    const uint32_t max_bits = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_MAX_BITS", 16u, 1u, 32u);
    const uint32_t enabled = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND", 0u, 0u, 1u);
    return enabled && bits <= max_bits;
}

static uint32_t m1rsi_lace_local_demand_metal_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_METAL", 1u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_require_metal(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_REQUIRE_METAL", 0u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_chain_metal_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_CHAIN_METAL", 1u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_bridge_close_metal_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_BRIDGE_CLOSE_METAL", 1u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_chain_bridge_close_metal_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_CHAIN_BRIDGE_CLOSE_METAL", 1u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_bucket_cache_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE", 1u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_bucket_cache_log_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LOG_LOCAL_DEMAND_BUCKET_CACHE", 0u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_template_cache_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_TEMPLATE_CACHE", 1u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_template_cache_log_enabled(void) {
    return m1rsi_lace_env_u32("M1RSI_LOG_LOCAL_DEMAND_TEMPLATE_CACHE", 0u, 0u, 1u);
}

static uint32_t m1rsi_lace_local_demand_thread_count(uint32_t trials) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t fallback = (trials >= (1u << 20u) && n > 1) ? (uint32_t)n : 1u;
    if (fallback > 32u) fallback = 32u;
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_THREADS", fallback, 1u, 64u);
}

static uint32_t m1rsi_lace_local_demand_trials(uint32_t bits) {
    const uint32_t fallback = bits <= 13u ? (1u << 18u) : (bits <= 18u ? (1u << 20u) : (1u << 22u));
    if (bits > 13u) {
        const uint32_t high = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_HIGH_TRIALS", fallback, 1024u, 1u << 26u);
        return high < fallback ? fallback : high;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_TRIALS", fallback, 1024u, 1u << 26u);
}

static uint32_t m1rsi_lace_local_demand_bridge_trials(uint32_t bits) {
    const uint32_t fallback = bits <= 13u ? (1u << 20u) : (bits <= 16u ? (1u << 25u) : (bits <= 18u ? (1u << 27u) : (1u << 30u)));
    if (bits > 13u) {
        const uint32_t high = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_HIGH_BRIDGE_TRIALS", fallback, 1024u, 1u << 30u);
        return high < fallback ? fallback : high;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_BRIDGE_TRIALS", fallback, 1024u, 1u << 30u);
}

static uint32_t m1rsi_lace_local_demand_way_cap(void) {
    return m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_WAYS", 512u, 4u, 1u << 16u);
}

static void *m1rsi_lace_local_demand_worker_main(void *raw) {
    M1RsiLaceLocalDemandWorker *w = (M1RsiLaceLocalDemandWorker *)raw;
    if (!w || !w->job || !w->out || !w->out_count || !w->stop_flag) return NULL;
    uint64_t edge = (w->edge_start + (w->stride * (uint64_t)w->begin)) & w->edge_mask;
    for (uint32_t t = w->begin; t < w->end; ++t) {
        if (atomic_load_explicit(w->stop_flag, memory_order_relaxed)) break;
        if (edge != 0xffffffffull && m1rsi_lace_edge_distinct_prefix(w->prefix_edges, w->prefix_count, edge)) {
            const uint32_t endpoint = m1rsi_endpoint(w->job->keys, w->job->edge_bits, edge, w->side);
            if (((endpoint ^ w->want_endpoint) & w->mask) == 0u) {
                if (w->stop_at_first) {
                    uint32_t expected = 0u;
                    if (atomic_compare_exchange_strong_explicit(
                            w->out_count,
                            &expected,
                            1u,
                            memory_order_relaxed,
                            memory_order_relaxed)) {
                        w->out[0].edge = edge;
                        w->out[0].other_endpoint = m1rsi_endpoint(w->job->keys, w->job->edge_bits, edge, w->side ^ 1u);
                        atomic_store_explicit(w->stop_flag, 1u, memory_order_relaxed);
                        break;
                    }
                } else {
                    const uint32_t slot = atomic_fetch_add_explicit(w->out_count, 1u, memory_order_relaxed);
                    if (slot < w->cap) {
                        w->out[slot].edge = edge;
                        w->out[slot].other_endpoint = m1rsi_endpoint(w->job->keys, w->job->edge_bits, edge, w->side ^ 1u);
                        if (slot + 1u >= w->cap) {
                            atomic_store_explicit(w->stop_flag, 1u, memory_order_relaxed);
                            break;
                        }
                    } else {
                        atomic_store_explicit(w->stop_flag, 1u, memory_order_relaxed);
                        break;
                    }
                }
            }
        }
        edge = (edge + w->stride) & w->edge_mask;
    }
    return NULL;
}

typedef struct M1RsiLaceLocalDemandSchedule {
    uint64_t edge_start;
    uint64_t stride;
} M1RsiLaceLocalDemandSchedule;

static M1RsiLaceLocalDemandSchedule m1rsi_lace_local_demand_schedule(
    const M1RsiJob *job,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t mask,
    uint64_t salt,
    uint64_t edge_mask) {
    M1RsiLaceLocalDemandSchedule out;
    const uint64_t seed = m1rsi_lace_mix64(
        0x4c4f43414c444d44ull ^
        m1rsi_lace_key_mix(job) ^
        ((uint64_t)side * 0x94d049bb133111ebull) ^
        ((uint64_t)(want_endpoint & mask) * 0xd6e8feb86659fd93ull) ^
        salt);
    out.stride = m1rsi_lace_mix64(seed ^ 0x64656d616e647374ull) | 1ull;
    out.edge_start = m1rsi_lace_mix64(seed ^ 0x64656d616e646261ull) & edge_mask;
    return out;
}

static uint32_t m1rsi_lace_local_demand_bucket_cache_slot(
    uint64_t key_mix,
    uint64_t edge_mask,
    uint32_t side,
    uint32_t want_low,
    uint32_t bits) {
    uint64_t h = key_mix ^
        (edge_mask * 0x9e3779b97f4a7c15ull) ^
        ((uint64_t)side * 0x94d049bb133111ebull) ^
        ((uint64_t)bits * 0xbf58476d1ce4e5b9ull) ^
        ((uint64_t)want_low * 0xd6e8feb86659fd93ull);
    h = m1rsi_lace_mix64(h);
    return (uint32_t)(h & (uint64_t)(M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_SLOTS - 1u));
}

static uint32_t m1rsi_lace_local_demand_bucket_cache_lookup(
    const M1RsiJob *job,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t bits,
    uint32_t mask,
    uint64_t edge_mask,
    const uint64_t *prefix_edges,
    uint32_t prefix_count,
    M1RsiLaceLocalDemandCandidate *out,
    uint32_t cap,
    uint32_t *out_count) {
    if (out_count) *out_count = 0u;
    if (!job || !out || cap == 0u || !m1rsi_lace_local_demand_bucket_cache_enabled()) return 0u;
    const uint64_t key_mix = m1rsi_lace_key_mix(job);
    const uint32_t want_low = want_endpoint & mask;
    const uint32_t slot = m1rsi_lace_local_demand_bucket_cache_slot(key_mix, edge_mask, side, want_low, bits);
    pthread_mutex_lock(&g_m1rsi_lace_local_demand_bucket_cache_mutex);
    const M1RsiLaceLocalDemandBucketCacheEntry *entry = &g_m1rsi_lace_local_demand_bucket_cache[slot];
    const uint32_t hit =
        entry->count != 0u &&
        entry->key_mix == key_mix &&
        entry->edge_mask == edge_mask &&
        entry->want_low == want_low &&
        entry->bits == bits &&
        entry->side == side &&
        (!m1rsi_lace_local_demand_require_metal() || entry->source_metal);
    uint32_t count = 0u;
    const uint32_t source_metal = hit ? entry->source_metal : 0u;
    if (hit) {
        for (uint32_t i = 0u; i < entry->count && count < cap; ++i) {
            const uint64_t edge = entry->edges[i];
            if (!m1rsi_lace_edge_distinct_prefix(prefix_edges, prefix_count, edge)) continue;
            out[count].edge = edge;
            out[count].other_endpoint = entry->other_endpoints[i];
            count += 1u;
        }
    }
    pthread_mutex_unlock(&g_m1rsi_lace_local_demand_bucket_cache_mutex);
    if (!hit) return 0u;
    if (out_count) *out_count = count;
    if (count != 0u && m1rsi_lace_local_demand_bucket_cache_log_enabled()) {
        fprintf(stderr,
                "m1rsi: lace_local_demand_bucket_cache_hit=1 side=%u bits=%u want_low=%u count=%u cap=%u source_metal=%u born_endpoint_bucket=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                side,
                bits,
                want_low,
                count,
                cap,
                source_metal);
    }
    return 1u;
}

static void m1rsi_lace_local_demand_bucket_cache_store(
    const M1RsiJob *job,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t bits,
    uint32_t mask,
    uint64_t edge_mask,
    const M1RsiLaceLocalDemandCandidate *candidates,
    uint32_t count,
    uint32_t source_metal) {
    if (!job || !candidates || count == 0u || !m1rsi_lace_local_demand_bucket_cache_enabled()) return;
    const uint64_t key_mix = m1rsi_lace_key_mix(job);
    const uint32_t want_low = want_endpoint & mask;
    const uint32_t slot = m1rsi_lace_local_demand_bucket_cache_slot(key_mix, edge_mask, side, want_low, bits);
    const uint32_t stored = count < M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_WAYS ? count : M1RSI_LACE_LOCAL_DEMAND_BUCKET_CACHE_WAYS;
    pthread_mutex_lock(&g_m1rsi_lace_local_demand_bucket_cache_mutex);
    M1RsiLaceLocalDemandBucketCacheEntry *entry = &g_m1rsi_lace_local_demand_bucket_cache[slot];
    entry->key_mix = key_mix;
    entry->edge_mask = edge_mask;
    entry->want_low = want_low;
    entry->bits = bits;
    entry->side = side;
    entry->source_metal = source_metal ? 1u : 0u;
    entry->count = stored;
    for (uint32_t i = 0u; i < stored; ++i) {
        entry->edges[i] = candidates[i].edge;
        entry->other_endpoints[i] = candidates[i].other_endpoint;
    }
    pthread_mutex_unlock(&g_m1rsi_lace_local_demand_bucket_cache_mutex);
    if (m1rsi_lace_local_demand_bucket_cache_log_enabled()) {
        fprintf(stderr,
                "m1rsi: lace_local_demand_bucket_cache_store=1 side=%u bits=%u want_low=%u stored=%u source_metal=%u born_endpoint_bucket=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                side,
                bits,
                want_low,
                stored,
                source_metal ? 1u : 0u);
    }
}

static uint32_t m1rsi_lace_local_template_cache_lookup(
    const M1RsiJob *job,
    uint32_t lift_bits,
    uint64_t base_start,
    uint64_t edge_mask,
    M1RsiLaceTemplate42 *out,
    uint32_t cap) {
    if (!job || !out || cap == 0u || !m1rsi_lace_local_template_cache_enabled()) return 0u;
    pthread_mutex_lock(&g_m1rsi_lace_local_template_cache_mutex);
    const M1RsiLaceLocalTemplateCache *cache = NULL;
    for (uint32_t slot = 0u; slot < M1RSI_LACE_LOCAL_TEMPLATE_CACHE_SLOTS; ++slot) {
        const M1RsiLaceLocalTemplateCache *candidate = &g_m1rsi_lace_local_template_cache[slot];
        if (candidate->valid &&
            candidate->templates &&
            candidate->count != 0u &&
            candidate->edge_bits == job->edge_bits &&
            candidate->lift_bits == lift_bits &&
            candidate->edge_mask == edge_mask &&
            m1rsi_lace_keys_equal(candidate->keys, job->keys)) {
            cache = candidate;
            break;
        }
    }
    uint32_t copied = 0u;
    uint32_t base_adjusted = 0u;
    if (cache) {
        copied = cache->count < cap ? cache->count : cap;
        base_adjusted = base_start == cache->base_start ? 0u : 1u;
        for (uint32_t t = 0u; t < copied; ++t) {
            for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
                const uint64_t absolute_edge = (cache->base_start + cache->templates[t].offsets[i]) & edge_mask;
                out[t].offsets[i] = (absolute_edge - base_start) & edge_mask;
            }
        }
    }
    pthread_mutex_unlock(&g_m1rsi_lace_local_template_cache_mutex);
    if (copied != 0u) {
        fprintf(stderr,
                "m1rsi: lace_local_demand_template_cache_hit=1 bits=%u copied=%u base_adjusted=%u correctness_keyed=1 localized_build=1 likelihood_gated_build=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                lift_bits,
                copied,
                base_adjusted);
    }
    return copied;
}

static void m1rsi_lace_local_template_cache_store(
    const M1RsiJob *job,
    uint32_t lift_bits,
    uint64_t base_start,
    uint64_t edge_mask,
    const M1RsiLaceTemplate42 *templates,
    uint32_t count) {
    if (!job || !templates || count == 0u || !m1rsi_lace_local_template_cache_enabled()) return;
    uint32_t limit = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_TEMPLATE_CACHE_MAX", count, 1u, M1RSI_LACE_TEMPLATE_MAX);
    if (limit > count) limit = count;
    pthread_mutex_lock(&g_m1rsi_lace_local_template_cache_mutex);
    M1RsiLaceLocalTemplateCache *cache = NULL;
    for (uint32_t slot = 0u; slot < M1RSI_LACE_LOCAL_TEMPLATE_CACHE_SLOTS; ++slot) {
        M1RsiLaceLocalTemplateCache *candidate = &g_m1rsi_lace_local_template_cache[slot];
        if (candidate->valid &&
            candidate->edge_bits == job->edge_bits &&
            candidate->lift_bits == lift_bits &&
            candidate->edge_mask == edge_mask &&
            m1rsi_lace_keys_equal(candidate->keys, job->keys)) {
            cache = candidate;
            break;
        }
    }
    if (!cache) {
        for (uint32_t slot = 0u; slot < M1RSI_LACE_LOCAL_TEMPLATE_CACHE_SLOTS; ++slot) {
            M1RsiLaceLocalTemplateCache *candidate = &g_m1rsi_lace_local_template_cache[slot];
            if (!candidate->valid) {
                cache = candidate;
                break;
            }
        }
    }
    if (!cache) {
        cache = &g_m1rsi_lace_local_template_cache[
            g_m1rsi_lace_local_template_cache_next++ % M1RSI_LACE_LOCAL_TEMPLATE_CACHE_SLOTS];
    }
    if (cache->capacity < limit) {
        M1RsiLaceTemplate42 *next = (M1RsiLaceTemplate42 *)realloc(cache->templates, (size_t)limit * sizeof(*next));
        if (!next) {
            pthread_mutex_unlock(&g_m1rsi_lace_local_template_cache_mutex);
            return;
        }
        cache->templates = next;
        cache->capacity = limit;
    }
    memcpy(cache->templates, templates, (size_t)limit * sizeof(*templates));
    cache->valid = 1u;
    cache->edge_bits = job->edge_bits;
    cache->lift_bits = lift_bits;
    cache->edge_mask = edge_mask;
    cache->base_start = base_start;
    cache->keys = job->keys;
    cache->count = limit;
    pthread_mutex_unlock(&g_m1rsi_lace_local_template_cache_mutex);
    if (m1rsi_lace_local_template_cache_log_enabled()) {
        fprintf(stderr,
                "m1rsi: lace_local_demand_template_cache_store=1 bits=%u stored=%u correctness_keyed=1 reusable_support_bank=1 localized_build=1 likelihood_gated_build=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                lift_bits,
                limit);
    }
}

/*
 * A localized construction gate: build only the endpoint bucket demanded by the
 * current born support obligation.  This is not a graph, not an adjacency
 * index, and not a fixed endpoint preimage lane.  The demand endpoint is born
 * by the partial LACE witness state; candidates outside that bucket are never
 * retained.
 */
static uint32_t m1rsi_lace_local_demand_fill(
    const M1RsiJob *job,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t bits,
    uint64_t salt,
    const uint64_t *prefix_edges,
    uint32_t prefix_count,
    uint64_t edge_mask,
    M1RsiLaceLocalDemandCandidate *out,
    uint32_t cap,
    uint32_t trials) {
    if (!job || side > 1u || bits == 0u || bits > job->edge_bits || !out || cap == 0u) return 0u;
    const uint32_t mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
    uint32_t cached_count = 0u;
    if (m1rsi_lace_local_demand_bucket_cache_lookup(
            job,
            side,
            want_endpoint,
            bits,
            mask,
            edge_mask,
            prefix_edges,
            prefix_count,
            out,
            cap,
            &cached_count) && cached_count != 0u) {
        return cached_count;
    }
    const M1RsiLaceLocalDemandSchedule sched = m1rsi_lace_local_demand_schedule(job, side, want_endpoint, mask, salt, edge_mask);
    const uint64_t stride = sched.stride;
    uint64_t edge = sched.edge_start;
    const uint64_t edge_period = edge_mask + 1ull;
    if (m1rsi_lace_local_demand_metal_enabled() && edge_period != 0ull && (uint64_t)trials <= edge_period) {
        uint64_t stack_edges[64];
        uint32_t stack_other[64];
        uint64_t *metal_edges = cap <= 64u ? stack_edges : (uint64_t *)calloc((size_t)cap, sizeof(*metal_edges));
        uint32_t *metal_other = cap <= 64u ? stack_other : (uint32_t *)calloc((size_t)cap, sizeof(*metal_other));
        if (metal_edges && metal_other) {
            uint32_t metal_count = 0u;
            uint32_t metal_overflow = 0u;
            const uint32_t metal_st = m1rsi_metal_lace_local_demand_fill(
                job,
                side,
                want_endpoint,
                bits,
                edge,
                stride,
                edge_mask,
                prefix_edges,
                prefix_count,
                metal_edges,
                metal_other,
                cap,
                trials,
                &metal_count,
                &metal_overflow);
            if (metal_st == M1RSI_STATUS_OK) {
                const uint32_t count = metal_count < cap ? metal_count : cap;
                for (uint32_t i = 0u; i < count; ++i) {
                    out[i].edge = metal_edges[i];
                    out[i].other_endpoint = metal_other[i];
                }
                m1rsi_lace_local_demand_bucket_cache_store(
                    job,
                    side,
                    want_endpoint,
                    bits,
                    mask,
                    edge_mask,
                    out,
                    count,
                    1u);
                if (cap > 1u) {
                    fprintf(stderr,
                            "m1rsi: lace_local_demand_metal_fill=1 side=%u bits=%u count=%u overflow=%u cap=%u trials=%u local_demand_stack_small_cap=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                            side,
                            bits,
                            count,
                            metal_overflow,
                            cap,
                            trials,
                            cap <= 64u ? 1u : 0u);
                }
                if (cap > 64u) {
                    free(metal_edges);
                    free(metal_other);
                }
                return count;
            }
        }
        if (cap > 64u) {
            free(metal_edges);
            free(metal_other);
        }
        if (m1rsi_lace_local_demand_require_metal()) return 0u;
    }
    uint32_t threads = m1rsi_lace_local_demand_thread_count(trials);
    if (threads > trials) threads = trials;
    if (threads > 1u) {
        pthread_t tids[64];
        M1RsiLaceLocalDemandWorker workers[64];
        memset(tids, 0, sizeof(tids));
        memset(workers, 0, sizeof(workers));
        atomic_uint out_count;
        atomic_uint stop_flag;
        atomic_init(&out_count, 0u);
        atomic_init(&stop_flag, 0u);
        uint32_t launched = 0u;
        uint32_t create_failed = 0u;
        for (uint32_t t = 0u; t < threads; ++t) {
            workers[t].job = job;
            workers[t].prefix_edges = prefix_edges;
            workers[t].out = out;
            workers[t].out_count = &out_count;
            workers[t].stop_flag = &stop_flag;
            workers[t].edge_start = edge;
            workers[t].stride = stride;
            workers[t].edge_mask = edge_mask;
            workers[t].side = side;
            workers[t].want_endpoint = want_endpoint;
            workers[t].bits = bits;
            workers[t].mask = mask;
            workers[t].prefix_count = prefix_count;
            workers[t].cap = cap;
            workers[t].begin = (uint32_t)(((uint64_t)trials * (uint64_t)t) / (uint64_t)threads);
            workers[t].end = (uint32_t)(((uint64_t)trials * (uint64_t)(t + 1u)) / (uint64_t)threads);
            workers[t].stop_at_first = cap == 1u ? 1u : 0u;
            if (pthread_create(&tids[t], NULL, m1rsi_lace_local_demand_worker_main, &workers[t]) != 0) {
                create_failed = 1u;
                break;
            }
            launched += 1u;
        }
        for (uint32_t t = 0u; t < launched; ++t) pthread_join(tids[t], NULL);
        if (!create_failed && launched == threads) {
            uint32_t count = atomic_load_explicit(&out_count, memory_order_relaxed);
            count = count < cap ? count : cap;
            m1rsi_lace_local_demand_bucket_cache_store(
                job,
                side,
                want_endpoint,
                bits,
                mask,
                edge_mask,
                out,
                count,
                0u);
            return count;
        }
    }

    uint32_t count = 0u;
    for (uint32_t t = 0u; t < trials && count < cap; ++t) {
        if (edge != 0xffffffffull && m1rsi_lace_edge_distinct_prefix(prefix_edges, prefix_count, edge)) {
            uint32_t duplicate = 0u;
            for (uint32_t i = 0u; i < count; ++i) {
                if (out[i].edge == edge) {
                    duplicate = 1u;
                    break;
                }
            }
            if (!duplicate) {
                const uint32_t endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edge, side);
                if (((endpoint ^ want_endpoint) & mask) == 0u) {
                    out[count].edge = edge;
                    out[count].other_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edge, side ^ 1u);
                    count += 1u;
                }
            }
        }
        edge = (edge + stride) & edge_mask;
    }
    m1rsi_lace_local_demand_bucket_cache_store(
        job,
        side,
        want_endpoint,
        bits,
        mask,
        edge_mask,
        out,
        count,
        0u);
    return count;
}

static uint32_t m1rsi_lace_local_demand_pick(
    const M1RsiJob *job,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t bits,
    uint64_t salt,
    const uint64_t *prefix_edges,
    uint32_t prefix_count,
    uint64_t edge_mask,
    uint64_t *out_edge,
    uint32_t *out_other_endpoint,
    uint32_t *out_seen) {
    if (out_seen) *out_seen = 0u;
    if (!out_edge || !out_other_endpoint) return 0u;
    M1RsiLaceLocalDemandCandidate one[1];
    memset(one, 0, sizeof(one));
    const uint32_t found = m1rsi_lace_local_demand_fill(
        job,
        side,
        want_endpoint,
        bits,
        salt,
        prefix_edges,
        prefix_count,
        edge_mask,
        one,
        1u,
        m1rsi_lace_local_demand_trials(bits));
    if (out_seen) *out_seen = found;
    if (found == 0u) return 0u;
    *out_edge = one[0].edge;
    *out_other_endpoint = one[0].other_endpoint;
    return 1u;
}

static uint32_t m1rsi_lace_local_demand_pick_bridge2(
    const M1RsiJob *job,
    uint32_t want_endpoint_a,
    uint32_t want_endpoint_b,
    uint32_t bits,
    uint64_t salt,
    const uint64_t *prefix_edges,
    uint32_t prefix_count,
    uint64_t edge_mask,
    uint64_t *out_edge_a,
    uint64_t *out_edge_b,
    uint32_t *out_left_count,
    uint32_t *out_right_count) {
    if (out_left_count) *out_left_count = 0u;
    if (out_right_count) *out_right_count = 0u;
    if (!job || !out_edge_a || !out_edge_b || bits == 0u || bits > job->edge_bits) return 0u;
    const uint32_t cap = m1rsi_lace_local_demand_way_cap();
    const uint32_t local_demand_bridge_stack_default =
        cap <= M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS ? 1u : 0u;
    const uint32_t trials = m1rsi_lace_local_demand_bridge_trials(bits);
    const uint64_t edge_period = edge_mask + 1ull;
    if (m1rsi_lace_local_demand_bridge_close_metal_enabled() &&
        m1rsi_lace_local_demand_metal_enabled() &&
        local_demand_bridge_stack_default &&
        edge_period != 0ull &&
        (uint64_t)trials <= edge_period) {
        const uint32_t mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
        const M1RsiLaceLocalDemandSchedule left_sched =
            m1rsi_lace_local_demand_schedule(job, 0u, want_endpoint_a, mask, salt ^ 0x6272326c656674ull, edge_mask);
        const M1RsiLaceLocalDemandSchedule right_sched =
            m1rsi_lace_local_demand_schedule(job, 0u, want_endpoint_b, mask, salt ^ 0x6272327269676874ull, edge_mask);
        uint32_t left_count_metal = 0u;
        uint32_t right_count_metal = 0u;
        uint32_t left_overflow_metal = 0u;
        uint32_t right_overflow_metal = 0u;
        const uint32_t metal_st = m1rsi_metal_lace_local_demand_bridge_close(
            job,
            0u,
            want_endpoint_a,
            0u,
            want_endpoint_b,
            bits,
            left_sched.edge_start,
            left_sched.stride,
            right_sched.edge_start,
            right_sched.stride,
            edge_mask,
            prefix_edges,
            prefix_count,
            cap,
            trials,
            out_edge_a,
            out_edge_b,
            &left_count_metal,
            &left_overflow_metal,
            &right_count_metal,
            &right_overflow_metal);
        if (metal_st == M1RSI_STATUS_OK) {
            if (out_left_count) *out_left_count = left_count_metal;
            if (out_right_count) *out_right_count = right_count_metal;
            fprintf(stderr,
                    "m1rsi: lace_local_demand_metal_bridge_close=1 bits=%u left_count=%u right_count=%u left_overflow=%u right_overflow=%u cap=%u trials=%u bridge_close_command_buffer=1 local_demand_bridge_stack_default=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                    bits,
                    left_count_metal,
                    right_count_metal,
                    left_overflow_metal,
                    right_overflow_metal,
                    cap,
                    trials,
                    local_demand_bridge_stack_default);
            return 1u;
        }
        if (metal_st == M1RSI_STATUS_NO_CYCLE) {
            if (out_left_count) *out_left_count = left_count_metal;
            if (out_right_count) *out_right_count = right_count_metal;
            fprintf(stderr,
                    "m1rsi: lace_local_demand_metal_bridge_close_no_cycle=1 bits=%u left_count=%u right_count=%u left_overflow=%u right_overflow=%u cap=%u trials=%u bridge_close_command_buffer=1 host_pair_fallback=0 graph_materialized=0 fixed_endpoint_preimage=0\n",
                    bits,
                    left_count_metal,
                    right_count_metal,
                    left_overflow_metal,
                    right_overflow_metal,
                    cap,
                    trials);
            return 0u;
        }
        if (m1rsi_lace_local_demand_require_metal()) return 0u;
    }
    M1RsiLaceLocalDemandCandidate left_stack[M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS];
    M1RsiLaceLocalDemandCandidate right_stack[M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS];
    M1RsiLaceLocalDemandCandidate *left = local_demand_bridge_stack_default
        ? left_stack
        : (M1RsiLaceLocalDemandCandidate *)calloc((size_t)cap, sizeof(*left));
    M1RsiLaceLocalDemandCandidate *right = local_demand_bridge_stack_default
        ? right_stack
        : (M1RsiLaceLocalDemandCandidate *)calloc((size_t)cap, sizeof(*right));
    if (!left || !right) {
        if (!local_demand_bridge_stack_default) {
            free(left);
            free(right);
        }
        return 0u;
    }

    uint32_t left_count = 0u;
    uint32_t right_count = 0u;
    uint32_t pair_done = 0u;
    if (m1rsi_lace_local_demand_metal_enabled() && edge_period != 0ull && (uint64_t)trials <= edge_period) {
        uint64_t left_edges_stack[M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS];
        uint64_t right_edges_stack[M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS];
        uint32_t left_other_stack[M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS];
        uint32_t right_other_stack[M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS];
        uint64_t *left_edges = local_demand_bridge_stack_default
            ? left_edges_stack
            : (uint64_t *)calloc((size_t)cap, sizeof(*left_edges));
        uint64_t *right_edges = local_demand_bridge_stack_default
            ? right_edges_stack
            : (uint64_t *)calloc((size_t)cap, sizeof(*right_edges));
        uint32_t *left_other = local_demand_bridge_stack_default
            ? left_other_stack
            : (uint32_t *)calloc((size_t)cap, sizeof(*left_other));
        uint32_t *right_other = local_demand_bridge_stack_default
            ? right_other_stack
            : (uint32_t *)calloc((size_t)cap, sizeof(*right_other));
        if (left_edges && right_edges && left_other && right_other) {
            const uint32_t mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
            const M1RsiLaceLocalDemandSchedule left_sched =
                m1rsi_lace_local_demand_schedule(job, 0u, want_endpoint_a, mask, salt ^ 0x6272326c656674ull, edge_mask);
            const M1RsiLaceLocalDemandSchedule right_sched =
                m1rsi_lace_local_demand_schedule(job, 0u, want_endpoint_b, mask, salt ^ 0x6272327269676874ull, edge_mask);
            uint32_t left_overflow = 0u;
            uint32_t right_overflow = 0u;
            const uint32_t metal_st = m1rsi_metal_lace_local_demand_fill_pair(
                job,
                0u,
                want_endpoint_a,
                0u,
                want_endpoint_b,
                bits,
                left_sched.edge_start,
                left_sched.stride,
                right_sched.edge_start,
                right_sched.stride,
                edge_mask,
                prefix_edges,
                prefix_count,
                left_edges,
                left_other,
                cap,
                right_edges,
                right_other,
                cap,
                trials,
                &left_count,
                &left_overflow,
                &right_count,
                &right_overflow);
            if (metal_st == M1RSI_STATUS_OK) {
                if (left_count > cap) left_count = cap;
                if (right_count > cap) right_count = cap;
                for (uint32_t i = 0u; i < left_count; ++i) {
                    left[i].edge = left_edges[i];
                    left[i].other_endpoint = left_other[i];
                }
                for (uint32_t i = 0u; i < right_count; ++i) {
                    right[i].edge = right_edges[i];
                    right[i].other_endpoint = right_other[i];
                }
                pair_done = 1u;
                fprintf(stderr,
                        "m1rsi: lace_local_demand_metal_pair_fill=1 bits=%u left_count=%u right_count=%u left_overflow=%u right_overflow=%u cap=%u trials=%u batch_command_buffer=1 local_demand_bridge_stack_default=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                        bits,
                        left_count,
                        right_count,
                        left_overflow,
                        right_overflow,
                        cap,
                        trials,
                        local_demand_bridge_stack_default);
            }
        }
        if (!local_demand_bridge_stack_default) {
            free(left_edges);
            free(right_edges);
            free(left_other);
            free(right_other);
        }
        if (!pair_done && m1rsi_lace_local_demand_require_metal()) {
            if (!local_demand_bridge_stack_default) {
                free(left);
                free(right);
            }
            return 0u;
        }
    }
    if (!pair_done) {
        left_count = m1rsi_lace_local_demand_fill(
            job,
            0u,
            want_endpoint_a,
            bits,
            salt ^ 0x6272326c656674ull,
            prefix_edges,
            prefix_count,
            edge_mask,
            left,
            cap,
            trials);
        right_count = m1rsi_lace_local_demand_fill(
            job,
            0u,
            want_endpoint_b,
            bits,
            salt ^ 0x6272327269676874ull,
            prefix_edges,
            prefix_count,
            edge_mask,
            right,
            cap,
            trials);
    }
    if (out_left_count) *out_left_count = left_count;
    if (out_right_count) *out_right_count = right_count;

    const uint32_t mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
    uint32_t ok = 0u;
    for (uint32_t i = 0u; i < left_count && !ok; ++i) {
        for (uint32_t j = 0u; j < right_count; ++j) {
            if (left[i].edge == right[j].edge) continue;
            if (!m1rsi_lace_edge_distinct_prefix(prefix_edges, prefix_count, right[j].edge)) continue;
            if (((left[i].other_endpoint ^ right[j].other_endpoint) & mask) != 1u) continue;
            *out_edge_a = left[i].edge;
            *out_edge_b = right[j].edge;
            ok = 1u;
            break;
        }
    }
    if (!local_demand_bridge_stack_default) {
        free(left);
        free(right);
    }
    return ok;
}

static int m1rsi_lace_path_mitm_state_cmp(const void *a, const void *b) {
    const M1RsiLacePathMitmState *sa = (const M1RsiLacePathMitmState *)a;
    const M1RsiLacePathMitmState *sb = (const M1RsiLacePathMitmState *)b;
    if (sa->key < sb->key) return -1;
    if (sa->key > sb->key) return 1;
    return 0;
}

static uint32_t m1rsi_lace_path_mitm_lower_bound(const M1RsiLacePathMitmState *states, uint32_t count, uint32_t key) {
    uint32_t lo = 0u;
    uint32_t hi = count;
    while (lo < hi) {
        const uint32_t mid = lo + ((hi - lo) >> 1u);
        if (states[mid].key < key) lo = mid + 1u;
        else hi = mid;
    }
    return lo;
}

static uint32_t m1rsi_lace_sparse_lift_pick_side_exact(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t return_bits,
    uint64_t salt,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edge,
    uint32_t *out_other_endpoint);

static uint32_t m1rsi_lace_sparse_lift_collect_side_exact(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t return_bits,
    uint64_t salt,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edges,
    uint32_t *out_other_endpoints,
    uint32_t cap);

static uint64_t m1rsi_lace_path_mitm_endpoint_cache_slot_bytes(uint32_t fanout) {
    return fanout == 0u ? 0ull : (uint64_t)fanout * (uint64_t)sizeof(M1RsiLacePathMitmState);
}

static uint64_t m1rsi_lace_sparse_path_mitm_endpoint_cache_default_bytes(uint32_t fanout) {
    const uint64_t slot_bytes = m1rsi_lace_path_mitm_endpoint_cache_slot_bytes(fanout);
    if (slot_bytes == 0ull) return 0ull;
    uint32_t default_capacity = 64u;
    if (fanout > 4096u) default_capacity = 16u;
    if (fanout > 65536u) default_capacity = 4u;
    if (fanout > 262144u) default_capacity = 2u;
    return slot_bytes * 2ull * (uint64_t)default_capacity;
}

static uint64_t m1rsi_lace_sparse_path_mitm_endpoint_cache_budget_bytes(uint32_t fanout) {
    const uint64_t fallback = m1rsi_lace_sparse_path_mitm_endpoint_cache_default_bytes(fanout);
    return m1rsi_lace_env_u64("M1RSI_LACE_SPARSE_PATH_MITM_ENDPOINT_CACHE_BYTES", fallback, 0ull, ~0ull);
}

static uint32_t m1rsi_lace_sparse_path_mitm_endpoint_cache_capacity(uint32_t fanout) {
    const uint64_t slot_bytes = m1rsi_lace_path_mitm_endpoint_cache_slot_bytes(fanout);
    const uint64_t slot_pair_bytes = slot_bytes * 2ull;
    const uint64_t budget_bytes = m1rsi_lace_sparse_path_mitm_endpoint_cache_budget_bytes(fanout);
    uint64_t fallback = (slot_pair_bytes == 0ull) ? 0ull : (budget_bytes / slot_pair_bytes);
    if (fallback > (1ull << 16u)) fallback = 1ull << 16u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.endpoint_cache_cap != 0u) {
        uint32_t cap = g_lace_sparse_config_override.endpoint_cache_cap;
        if (cap > (1u << 16u)) cap = 1u << 16u;
        return cap;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_PATH_MITM_ENDPOINT_CACHE_CAP", (uint32_t)fallback, 0u, 1u << 16u);
}

static uint32_t m1rsi_lace_sparse_path_mitm_thread_count(uint32_t fanout) {
    uint32_t fallback = fanout >= 8192u ? m1rsi_lace_host_cpu_count() : 1u;
    if (fallback > 32u) fallback = 32u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.path_mitm_threads != 0u) {
        uint32_t threads = g_lace_sparse_config_override.path_mitm_threads;
        if (threads > 64u) threads = 64u;
        return threads == 0u ? 1u : threads;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_PATH_MITM_THREADS", fallback, 1u, 64u);
}

static uint32_t m1rsi_lace_path_mitm_endpoint_cache_matches(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t return_bits,
    uint32_t fanout,
    uint32_t left_steps,
    uint32_t capacity,
    uint64_t budget_bytes,
    uint64_t slot_bytes) {
    return job && idx &&
        g_lace_path_mitm_endpoint_cache.valid &&
        g_lace_path_mitm_endpoint_cache.bits == idx->bits &&
        g_lace_path_mitm_endpoint_cache.return_bits == return_bits &&
        g_lace_path_mitm_endpoint_cache.edge_bits == job->edge_bits &&
        g_lace_path_mitm_endpoint_cache.way_count == idx->way_count &&
        g_lace_path_mitm_endpoint_cache.bridge_edges == idx->bridge_edges &&
        g_lace_path_mitm_endpoint_cache.sparse_scan_count == idx->scan_count &&
        g_lace_path_mitm_endpoint_cache.fanout == fanout &&
        g_lace_path_mitm_endpoint_cache.left_steps == left_steps &&
        g_lace_path_mitm_endpoint_cache.capacity == capacity &&
        g_lace_path_mitm_endpoint_cache.budget_bytes == budget_bytes &&
        g_lace_path_mitm_endpoint_cache.slot_bytes == slot_bytes &&
        m1rsi_lace_keys_equal(g_lace_path_mitm_endpoint_cache.keys, job->keys);
}

static uint32_t m1rsi_lace_path_mitm_endpoint_cache_prepare(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t return_bits,
    uint32_t fanout,
    uint32_t left_steps,
    uint32_t capacity,
    uint64_t budget_bytes,
    uint64_t slot_bytes) {
    if (!job || !idx || capacity == 0u || fanout == 0u) return 0u;
    if (m1rsi_lace_path_mitm_endpoint_cache_matches(job, idx, return_bits, fanout, left_steps, capacity, budget_bytes, slot_bytes)) return 1u;
    m1rsi_lace_path_mitm_endpoint_cache_free(&g_lace_path_mitm_endpoint_cache);
    g_lace_path_mitm_endpoint_cache.entries[0] = (M1RsiLacePathMitmEndpointCacheEntry *)calloc((size_t)capacity, sizeof(*g_lace_path_mitm_endpoint_cache.entries[0]));
    g_lace_path_mitm_endpoint_cache.entries[1] = (M1RsiLacePathMitmEndpointCacheEntry *)calloc((size_t)capacity, sizeof(*g_lace_path_mitm_endpoint_cache.entries[1]));
    if (!g_lace_path_mitm_endpoint_cache.entries[0] || !g_lace_path_mitm_endpoint_cache.entries[1]) {
        m1rsi_lace_path_mitm_endpoint_cache_free(&g_lace_path_mitm_endpoint_cache);
        return 0u;
    }
    g_lace_path_mitm_endpoint_cache.valid = 1u;
    g_lace_path_mitm_endpoint_cache.bits = idx->bits;
    g_lace_path_mitm_endpoint_cache.return_bits = return_bits;
    g_lace_path_mitm_endpoint_cache.edge_bits = job->edge_bits;
    g_lace_path_mitm_endpoint_cache.way_count = idx->way_count;
    g_lace_path_mitm_endpoint_cache.bridge_edges = idx->bridge_edges;
    g_lace_path_mitm_endpoint_cache.sparse_scan_count = idx->scan_count;
    g_lace_path_mitm_endpoint_cache.fanout = fanout;
    g_lace_path_mitm_endpoint_cache.left_steps = left_steps;
    g_lace_path_mitm_endpoint_cache.capacity = capacity;
    g_lace_path_mitm_endpoint_cache.budget_bytes = budget_bytes;
    g_lace_path_mitm_endpoint_cache.slot_bytes = slot_bytes;
    g_lace_path_mitm_endpoint_cache.keys = job->keys;
    fprintf(stderr,
            "m1rsi: lace_bridge_path_mitm_endpoint_cache_reset bits=%u return_bits=%u fanout=%u left_steps=%u capacity=%u budget_bytes=%llu slot_bytes=%llu %s graph_materialized=0 fixed_endpoint_preimage=0\n",
            idx->bits,
            return_bits,
            fanout,
            left_steps,
            capacity,
            (unsigned long long)budget_bytes,
            (unsigned long long)slot_bytes,
            (fanout > 4096u && capacity != 0u) ? "non_toy_capacity=1" : "non_toy_capacity=0");
    return 1u;
}

static uint32_t m1rsi_lace_path_mitm_fill_endpoint_variant(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t direction,
    uint32_t endpoint_key,
    uint32_t return_bits,
    uint32_t left_steps,
    uint64_t edge_mask,
    uint32_t return_mask,
    uint64_t seed,
    uint32_t variant,
    M1RsiLacePathMitmState *out_state) {
    if (!job || !idx || !out_state || direction > 1u) return 0u;
    M1RsiLacePathMitmState state;
    memset(&state, 0, sizeof(state));
    if (direction == 0u) {
        uint32_t current_endpoint = 0u;
        const uint64_t salt0 = seed ^ ((uint64_t)variant * 0xa0761d6478bd642full);
        if (!m1rsi_lace_sparse_lift_pick_side_exact(
                job,
                idx,
                0u,
                endpoint_key,
                return_bits,
                salt0 ^ 0x6d69746d5f6530ull,
                state.edges,
                0u,
                edge_mask,
                &state.edges[0],
                &current_endpoint)) {
            return 0u;
        }
        uint32_t edge_count = 1u;
        for (uint32_t j = 0u; j < left_steps; ++j) {
            const uint32_t side = m1rsi_lace_delta_side(j);
            const uint32_t want = current_endpoint ^ 1u;
            uint64_t candidate = 0u;
            uint32_t other_endpoint = 0u;
            if (!m1rsi_lace_sparse_lift_pick_side_exact(
                    job,
                    idx,
                    side,
                    want,
                    return_bits,
                    salt0 ^ ((uint64_t)j * 0xe7037ed1a0b428dbull),
                    state.edges,
                    edge_count,
                    edge_mask,
                    &candidate,
                    &other_endpoint)) {
                return 0u;
            }
            state.edges[edge_count++] = candidate;
            current_endpoint = other_endpoint;
        }
        state.key = current_endpoint & return_mask;
        *out_state = state;
        return 1u;
    }

    uint64_t used[M1RSI_PROOFSIZE];
    uint32_t used_count = 0u;
    memset(used, 0, sizeof(used));
    uint32_t desired_current = endpoint_key;
    const uint64_t salt0 = seed ^ 0x5245564d49544d31ull ^ ((uint64_t)variant * 0x8ebc6af09c88c6e3ull);
    for (int32_t j = (int32_t)(M1RSI_PROOFSIZE - 4u); j >= (int32_t)left_steps; --j) {
        const uint32_t forward_side = m1rsi_lace_delta_side((uint32_t)j);
        const uint32_t reverse_side = forward_side ^ 1u;
        uint64_t candidate = 0u;
        uint32_t forward_endpoint = 0u;
        if (!m1rsi_lace_sparse_lift_pick_side_exact(
                job,
                idx,
                reverse_side,
                desired_current,
                return_bits,
                salt0 ^ ((uint64_t)(uint32_t)j * 0x589965cc75374cc3ull),
                used,
                used_count,
                edge_mask,
                &candidate,
                &forward_endpoint)) {
            return 0u;
        }
        state.edges[(uint32_t)j + 1u] = candidate;
        used[used_count++] = candidate;
        desired_current = forward_endpoint ^ 1u;
    }
    state.key = desired_current & return_mask;
    *out_state = state;
    return 1u;
}

typedef struct M1RsiLacePathMitmFillWorker {
    const M1RsiJob *job;
    const M1RsiLaceSparseLiftIndex *idx;
    uint32_t direction;
    uint32_t endpoint_key;
    uint32_t return_bits;
    uint32_t left_steps;
    uint64_t edge_mask;
    uint32_t return_mask;
    uint64_t seed;
    uint32_t begin;
    uint32_t end;
    uint32_t count;
    M1RsiLacePathMitmState *states;
} M1RsiLacePathMitmFillWorker;

typedef struct M1RsiLacePathMitmBeamState {
    M1RsiLacePathMitmState state;
    uint64_t used_edges[M1RSI_PROOFSIZE];
    uint32_t used_count;
    uint32_t endpoint;
} M1RsiLacePathMitmBeamState;

static void *m1rsi_lace_path_mitm_fill_worker_main(void *raw) {
    M1RsiLacePathMitmFillWorker *w = (M1RsiLacePathMitmFillWorker *)raw;
    if (!w || !w->states) return NULL;
    uint32_t count = 0u;
    for (uint32_t variant = w->begin; variant < w->end; ++variant) {
        M1RsiLacePathMitmState state;
        if (!m1rsi_lace_path_mitm_fill_endpoint_variant(
                w->job,
                w->idx,
                w->direction,
                w->endpoint_key,
                w->return_bits,
                w->left_steps,
                w->edge_mask,
                w->return_mask,
                w->seed,
                variant,
                &state)) {
            continue;
        }
        w->states[w->begin + count] = state;
        count += 1u;
    }
    w->count = count;
    return NULL;
}

static uint32_t m1rsi_lace_path_mitm_fill_endpoint_serial(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t direction,
    uint32_t endpoint_key,
    uint32_t return_bits,
    uint32_t left_steps,
    uint64_t edge_mask,
    uint32_t return_mask,
    uint64_t seed,
    uint32_t fanout,
    M1RsiLacePathMitmState *states) {
    uint32_t count = 0u;
    for (uint32_t variant = 0u; variant < fanout; ++variant) {
        M1RsiLacePathMitmState state;
        if (!m1rsi_lace_path_mitm_fill_endpoint_variant(
                job, idx, direction, endpoint_key, return_bits, left_steps, edge_mask, return_mask, seed, variant, &state)) {
            continue;
        }
        states[count++] = state;
    }
    return count;
}

static uint32_t m1rsi_lace_path_mitm_fill_endpoint_beam(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t direction,
    uint32_t endpoint_key,
    uint32_t return_bits,
    uint32_t left_steps,
    uint64_t edge_mask,
    uint32_t return_mask,
    uint64_t seed,
    uint32_t fanout,
    M1RsiLacePathMitmState *states) {
    if (!job || !idx || !states || direction > 1u || fanout == 0u || idx->way_count == 0u) return 0u;
    M1RsiLacePathMitmBeamState *frontier =
        (M1RsiLacePathMitmBeamState *)calloc((size_t)fanout, sizeof(*frontier));
    M1RsiLacePathMitmBeamState *next =
        (M1RsiLacePathMitmBeamState *)calloc((size_t)fanout, sizeof(*next));
    if (!frontier || !next) {
        free(frontier);
        free(next);
        return 0u;
    }

    uint32_t frontier_count = 0u;
    endpoint_key &= return_mask;
    if (direction == 0u) {
        uint64_t edge_buf[16];
        uint32_t other_buf[16];
        const uint32_t got = m1rsi_lace_sparse_lift_collect_side_exact(
            job,
            idx,
            0u,
            endpoint_key,
            return_bits,
            seed ^ 0x6d69746d5f6230ull,
            NULL,
            0u,
            edge_mask,
            edge_buf,
            other_buf,
            idx->way_count < 16u ? idx->way_count : 16u);
        for (uint32_t i = 0u; i < got && frontier_count < fanout; ++i) {
            M1RsiLacePathMitmBeamState *bs = &frontier[frontier_count++];
            memset(bs, 0, sizeof(*bs));
            bs->state.edges[0] = edge_buf[i];
            bs->used_edges[0] = edge_buf[i];
            bs->used_count = 1u;
            bs->endpoint = other_buf[i];
        }
        for (uint32_t j = 0u; j < left_steps && frontier_count != 0u; ++j) {
            uint32_t next_count = 0u;
            const uint32_t side = m1rsi_lace_delta_side(j);
            for (uint32_t fi = 0u; fi < frontier_count && next_count < fanout; ++fi) {
                const M1RsiLacePathMitmBeamState *cur = &frontier[fi];
                const uint32_t want = cur->endpoint ^ 1u;
                uint64_t edge_buf[16];
                uint32_t other_buf[16];
                const uint64_t salt = seed ^
                    ((uint64_t)j * 0xe7037ed1a0b428dbull) ^
                    ((uint64_t)fi * 0x94d049bb133111ebull);
                const uint32_t got = m1rsi_lace_sparse_lift_collect_side_exact(
                    job,
                    idx,
                    side,
                    want,
                    return_bits,
                    salt,
                    cur->used_edges,
                    cur->used_count,
                    edge_mask,
                    edge_buf,
                    other_buf,
                    idx->way_count < 16u ? idx->way_count : 16u);
                for (uint32_t k = 0u; k < got && next_count < fanout; ++k) {
                    M1RsiLacePathMitmBeamState *dst = &next[next_count++];
                    *dst = *cur;
                    dst->state.edges[j + 1u] = edge_buf[k];
                    dst->used_edges[dst->used_count++] = edge_buf[k];
                    dst->endpoint = other_buf[k];
                }
            }
            M1RsiLacePathMitmBeamState *tmp = frontier;
            frontier = next;
            next = tmp;
            frontier_count = next_count;
        }
        for (uint32_t i = 0u; i < frontier_count; ++i) {
            frontier[i].state.key = frontier[i].endpoint & return_mask;
            states[i] = frontier[i].state;
        }
    } else {
        memset(&frontier[0], 0, sizeof(frontier[0]));
        frontier[0].endpoint = endpoint_key;
        frontier_count = 1u;
        for (int32_t j = (int32_t)(M1RSI_PROOFSIZE - 4u);
             j >= (int32_t)left_steps && frontier_count != 0u;
             --j) {
            uint32_t next_count = 0u;
            const uint32_t forward_side = m1rsi_lace_delta_side((uint32_t)j);
            const uint32_t reverse_side = forward_side ^ 1u;
            for (uint32_t fi = 0u; fi < frontier_count && next_count < fanout; ++fi) {
                const M1RsiLacePathMitmBeamState *cur = &frontier[fi];
                uint64_t edge_buf[16];
                uint32_t other_buf[16];
                const uint64_t salt = seed ^
                    ((uint64_t)(uint32_t)j * 0x589965cc75374cc3ull) ^
                    ((uint64_t)fi * 0xd6e8feb86659fd93ull);
                const uint32_t got = m1rsi_lace_sparse_lift_collect_side_exact(
                    job,
                    idx,
                    reverse_side,
                    cur->endpoint,
                    return_bits,
                    salt,
                    cur->used_edges,
                    cur->used_count,
                    edge_mask,
                    edge_buf,
                    other_buf,
                    idx->way_count < 16u ? idx->way_count : 16u);
                for (uint32_t k = 0u; k < got && next_count < fanout; ++k) {
                    M1RsiLacePathMitmBeamState *dst = &next[next_count++];
                    *dst = *cur;
                    dst->state.edges[(uint32_t)j + 1u] = edge_buf[k];
                    dst->used_edges[dst->used_count++] = edge_buf[k];
                    dst->endpoint = other_buf[k] ^ 1u;
                }
            }
            M1RsiLacePathMitmBeamState *tmp = frontier;
            frontier = next;
            next = tmp;
            frontier_count = next_count;
        }
        for (uint32_t i = 0u; i < frontier_count; ++i) {
            frontier[i].state.key = frontier[i].endpoint & return_mask;
            states[i] = frontier[i].state;
        }
    }

    if (frontier_count != 0u) {
        fprintf(stderr,
                "m1rsi: lace_bridge_path_mitm_endpoint_beam_fill direction=%u endpoint=%u fanout=%u left_steps=%u count=%u return_bits=%u idx_bits=%u exact_branching=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                direction,
                endpoint_key,
                fanout,
                left_steps,
                frontier_count,
                return_bits,
                idx->bits);
    }
    free(frontier);
    free(next);
    return frontier_count;
}

static void m1rsi_lace_path_mitm_fill_endpoint_states(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t direction,
    uint32_t endpoint_key,
    uint64_t support_ordinal,
    uint32_t return_bits,
    uint32_t fanout,
    uint32_t left_steps,
    uint64_t edge_mask,
    M1RsiLacePathMitmState *states,
    uint32_t *out_count) {
    if (out_count) *out_count = 0u;
    if (!job || !idx || !states || !out_count || direction > 1u || fanout == 0u) return;
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    endpoint_key &= return_mask;
    const uint64_t seed = m1rsi_lace_mix64(
        0x504154484d455043ull ^
        m1rsi_lace_key_mix(job) ^
        (support_ordinal * 0x9e3779b97f4a7c15ull) ^
        ((uint64_t)endpoint_key * 0xd6e8feb86659fd93ull) ^
        ((uint64_t)return_bits * 0x94d049bb133111ebull) ^
        ((uint64_t)direction * 0x8ebc6af09c88c6e3ull));

    if (return_bits > idx->bits) {
        *out_count = m1rsi_lace_path_mitm_fill_endpoint_beam(
            job, idx, direction, endpoint_key, return_bits, left_steps, edge_mask, return_mask, seed, fanout, states);
        return;
    }

    uint32_t threads = m1rsi_lace_sparse_path_mitm_thread_count(fanout);
    if (threads > fanout) threads = fanout;
    if (threads > 64u) threads = 64u;
    if (threads <= 1u || fanout < 4096u) {
        *out_count = m1rsi_lace_path_mitm_fill_endpoint_serial(
            job, idx, direction, endpoint_key, return_bits, left_steps, edge_mask, return_mask, seed, fanout, states);
        return;
    }

    pthread_t tids[64];
    M1RsiLacePathMitmFillWorker workers[64];
    memset(tids, 0, sizeof(tids));
    memset(workers, 0, sizeof(workers));
    uint32_t launched = 0u;
    uint32_t create_failed = 0u;
    for (uint32_t t = 0u; t < threads; ++t) {
        const uint32_t begin = (uint32_t)(((uint64_t)fanout * (uint64_t)t) / (uint64_t)threads);
        const uint32_t end = (uint32_t)(((uint64_t)fanout * (uint64_t)(t + 1u)) / (uint64_t)threads);
        workers[t].job = job;
        workers[t].idx = idx;
        workers[t].direction = direction;
        workers[t].endpoint_key = endpoint_key;
        workers[t].return_bits = return_bits;
        workers[t].left_steps = left_steps;
        workers[t].edge_mask = edge_mask;
        workers[t].return_mask = return_mask;
        workers[t].seed = seed;
        workers[t].begin = begin;
        workers[t].end = end;
        workers[t].states = states;
        if (pthread_create(&tids[t], NULL, m1rsi_lace_path_mitm_fill_worker_main, &workers[t]) != 0) {
            create_failed = 1u;
            break;
        }
        launched += 1u;
    }
    for (uint32_t t = 0u; t < launched; ++t) pthread_join(tids[t], NULL);
    if (create_failed || launched != threads) {
        *out_count = m1rsi_lace_path_mitm_fill_endpoint_serial(
            job, idx, direction, endpoint_key, return_bits, left_steps, edge_mask, return_mask, seed, fanout, states);
        return;
    }

    uint32_t count = 0u;
    for (uint32_t t = 0u; t < threads; ++t) {
        if (workers[t].count != 0u) {
            if (count != workers[t].begin) {
                memmove(&states[count], &states[workers[t].begin], (size_t)workers[t].count * sizeof(states[0]));
            }
            count += workers[t].count;
        }
    }
    *out_count = count;
    fprintf(stderr,
            "m1rsi: lace_bridge_path_mitm_endpoint_fill direction=%u endpoint=%u support_ordinal=%llu fanout=%u path_mitm_threads=%u count=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
            direction,
            endpoint_key,
            (unsigned long long)support_ordinal,
            fanout,
            threads,
            count);
}

static uint32_t m1rsi_lace_path_mitm_endpoint_cache_get(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t direction,
    uint32_t endpoint_key,
    uint64_t request_ordinal,
    uint32_t return_bits,
    uint32_t fanout,
    uint32_t left_steps,
    uint64_t edge_mask,
    M1RsiLacePathMitmState **out_states,
    uint32_t *out_count,
    uint32_t *out_hit) {
    if (out_states) *out_states = NULL;
    if (out_count) *out_count = 0u;
    if (out_hit) *out_hit = 0u;
    if (!job || !idx || !out_states || !out_count || direction > 1u || fanout == 0u) return 0u;
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    endpoint_key &= return_mask;
    const uint64_t support_ordinal = 0u;
    const uint64_t slot_bytes = m1rsi_lace_path_mitm_endpoint_cache_slot_bytes(fanout);
    const uint64_t budget_bytes = m1rsi_lace_sparse_path_mitm_endpoint_cache_budget_bytes(fanout);
    const uint32_t capacity = m1rsi_lace_sparse_path_mitm_endpoint_cache_capacity(fanout);
    if (!m1rsi_lace_path_mitm_endpoint_cache_prepare(job, idx, return_bits, fanout, left_steps, capacity, budget_bytes, slot_bytes)) return 0u;

    M1RsiLacePathMitmEndpointCacheEntry *entries = g_lace_path_mitm_endpoint_cache.entries[direction];
    for (uint32_t i = 0u; i < g_lace_path_mitm_endpoint_cache.capacity; ++i) {
        M1RsiLacePathMitmEndpointCacheEntry *entry = &entries[i];
        if (!entry->valid || entry->endpoint_key != endpoint_key || entry->support_ordinal != support_ordinal) continue;
        *out_states = entry->states;
        *out_count = entry->count;
        if (out_hit) *out_hit = 1u;
        if (entry->count != 0u) {
            fprintf(stderr,
                    "m1rsi: lace_bridge_path_mitm_endpoint_cache_hit direction=%u endpoint=%u request_ordinal=%llu support_ordinal=%llu ordinal_independent=1 count=%u capacity=%u fanout=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                    direction,
                    endpoint_key,
                    (unsigned long long)request_ordinal,
                    (unsigned long long)support_ordinal,
                    entry->count,
                    g_lace_path_mitm_endpoint_cache.capacity,
                    fanout);
        }
        return 1u;
    }

    const uint32_t cache_capacity = g_lace_path_mitm_endpoint_cache.capacity;
    if (cache_capacity == 0u) return 0u; /* prepare() guarantees nonzero; keep the invariant local */
    const uint32_t slot = g_lace_path_mitm_endpoint_cache.next_slot[direction]++ % cache_capacity;
    M1RsiLacePathMitmEndpointCacheEntry *entry = &entries[slot];
    if (!entry->states) {
        entry->states = (M1RsiLacePathMitmState *)calloc((size_t)fanout, sizeof(*entry->states));
        if (!entry->states) return 0u;
    }
    entry->valid = 0u;
    entry->endpoint_key = endpoint_key;
    entry->support_ordinal = support_ordinal;
    entry->count = 0u;
    m1rsi_lace_path_mitm_fill_endpoint_states(
        job,
        idx,
        direction,
        endpoint_key,
        support_ordinal,
        return_bits,
        fanout,
        left_steps,
        edge_mask,
        entry->states,
        &entry->count);
    if (direction == 0u && entry->count > 1u) {
        qsort(entry->states, entry->count, sizeof(entry->states[0]), m1rsi_lace_path_mitm_state_cmp);
    }
    entry->valid = 1u;
    *out_states = entry->states;
    *out_count = entry->count;
    if (entry->count != 0u) {
        fprintf(stderr,
                "m1rsi: lace_bridge_path_mitm_endpoint_cache_store direction=%u endpoint=%u request_ordinal=%llu support_ordinal=%llu ordinal_independent=1 sorted_forward=%u count=%u capacity=%u fanout=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                direction,
                endpoint_key,
                (unsigned long long)request_ordinal,
                (unsigned long long)support_ordinal,
                direction == 0u ? 1u : 0u,
                entry->count,
                g_lace_path_mitm_endpoint_cache.capacity,
                fanout);
    }
    return 1u;
}

static uint32_t m1rsi_lace_sparse_lift_pick_side_exact(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t return_bits,
    uint64_t salt,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edge,
    uint32_t *out_other_endpoint) {
    if (!job || !idx || side > 1u || !idx->side_edges[side] || !idx->side_other[side] ||
        !out_edge || !out_other_endpoint || idx->way_count == 0u) {
        return 0u;
    }
    if (return_bits < idx->bits) return_bits = idx->bits;
    if (return_bits > job->edge_bits) return_bits = job->edge_bits;
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    const uint64_t base = (uint64_t)(want_endpoint & idx->mask) * (uint64_t)idx->way_count;
    const uint32_t start = (uint32_t)(m1rsi_lace_mix64(salt ^ 0x6578616374736964ull) % (uint64_t)idx->way_count);
    for (uint32_t attempt = 0u; attempt < idx->way_count; ++attempt) {
        const uint32_t w = (start + attempt) % idx->way_count;
        const uint32_t candidate32 = idx->side_edges[side][base + (uint64_t)w];
        if (candidate32 == 0xffffffffu) continue;
        const uint64_t candidate = (uint64_t)candidate32 & edge_mask;
        if (!m1rsi_lace_edge_distinct_prefix(edges, edge_count, candidate)) continue;
        const uint32_t endpoint = m1rsi_endpoint(job->keys, job->edge_bits, candidate, side);
        if (((endpoint ^ want_endpoint) & return_mask) != 0u) continue;
        *out_edge = candidate;
        *out_other_endpoint = idx->side_other[side][base + (uint64_t)w];
        return 1u;
    }
    return 0u;
}

static uint32_t m1rsi_lace_sparse_lift_collect_side_exact(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t side,
    uint32_t want_endpoint,
    uint32_t return_bits,
    uint64_t salt,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edges,
    uint32_t *out_other_endpoints,
    uint32_t cap) {
    if (!job || !idx || side > 1u || !idx->side_edges[side] || !idx->side_other[side] ||
        !out_edges || !out_other_endpoints || idx->way_count == 0u || cap == 0u) {
        return 0u;
    }
    if (return_bits < idx->bits) return_bits = idx->bits;
    if (return_bits > job->edge_bits) return_bits = job->edge_bits;
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    const uint64_t base = (uint64_t)(want_endpoint & idx->mask) * (uint64_t)idx->way_count;
    const uint32_t start = (uint32_t)(m1rsi_lace_mix64(salt ^ 0x6272616e63686578ull) % (uint64_t)idx->way_count);
    uint32_t count = 0u;
    for (uint32_t attempt = 0u; attempt < idx->way_count && count < cap; ++attempt) {
        const uint32_t w = (start + attempt) % idx->way_count;
        const uint32_t candidate32 = idx->side_edges[side][base + (uint64_t)w];
        if (candidate32 == 0xffffffffu) continue;
        const uint64_t candidate = (uint64_t)candidate32 & edge_mask;
        if (!m1rsi_lace_edge_distinct_prefix(edges, edge_count, candidate)) continue;
        uint32_t duplicate = 0u;
        for (uint32_t i = 0u; i < count; ++i) {
            if (out_edges[i] == candidate) {
                duplicate = 1u;
                break;
            }
        }
        if (duplicate) continue;
        const uint32_t endpoint = m1rsi_endpoint(job->keys, job->edge_bits, candidate, side);
        if (((endpoint ^ want_endpoint) & return_mask) != 0u) continue;
        out_edges[count] = candidate;
        out_other_endpoints[count] = idx->side_other[side][base + (uint64_t)w];
        count += 1u;
    }
    return count;
}

static uint32_t m1rsi_lace_sparse_bridge_catalog_matches(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t return_bits,
    uint32_t probe_count,
    uint32_t capacity) {
    return job && idx &&
        g_lace_bridge_catalog_cache.valid &&
        g_lace_bridge_catalog_cache.bits == idx->bits &&
        g_lace_bridge_catalog_cache.return_bits == return_bits &&
        g_lace_bridge_catalog_cache.edge_bits == job->edge_bits &&
        g_lace_bridge_catalog_cache.way_count == idx->way_count &&
        g_lace_bridge_catalog_cache.bridge_edges == idx->bridge_edges &&
        g_lace_bridge_catalog_cache.sparse_scan_count == idx->scan_count &&
        g_lace_bridge_catalog_cache.probe_count == probe_count &&
        g_lace_bridge_catalog_cache.capacity == capacity &&
        m1rsi_lace_keys_equal(g_lace_bridge_catalog_cache.keys, job->keys);
}

static uint32_t m1rsi_lace_sparse_bridge_catalog_get(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    uint32_t return_bits,
    uint32_t probe_count,
    M1RsiLaceBridgeCatalogCache **out_catalog) {
    if (out_catalog) *out_catalog = NULL;
    if (!job || !idx || !out_catalog || idx->bridge_edges < 2u || idx->way_count == 0u ||
        !idx->side_edges[1] || !idx->side_other[1] || probe_count == 0u) {
        return 0u;
    }
    if (return_bits < idx->bits) return_bits = idx->bits;
    if (return_bits > job->edge_bits) return_bits = job->edge_bits;
    const uint32_t capacity = m1rsi_lace_sparse_bridge_catalog_capacity(probe_count);
    if (m1rsi_lace_sparse_bridge_catalog_matches(job, idx, return_bits, probe_count, capacity)) {
        *out_catalog = &g_lace_bridge_catalog_cache;
        fprintf(stderr,
                "m1rsi: lace_bridge_catalog_cache_hit bits=%u return_bits=%u probes=%u capacity=%u entries=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                idx->bits,
                return_bits,
                probe_count,
                capacity,
                g_lace_bridge_catalog_cache.count);
        return 1u;
    }

    m1rsi_lace_bridge_catalog_cache_free(&g_lace_bridge_catalog_cache);
    g_lace_bridge_catalog_cache.entries = (M1RsiLaceBridgeCatalogEntry *)calloc((size_t)capacity, sizeof(*g_lace_bridge_catalog_cache.entries));
    if (!g_lace_bridge_catalog_cache.entries) return 0u;

    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint64_t seed = m1rsi_lace_mix64(
        0x4252494447454341ull ^
        m1rsi_lace_key_mix(job) ^
        ((uint64_t)idx->bits * 0x9e3779b97f4a7c15ull) ^
        ((uint64_t)return_bits * 0xd6e8feb86659fd93ull) ^
        idx->scan_count);

    uint32_t count = 0u;
    for (uint32_t probe = 0u; probe < probe_count && count < capacity; ++probe) {
        const uint32_t v_low = (uint32_t)(m1rsi_lace_mix64(seed + ((uint64_t)probe * 0xbf58476d1ce4e5b9ull)) & (uint64_t)idx->mask);
        const uint32_t v_pair_low = v_low ^ 1u;
        const uint64_t base_a = (uint64_t)v_low * (uint64_t)idx->way_count;
        const uint64_t base_b = (uint64_t)v_pair_low * (uint64_t)idx->way_count;
        const uint32_t start_a = (uint32_t)(m1rsi_lace_mix64(seed ^ ((uint64_t)probe * 0x6132627269646765ull)) % (uint64_t)idx->way_count);
        const uint32_t start_b = (uint32_t)(m1rsi_lace_mix64(seed ^ ((uint64_t)probe * 0x6232627269646765ull)) % (uint64_t)idx->way_count);
        for (uint32_t attempt_a = 0u; attempt_a < idx->way_count && count < capacity; ++attempt_a) {
            const uint32_t wa = (start_a + attempt_a) % idx->way_count;
            const uint32_t close_a32 = idx->side_edges[1][base_a + (uint64_t)wa];
            if (close_a32 == 0xffffffffu) continue;
            const uint64_t close_a = (uint64_t)close_a32 & edge_mask;
            const uint32_t close_a_v = m1rsi_endpoint(job->keys, job->edge_bits, close_a, 1u);
            const uint32_t close_a_u = idx->side_other[1][base_a + (uint64_t)wa];
            for (uint32_t attempt_b = 0u; attempt_b < idx->way_count && count < capacity; ++attempt_b) {
                const uint32_t wb = (start_b + attempt_b) % idx->way_count;
                const uint32_t close_b32 = idx->side_edges[1][base_b + (uint64_t)wb];
                if (close_b32 == 0xffffffffu) continue;
                const uint64_t close_b = (uint64_t)close_b32 & edge_mask;
                if (close_b == close_a) continue;
                const uint32_t close_b_v = m1rsi_endpoint(job->keys, job->edge_bits, close_b, 1u);
                if (((close_a_v ^ close_b_v) & return_mask) != 1u) continue;
                const uint32_t close_b_u = idx->side_other[1][base_b + (uint64_t)wb];
                M1RsiLaceBridgeCatalogEntry *entry = &g_lace_bridge_catalog_cache.entries[count++];
                entry->edge_a = (uint32_t)close_a;
                entry->edge_b = (uint32_t)close_b;
                entry->start_u = close_b_u ^ 1u;
                entry->target_current = close_a_u ^ 1u;
            }
        }
    }

    g_lace_bridge_catalog_cache.valid = 1u;
    g_lace_bridge_catalog_cache.bits = idx->bits;
    g_lace_bridge_catalog_cache.return_bits = return_bits;
    g_lace_bridge_catalog_cache.edge_bits = job->edge_bits;
    g_lace_bridge_catalog_cache.way_count = idx->way_count;
    g_lace_bridge_catalog_cache.bridge_edges = idx->bridge_edges;
    g_lace_bridge_catalog_cache.sparse_scan_count = idx->scan_count;
    g_lace_bridge_catalog_cache.probe_count = probe_count;
    g_lace_bridge_catalog_cache.capacity = capacity;
    g_lace_bridge_catalog_cache.count = count;
    g_lace_bridge_catalog_cache.keys = job->keys;
    *out_catalog = &g_lace_bridge_catalog_cache;
    fprintf(stderr,
            "m1rsi: lace_bridge_catalog bits=%u return_bits=%u probes=%u capacity=%u entries=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
            idx->bits,
            return_bits,
            probe_count,
            capacity,
            count);
    return count != 0u ? 1u : 0u;
}

static uint32_t m1rsi_lace_generate_sparse_lift_template_beam_restart(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t edge_mask,
    uint64_t seed,
    uint32_t restart,
    uint32_t pick_bits,
    uint32_t return_bits,
    uint32_t beam_size,
    M1RsiLaceSparseBeamState *beam,
    M1RsiLaceSparseBeamState *next,
    uint32_t next_cap) {
    if (!job || !idx || !tpl || !beam || !next || beam_size == 0u || next_cap == 0u || idx->way_count == 0u) return 0u;
    if (pick_bits < idx->bits) pick_bits = idx->bits;
    if (pick_bits > job->edge_bits) pick_bits = job->edge_bits;
    if (return_bits < idx->bits) return_bits = idx->bits;
    if (return_bits > job->edge_bits) return_bits = job->edge_bits;
    const uint32_t score_mask = pick_bits >= 32u ? 0xffffffffu : ((1u << pick_bits) - 1u);
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    const uint32_t exact_prune = return_bits > idx->bits ? 1u : 0u;
    const uint32_t bridge_edges = idx->bridge_edges ? idx->bridge_edges : 1u;
    const uint32_t chain_pairs = bridge_edges >= 2u ? (M1RSI_PROOFSIZE - 3u) : (M1RSI_PROOFSIZE - 2u);

    memset(&beam[0], 0, sizeof(beam[0]));
    beam[0].edges[0] = m1rsi_lace_mix64(seed ^ 0x6c69667462617365ull) & edge_mask;
    beam[0].edge_count = 1u;
    beam[0].current_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, beam[0].edges[0], 1u);
    beam[0].start_u_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, beam[0].edges[0], 0u);
    beam[0].score = 0u;
    uint32_t beam_count = 1u;

    for (uint32_t j = 0u; j < chain_pairs; ++j) {
        uint32_t next_count = 0u;
        const uint32_t side = m1rsi_lace_delta_side(j);
        for (uint32_t bi = 0u; bi < beam_count; ++bi) {
            const M1RsiLaceSparseBeamState *state = &beam[bi];
            const uint32_t want = state->current_endpoint ^ 1u;
            const uint64_t base = (uint64_t)(want & idx->mask) * (uint64_t)idx->way_count;
            const uint64_t salt = seed ^ ((uint64_t)j * 0xbf58476d1ce4e5b9ull) ^
                                  ((uint64_t)restart << 32u) ^
                                  ((uint64_t)bi * 0x94d049bb133111ebull);
            const uint32_t start = (uint32_t)(m1rsi_lace_mix64(salt) % (uint64_t)idx->way_count);
            for (uint32_t attempt = 0u; attempt < idx->way_count && next_count < next_cap; ++attempt) {
                const uint32_t w = (start + attempt) % idx->way_count;
                const uint32_t candidate32 = idx->side_edges[side][base + (uint64_t)w];
                if (candidate32 == 0xffffffffu) continue;
                const uint64_t candidate = (uint64_t)candidate32 & edge_mask;
                if (!m1rsi_lace_edge_distinct_prefix(state->edges, state->edge_count, candidate)) continue;
                const uint32_t candidate_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, candidate, side);
                const uint32_t diff = (candidate_endpoint ^ want) & score_mask;
                if (exact_prune && ((candidate_endpoint ^ want) & return_mask) != 0u) {
                    continue;
                }
                M1RsiLaceSparseBeamState *ns = &next[next_count++];
                *ns = *state;
                ns->edges[ns->edge_count++] = candidate;
                ns->current_endpoint = idx->side_other[side][base + (uint64_t)w];
                ns->score += m1rsi_lace_popcount32(diff);
            }
        }
        if (next_count == 0u) return 0u;
        qsort(next, next_count, sizeof(next[0]), m1rsi_lace_sparse_beam_state_cmp);
        beam_count = next_count < beam_size ? next_count : beam_size;
        memcpy(beam, next, (size_t)beam_count * sizeof(beam[0]));
    }

    uint32_t found = 0u;
    uint32_t best_score = UINT32_MAX;
    uint64_t best_edges[M1RSI_PROOFSIZE];
    memset(best_edges, 0, sizeof(best_edges));

    if (bridge_edges >= 2u) {
        const uint32_t side = 0u;
        const uint32_t terminal_score_bits = exact_prune ? return_bits : pick_bits;
        for (uint32_t bi = 0u; bi < beam_count; ++bi) {
            const M1RsiLaceSparseBeamState *state = &beam[bi];
            const uint32_t want_endpoint_a = state->current_endpoint ^ 1u;
            const uint32_t want_endpoint_b = state->start_u_endpoint ^ 1u;
            const uint64_t salt = seed ^ 0x74776f6564676573ull ^ ((uint64_t)restart << 29u) ^
                                  ((uint64_t)bi * 0xd6e8feb86659fd93ull);
            M1RsiLaceBridge2Pick close;
            memset(&close, 0, sizeof(close));
            if (!m1rsi_lace_sparse_lift_pick_side_bridge2(
                    job,
                    idx,
                    side,
                    want_endpoint_a,
                    want_endpoint_b,
                    terminal_score_bits,
                    exact_prune,
                    salt,
                    state->edges,
                    state->edge_count,
                    edge_mask,
                    &close)) {
                continue;
            }
            uint64_t edges[M1RSI_PROOFSIZE];
            memcpy(edges, state->edges, sizeof(edges));
            edges[M1RSI_PROOFSIZE - 2u] = close.edge_a;
            edges[M1RSI_PROOFSIZE - 1u] = close.edge_b;
            if (!m1rsi_lace_edges_are_distinct(edges)) continue;
            if (!m1rsi_lace_residual_zero_bits(job, edges, idx->bits)) continue;
            if (!m1rsi_lace_residual_zero_bits(job, edges, return_bits)) continue;
            const uint32_t score = state->score + close.score;
            if (!found || score < best_score) {
                found = 1u;
                best_score = score;
                memcpy(best_edges, edges, sizeof(best_edges));
                if (score == 0u && terminal_score_bits == job->edge_bits) goto beam_finish;
            }
        }
    } else {
        for (uint32_t bi = 0u; bi < beam_count; ++bi) {
            const M1RsiLaceSparseBeamState *state = &beam[bi];
            const uint32_t want_v = (state->current_endpoint ^ 1u) & idx->mask;
            const uint32_t want_u = (state->start_u_endpoint ^ 1u) & idx->mask;
            const uint64_t dual_key = ((uint64_t)want_v << idx->bits) | (uint64_t)want_u;
            uint64_t close_edge = 0u;
            if (!m1rsi_lace_sparse_lift_lookup_dual(idx, dual_key, state->edges, state->edge_count, edge_mask, &close_edge)) continue;
            uint64_t edges[M1RSI_PROOFSIZE];
            memcpy(edges, state->edges, sizeof(edges));
            edges[M1RSI_PROOFSIZE - 1u] = close_edge;
            if (!m1rsi_lace_edges_are_distinct(edges)) continue;
            if (!m1rsi_lace_residual_zero_bits(job, edges, idx->bits)) continue;
            if (!m1rsi_lace_residual_zero_bits(job, edges, return_bits)) continue;
            if (!found || state->score < best_score) {
                found = 1u;
                best_score = state->score;
                memcpy(best_edges, edges, sizeof(best_edges));
            }
        }
    }

beam_finish:
    if (!found) return 0u;
    for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
        tpl->offsets[i] = (best_edges[i] - base_start) & edge_mask;
    }
    return 1u;
}

static void m1rsi_lace_sparse_lift_insert_dual(M1RsiLaceSparseLiftIndex *idx, uint64_t key, uint32_t edge) {
    if (!idx || !idx->dual_keys || !idx->dual_edges || idx->dual_capacity == 0u || edge == 0xffffffffu) return;
    uint64_t pos = m1rsi_lace_mix64((uint64_t)key ^ 0x6475616c31365f6bull) & idx->dual_mask;
    for (uint32_t probe = 0u; probe < 64u; ++probe) {
        const uint64_t cur = idx->dual_keys[pos];
        if (cur == UINT64_MAX) {
            idx->dual_keys[pos] = key;
            idx->dual_edges[pos] = edge;
            idx->dual_filled += 1u;
            return;
        }
        if (cur == key) return;
        pos = (pos + 1u) & idx->dual_mask;
    }
}

static uint32_t m1rsi_lace_sparse_lift_lookup_dual(
    const M1RsiLaceSparseLiftIndex *idx,
    uint64_t key,
    const uint64_t *edges,
    uint32_t edge_count,
    uint64_t edge_mask,
    uint64_t *out_edge) {
    if (!idx || !idx->dual_keys || !idx->dual_edges || idx->dual_capacity == 0u || !out_edge) return 0u;
    uint64_t pos = m1rsi_lace_mix64((uint64_t)key ^ 0x6475616c31365f6bull) & idx->dual_mask;
    for (uint32_t probe = 0u; probe < 64u; ++probe) {
        const uint64_t cur = idx->dual_keys[pos];
        if (cur == UINT64_MAX) return 0u;
        if (cur == key) {
            const uint64_t candidate = (uint64_t)idx->dual_edges[pos] & edge_mask;
            if (!m1rsi_lace_edge_distinct_prefix(edges, edge_count, candidate)) return 0u;
            *out_edge = candidate;
            return 1u;
        }
        pos = (pos + 1u) & idx->dual_mask;
    }
    return 0u;
}

static uint32_t m1rsi_lace_build_dual_low_index(const M1RsiJob *job, uint32_t bits, M1RsiLaceDualLowIndex *idx) {
    if (!job || !idx || bits == 0u || bits > 12u || job->edge_bits == 0u || job->edge_bits > 32u) return M1RSI_STATUS_BAD_ARGUMENT;
    memset(idx, 0, sizeof(*idx));
    const uint64_t bucket_count = 1ull << (2u * bits);
    if (bucket_count > (1ull << 24u)) return M1RSI_STATUS_BAD_ARGUMENT;
    idx->slots = (uint32_t *)malloc((size_t)bucket_count * sizeof(uint32_t));
    if (!idx->slots) return M1RSI_STATUS_INTERNAL;
    for (uint64_t i = 0u; i < bucket_count; ++i) idx->slots[i] = 0xffffffffu;

    idx->bits = bits;
    idx->mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
    idx->bucket_count = bucket_count;
    const uint64_t default_scan = bucket_count > (1ull << 26u) ? (1ull << 26u) : (bucket_count * 4ull);
    idx->scan_count = (uint64_t)m1rsi_lace_env_u32("M1RSI_LACE_DUAL_INDEX_SCAN", (uint32_t)default_scan, 1u, 1u << 27u);

    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint64_t seed = m1rsi_lace_mix64(0x4455414c5f4c4946ull ^ m1rsi_lace_key_mix(job) ^ (uint64_t)bits);
    const uint64_t stride = m1rsi_lace_mix64(seed ^ 0x737472696465ull) | 1ull;
    uint64_t edge = m1rsi_lace_mix64(seed ^ 0x7374617274ull) & edge_mask;
    for (uint64_t i = 0u; i < idx->scan_count; ++i) {
        const uint32_t v_low = m1rsi_endpoint(job->keys, job->edge_bits, edge, 1u) & idx->mask;
        const uint32_t u_low = m1rsi_endpoint(job->keys, job->edge_bits, edge, 0u) & idx->mask;
        const uint64_t key = ((uint64_t)v_low << bits) | (uint64_t)u_low;
        if (idx->slots[key] == 0xffffffffu) {
            idx->slots[key] = (uint32_t)edge;
            idx->filled += 1u;
        }
        edge = (edge + stride) & edge_mask;
    }
    fprintf(stderr,
            "m1rsi: lace_dual_low_index bits=%u buckets=%llu scanned=%llu filled=%llu graph_materialized=0 fixed_endpoint_preimage=0\n",
            bits,
            (unsigned long long)idx->bucket_count,
            (unsigned long long)idx->scan_count,
            (unsigned long long)idx->filled);
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_lace_generate_dual_index_template(
    const M1RsiJob *job,
    const M1RsiLaceDualLowIndex *idx,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal) {
    if (!job || !idx || !idx->slots || !tpl || idx->bits == 0u || idx->bits > 12u) return 0u;
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t restarts = m1rsi_lace_env_u32("M1RSI_LACE_DUAL_TEMPLATE_RESTARTS", 4096u, 1u, 1u << 20u);
    const uint64_t seed0 = m1rsi_lace_mix64(0x4455414c5f54454dull ^ m1rsi_lace_key_mix(job) ^ (ordinal * 0x9e3779b97f4a7c15ull));
    uint64_t edges[M1RSI_PROOFSIZE];

    for (uint32_t restart = 0u; restart < restarts; ++restart) {
        memset(edges, 0, sizeof(edges));
        uint32_t ok = 1u;
        const uint64_t seed = m1rsi_lace_mix64(seed0 ^ ((uint64_t)restart * 0xbf58476d1ce4e5b9ull));
        for (uint32_t k = 0u; k < M1RSI_BOUNDARY_RUNG_COUNT; ++k) {
            uint64_t even = m1rsi_lace_mix64(seed + ((uint64_t)k * 0x94d049bb133111ebull)) & edge_mask;
            uint32_t tweak = 0u;
            while (!m1rsi_lace_edge_distinct_prefix(edges, k * 2u, even) && tweak < 64u) {
                even = (even + m1rsi_lace_mix64(seed ^ ((uint64_t)tweak + 1u))) & edge_mask;
                tweak += 1u;
            }
            if (!m1rsi_lace_edge_distinct_prefix(edges, k * 2u, even)) {
                ok = 0u;
                break;
            }
            edges[k * 2u] = even;
        }
        if (!ok) continue;

        for (uint32_t k = 0u; k < M1RSI_BOUNDARY_RUNG_COUNT; ++k) {
            const uint32_t even = k * 2u;
            const uint32_t odd = even + 1u;
            const uint32_t next_even = (odd + 1u) % M1RSI_PROOFSIZE;
            const uint32_t want_v = (m1rsi_endpoint(job->keys, job->edge_bits, edges[even], 1u) ^ 1u) & idx->mask;
            const uint32_t want_u = (m1rsi_endpoint(job->keys, job->edge_bits, edges[next_even], 0u) ^ 1u) & idx->mask;
            const uint64_t key = ((uint64_t)want_v << idx->bits) | (uint64_t)want_u;
            uint64_t candidate = (uint64_t)idx->slots[key];
            if (idx->slots[key] == 0xffffffffu || !m1rsi_lace_edge_distinct_prefix(edges, odd, candidate)) {
                ok = 0u;
                break;
            }
            edges[odd] = candidate & edge_mask;
        }
        if (!ok) continue;
        if (!m1rsi_lace_edges_are_distinct(edges)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, idx->bits)) continue;
        for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
            tpl->offsets[i] = (edges[i] - base_start) & edge_mask;
        }
        return 1u;
    }
    return 0u;
}

static uint32_t m1rsi_lace_build_sparse_lift_index(const M1RsiJob *job, uint32_t bits, M1RsiLaceSparseLiftIndex *idx) {
    if (!job || !idx || bits == 0u || bits > 32u || job->edge_bits == 0u || job->edge_bits > 32u || bits > job->edge_bits) return M1RSI_STATUS_BAD_ARGUMENT;
    memset(idx, 0, sizeof(*idx));
    idx->bits = bits;
    idx->mask = bits >= 32u ? 0xffffffffu : ((1u << bits) - 1u);
    idx->endpoint_count = m1rsi_lace_sparse_lift_endpoint_count_field(bits);
    idx->way_count = m1rsi_lace_sparse_lift_desired_way_count(bits);
    idx->bridge_edges = m1rsi_lace_sparse_lift_desired_bridge_edges(bits);
    const uint64_t endpoint_slots = m1rsi_lace_sparse_lift_endpoint_slots(bits, idx->way_count);
    idx->side_edges[0] = (uint32_t *)malloc((size_t)endpoint_slots * sizeof(uint32_t));
    idx->side_edges[1] = (uint32_t *)malloc((size_t)endpoint_slots * sizeof(uint32_t));
    idx->side_other[0] = (uint32_t *)malloc((size_t)endpoint_slots * sizeof(uint32_t));
    idx->side_other[1] = (uint32_t *)malloc((size_t)endpoint_slots * sizeof(uint32_t));
    if (!idx->side_edges[0] || !idx->side_edges[1] || !idx->side_other[0] || !idx->side_other[1]) {
        m1rsi_lace_sparse_lift_index_free(idx);
        return M1RSI_STATUS_INTERNAL;
    }
    memset(idx->side_edges[0], 0xff, (size_t)endpoint_slots * sizeof(uint32_t));
    memset(idx->side_edges[1], 0xff, (size_t)endpoint_slots * sizeof(uint32_t));
    memset(idx->side_other[0], 0, (size_t)endpoint_slots * sizeof(uint32_t));
    memset(idx->side_other[1], 0, (size_t)endpoint_slots * sizeof(uint32_t));

    idx->scan_count = m1rsi_lace_sparse_lift_desired_scan_count(job, bits);
    if (idx->bridge_edges <= 1u) {
        idx->dual_capacity = m1rsi_lace_pow2_at_least(idx->scan_count * 2ull);
        if (idx->dual_capacity < 1024ull) idx->dual_capacity = 1024ull;
        idx->dual_mask = idx->dual_capacity - 1ull;
        idx->dual_keys = (uint64_t *)malloc((size_t)idx->dual_capacity * sizeof(uint64_t));
        idx->dual_edges = (uint32_t *)malloc((size_t)idx->dual_capacity * sizeof(uint32_t));
        if (!idx->dual_keys || !idx->dual_edges) {
            m1rsi_lace_sparse_lift_index_free(idx);
            return M1RSI_STATUS_INTERNAL;
        }
        for (uint64_t i = 0u; i < idx->dual_capacity; ++i) {
            idx->dual_keys[i] = UINT64_MAX;
            idx->dual_edges[i] = 0xffffffffu;
        }
    }

    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint64_t seed = m1rsi_lace_mix64(0x5350415253454c46ull ^ m1rsi_lace_key_mix(job) ^ (uint64_t)bits);
    const uint64_t stride = m1rsi_lace_mix64(seed ^ 0x7370617273657374ull) | 1ull;
    const uint64_t edge_start = m1rsi_lace_mix64(seed ^ 0x7370617273656261ull) & edge_mask;
    uint32_t index_threads = m1rsi_lace_sparse_index_thread_count(bits, idx->bridge_edges);
    if (index_threads > idx->scan_count) index_threads = (uint32_t)idx->scan_count;
    uint32_t index_parallel_fallback = 0u;
    if (index_threads > 1u && idx->bridge_edges >= 2u && idx->scan_count >= (1ull << 20u)) {
        if (index_threads > 64u) index_threads = 64u;
        pthread_t tids[64];
        M1RsiLaceSparseIndexWorker workers[64];
        memset(tids, 0, sizeof(tids));
        memset(workers, 0, sizeof(workers));
        uint32_t launched = 0u;
        uint32_t create_failed = 0u;
        for (uint32_t t = 0u; t < index_threads; ++t) {
            workers[t].job = job;
            workers[t].idx = idx;
            workers[t].edge_start = edge_start;
            workers[t].stride = stride;
            workers[t].edge_mask = edge_mask;
            workers[t].begin = (idx->scan_count * (uint64_t)t) / (uint64_t)index_threads;
            workers[t].end = (idx->scan_count * (uint64_t)(t + 1u)) / (uint64_t)index_threads;
            if (pthread_create(&tids[t], NULL, m1rsi_lace_sparse_index_worker_main, &workers[t]) != 0) {
                create_failed = 1u;
                break;
            }
            launched += 1u;
        }
        for (uint32_t t = 0u; t < launched; ++t) pthread_join(tids[t], NULL);
        if (!create_failed && launched == index_threads) {
            idx->side_filled[0] = 0u;
            idx->side_filled[1] = 0u;
            for (uint32_t t = 0u; t < launched; ++t) {
                idx->side_filled[0] += workers[t].side_filled[0];
                idx->side_filled[1] += workers[t].side_filled[1];
            }
        } else {
            memset(idx->side_edges[0], 0xff, (size_t)endpoint_slots * sizeof(uint32_t));
            memset(idx->side_edges[1], 0xff, (size_t)endpoint_slots * sizeof(uint32_t));
            memset(idx->side_other[0], 0, (size_t)endpoint_slots * sizeof(uint32_t));
            memset(idx->side_other[1], 0, (size_t)endpoint_slots * sizeof(uint32_t));
            idx->side_filled[0] = 0u;
            idx->side_filled[1] = 0u;
            index_parallel_fallback = 1u;
            index_threads = 1u;
        }
    }
    if (index_threads <= 1u || idx->bridge_edges <= 1u || idx->scan_count < (1ull << 20u)) {
        uint64_t edge = edge_start;
        for (uint64_t i = 0u; i < idx->scan_count; ++i) {
            if (edge != 0xffffffffull) {
                const uint32_t v_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edge, 1u);
                const uint32_t u_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edge, 0u);
                const uint32_t v_low = v_endpoint & idx->mask;
                const uint32_t u_low = u_endpoint & idx->mask;
                m1rsi_lace_sparse_lift_insert_side(idx, 1u, v_low, u_endpoint, (uint32_t)edge);
                m1rsi_lace_sparse_lift_insert_side(idx, 0u, u_low, v_endpoint, (uint32_t)edge);
                if (idx->bridge_edges <= 1u) {
                    const uint64_t key = ((uint64_t)v_low << bits) | (uint64_t)u_low;
                    m1rsi_lace_sparse_lift_insert_dual(idx, key, (uint32_t)edge);
                }
            }
            edge = (edge + stride) & edge_mask;
        }
    }

    fprintf(stderr,
            "m1rsi: lace_sparse_lift_index bits=%u endpoint_slots=%llu ways=%u bridge_edges=%u scanned=%llu index_threads=%u index_parallel_fallback=%u side0_filled=%llu side1_filled=%llu dual_capacity=%llu dual_filled=%llu graph_materialized=0 fixed_endpoint_preimage=0\n",
            bits,
            (unsigned long long)endpoint_slots,
            idx->way_count,
            idx->bridge_edges,
            (unsigned long long)idx->scan_count,
            index_threads,
            index_parallel_fallback,
            (unsigned long long)idx->side_filled[0],
            (unsigned long long)idx->side_filled[1],
            (unsigned long long)idx->dual_capacity,
            (unsigned long long)idx->dual_filled);
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_lace_sparse_lift_cache_get(
    const M1RsiJob *job,
    uint32_t bits,
    M1RsiLaceSparseLiftIndex **out_idx,
    uint32_t *out_hit) {
    if (out_idx) *out_idx = NULL;
    if (out_hit) *out_hit = 0u;
    if (!job || !out_idx) return M1RSI_STATUS_BAD_ARGUMENT;
    const uint32_t desired_ways = m1rsi_lace_sparse_lift_desired_way_count(bits);
    const uint32_t desired_bridge_edges = m1rsi_lace_sparse_lift_desired_bridge_edges(bits);
    const uint64_t desired_scan = m1rsi_lace_sparse_lift_desired_scan_count(job, bits);
    if (g_lace_sparse_lift_cache.valid &&
        g_lace_sparse_lift_cache.bits == bits &&
        g_lace_sparse_lift_cache.edge_bits == job->edge_bits &&
        g_lace_sparse_lift_cache.way_count == desired_ways &&
        g_lace_sparse_lift_cache.bridge_edges == desired_bridge_edges &&
        g_lace_sparse_lift_cache.scan_count == desired_scan &&
        m1rsi_lace_keys_equal(g_lace_sparse_lift_cache.keys, job->keys)) {
        *out_idx = &g_lace_sparse_lift_cache.idx;
        if (out_hit) *out_hit = 1u;
        fprintf(stderr,
                "m1rsi: lace_sparse_lift_cache_hit bits=%u ways=%u bridge_edges=%u scanned=%llu dual_filled=%llu graph_materialized=0 fixed_endpoint_preimage=0\n",
                bits,
                desired_ways,
                desired_bridge_edges,
                (unsigned long long)desired_scan,
                (unsigned long long)g_lace_sparse_lift_cache.idx.dual_filled);
        return M1RSI_STATUS_OK;
    }

    m1rsi_lace_sparse_lift_index_free(&g_lace_sparse_lift_cache.idx);
    m1rsi_lace_bridge_catalog_cache_free(&g_lace_bridge_catalog_cache);
    m1rsi_lace_path_mitm_endpoint_cache_free(&g_lace_path_mitm_endpoint_cache);
    memset(&g_lace_sparse_lift_cache, 0, sizeof(g_lace_sparse_lift_cache));
    char index_path[4096];
    const uint32_t has_index_path = m1rsi_lace_sparse_lift_index_path(job, bits, index_path, sizeof(index_path));
    if (has_index_path &&
        m1rsi_lace_sparse_lift_try_load_file(job, bits, index_path, &g_lace_sparse_lift_cache.idx)) {
        g_lace_sparse_lift_cache.valid = 1u;
        g_lace_sparse_lift_cache.bits = bits;
        g_lace_sparse_lift_cache.edge_bits = job->edge_bits;
        g_lace_sparse_lift_cache.way_count = desired_ways;
        g_lace_sparse_lift_cache.bridge_edges = desired_bridge_edges;
        g_lace_sparse_lift_cache.scan_count = desired_scan;
        g_lace_sparse_lift_cache.keys = job->keys;
        *out_idx = &g_lace_sparse_lift_cache.idx;
        if (out_hit) *out_hit = 1u;
        return M1RSI_STATUS_OK;
    }
    uint32_t st = m1rsi_lace_build_sparse_lift_index(job, bits, &g_lace_sparse_lift_cache.idx);
    if (st != M1RSI_STATUS_OK) return st;
    if (has_index_path) {
        (void)m1rsi_lace_sparse_lift_save_file(job, &g_lace_sparse_lift_cache.idx, index_path);
    }
    g_lace_sparse_lift_cache.valid = 1u;
    g_lace_sparse_lift_cache.bits = bits;
    g_lace_sparse_lift_cache.edge_bits = job->edge_bits;
    g_lace_sparse_lift_cache.way_count = desired_ways;
    g_lace_sparse_lift_cache.bridge_edges = desired_bridge_edges;
    g_lace_sparse_lift_cache.scan_count = desired_scan;
    g_lace_sparse_lift_cache.keys = job->keys;
    *out_idx = &g_lace_sparse_lift_cache.idx;
    fprintf(stderr,
            "m1rsi: lace_sparse_lift_cache_store bits=%u ways=%u bridge_edges=%u scanned=%llu graph_materialized=0 fixed_endpoint_preimage=0\n",
            bits,
            desired_ways,
            desired_bridge_edges,
            (unsigned long long)desired_scan);
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_lace_host_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1l) return 1u;
    if (n > 64l) return 64u;
    return (uint32_t)n;
}

static uint32_t m1rsi_lace_sparse_template_thread_count(const M1RsiLaceSparseLiftIndex *idx) {
    uint32_t fallback = (idx && idx->bits >= 24u) ? m1rsi_lace_host_cpu_count() : 1u;
    if (fallback > 32u) fallback = 32u;
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.template_threads != 0u) {
        uint32_t threads = g_lace_sparse_config_override.template_threads;
        if (threads > 64u) threads = 64u;
        return threads == 0u ? 1u : threads;
    }
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_TEMPLATE_THREADS", fallback, 1u, 64u);
}

static M1RsiLaceSparseConfigOverride m1rsi_lace_sparse_high_config(const M1RsiJob *job, uint32_t bits) {
    M1RsiLaceSparseConfigOverride cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (!job || bits == 0u || job->edge_bits == 0u) return cfg;
    cfg.active = 1u;
    if (bits > job->edge_bits) bits = job->edge_bits;
    uint32_t host_threads = m1rsi_lace_host_cpu_count();
    if (host_threads > 32u) host_threads = 32u;
    const uint64_t max_scan = m1rsi_lace_sparse_lift_max_scan(job);
    uint64_t default_scan = bits >= 24u ? (1ull << 25u) : m1rsi_lace_sparse_lift_default_scan(bits);
    if (default_scan > max_scan) default_scan = max_scan;
    cfg.bridge_edges = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_BRIDGE_EDGES", 2u, 1u, 2u);
    cfg.way_count = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_LIFT_WAYS", bits >= 32u ? 1u : 4u, 1u, 16u);
    cfg.scan_count = m1rsi_lace_env_u64("M1RSI_LACE_SPARSE_HIGH_LIFT_SCAN", default_scan, 1ull, max_scan);
    cfg.index_threads = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_INDEX_THREADS", host_threads, 1u, 64u);
    cfg.template_threads = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_TEMPLATE_THREADS", host_threads, 1u, 64u);
    cfg.pick_bits = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_PICK_BITS", bits, bits, job->edge_bits);
    cfg.return_bits = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_RETURN_BITS", bits, bits, job->edge_bits);
    cfg.bridge_first_probes = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_BRIDGE_FIRST_PROBES", 1u << 18u, 0u, 1u << 30u);
    cfg.bridge_catalog_cap = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_BRIDGE_CATALOG_CAP", 1u << 16u, 1u, 1u << 24u);
    cfg.path_mitm_fanout = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_PATH_MITM_FANOUT", 1u << 13u, 0u, 1u << 20u);
    cfg.path_mitm_left = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_PATH_MITM_LEFT", 19u, 1u, M1RSI_PROOFSIZE - 4u);
    cfg.path_mitm_threads = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_PATH_MITM_THREADS", host_threads, 1u, 64u);
    cfg.endpoint_cache_cap = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_ENDPOINT_CACHE_CAP", 16u, 0u, 1u << 16u);
    cfg.template_restarts = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_TEMPLATE_RESTARTS", 1u, 1u, 1u << 30u);
    return cfg;
}

static uint32_t m1rsi_lace_generate_sparse_bridge_mitm_template(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    const M1RsiLaceBridgeCatalogEntry *entry,
    uint32_t entry_index,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal,
    uint32_t return_bits,
    uint32_t fanout,
    uint32_t left_steps) {
    if (!job || !idx || !entry || !tpl || fanout == 0u || left_steps == 0u || left_steps >= M1RSI_PROOFSIZE - 3u) return 0u;
    if (return_bits < idx->bits) return_bits = idx->bits;
    if (return_bits > job->edge_bits) return_bits = job->edge_bits;
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t start_key = entry->start_u & return_mask;
    const uint32_t target_key = entry->target_current & return_mask;
    const uint64_t close_a = (uint64_t)entry->edge_a & edge_mask;
    const uint64_t close_b = (uint64_t)entry->edge_b & edge_mask;
    M1RsiLacePathMitmState *forward = NULL;
    M1RsiLacePathMitmState *reverse = NULL;
    uint32_t forward_count = 0u;
    uint32_t reverse_count = 0u;
    uint32_t forward_cache_owned = 0u;
    uint32_t reverse_cache_owned = 0u;
    uint32_t forward_cache_hit = 0u;
    uint32_t reverse_cache_hit = 0u;

    forward_cache_owned = m1rsi_lace_path_mitm_endpoint_cache_get(
            job,
            idx,
            0u,
            start_key,
            ordinal,
            return_bits,
            fanout,
            left_steps,
            edge_mask,
            &forward,
            &forward_count,
            &forward_cache_hit);
    if (!forward_cache_owned) {
        forward = (M1RsiLacePathMitmState *)calloc((size_t)fanout, sizeof(*forward));
        if (!forward) return 0u;
        m1rsi_lace_path_mitm_fill_endpoint_states(
            job,
            idx,
            0u,
            start_key,
            ordinal,
            return_bits,
            fanout,
            left_steps,
            edge_mask,
            forward,
            &forward_count);
    }

    reverse_cache_owned = m1rsi_lace_path_mitm_endpoint_cache_get(
            job,
            idx,
            1u,
            target_key,
            ordinal,
            return_bits,
            fanout,
            left_steps,
            edge_mask,
            &reverse,
            &reverse_count,
            &reverse_cache_hit);
    if (!reverse_cache_owned) {
        reverse = (M1RsiLacePathMitmState *)calloc((size_t)fanout, sizeof(*reverse));
        if (!reverse) {
            if (!forward_cache_owned) free(forward);
            return 0u;
        }
        m1rsi_lace_path_mitm_fill_endpoint_states(
            job,
            idx,
            1u,
            target_key,
            ordinal,
            return_bits,
            fanout,
            left_steps,
            edge_mask,
            reverse,
            &reverse_count);
    }

    if (forward_count != 0u && reverse_count != 0u) {
        if (!forward_cache_owned) qsort(forward, forward_count, sizeof(forward[0]), m1rsi_lace_path_mitm_state_cmp);
        const uint32_t reverse_start = (uint32_t)(m1rsi_lace_mix64(
            0x4a4f494e52455653ull ^
            (ordinal * 0x9e3779b97f4a7c15ull) ^
            ((uint64_t)entry_index * 0xd6e8feb86659fd93ull)) % (uint64_t)reverse_count);
        for (uint32_t rstep = 0u; rstep < reverse_count; ++rstep) {
            const uint32_t ri = (reverse_start + rstep) % reverse_count;
            const uint32_t begin = m1rsi_lace_path_mitm_lower_bound(forward, forward_count, reverse[ri].key);
            uint32_t end = begin;
            while (end < forward_count && forward[end].key == reverse[ri].key) ++end;
            const uint32_t span = end - begin;
            if (span == 0u) continue;
            const uint32_t forward_start = begin + (uint32_t)(m1rsi_lace_mix64(
                0x4a4f494e46574453ull ^
                (ordinal * 0x94d049bb133111ebull) ^
                ((uint64_t)entry_index * 0xa0761d6478bd642full) ^
                ((uint64_t)reverse[ri].key * 0xe7037ed1a0b428dbull)) % (uint64_t)span);
            for (uint32_t fstep = 0u; fstep < span; ++fstep) {
                const uint32_t fi = begin + ((forward_start - begin + fstep) % span);
                uint64_t edges[M1RSI_PROOFSIZE];
                memset(edges, 0, sizeof(edges));
                for (uint32_t i = 0u; i <= left_steps; ++i) edges[i] = forward[fi].edges[i];
                for (uint32_t i = left_steps + 1u; i < M1RSI_PROOFSIZE - 2u; ++i) edges[i] = reverse[ri].edges[i];
                edges[M1RSI_PROOFSIZE - 2u] = close_a;
                edges[M1RSI_PROOFSIZE - 1u] = close_b;
                if (!m1rsi_lace_edges_are_distinct(edges)) continue;
                if (!m1rsi_lace_residual_zero_bits(job, edges, idx->bits)) continue;
                if (!m1rsi_lace_residual_zero_bits(job, edges, return_bits)) continue;
                for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
                    tpl->offsets[i] = (edges[i] - base_start) & edge_mask;
                }
                fprintf(stderr,
                        "m1rsi: lace_bridge_path_mitm bits=%u return_bits=%u fanout=%u left_steps=%u forward=%u reverse=%u entry=%u endpoint_cache_forward_hit=%u endpoint_cache_reverse_hit=%u endpoint_cache_forward_owned=%u endpoint_cache_reverse_owned=%u ordinal_join_shuffle=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                        idx->bits,
                        return_bits,
                        fanout,
                        left_steps,
                        forward_count,
                        reverse_count,
                        entry_index,
                        forward_cache_hit,
                        reverse_cache_hit,
                        forward_cache_owned,
                        reverse_cache_owned);
                if (!forward_cache_owned) free(forward);
                if (!reverse_cache_owned) free(reverse);
                return 1u;
            }
        }
    }

    if (!forward_cache_owned) free(forward);
    if (!reverse_cache_owned) free(reverse);
    return 0u;
}

static uint32_t m1rsi_lace_generate_sparse_bridge_first_template(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal,
    uint32_t return_bits,
    uint32_t probe_count) {
    if (!job || !idx || !tpl || idx->bridge_edges < 2u || idx->way_count == 0u ||
        !idx->side_edges[0] || !idx->side_edges[1] || !idx->side_other[0] || !idx->side_other[1] ||
        idx->bits == 0u || idx->bits > job->edge_bits || probe_count == 0u) {
        return 0u;
    }
    if (return_bits < idx->bits) return_bits = idx->bits;
    if (return_bits > job->edge_bits) return_bits = job->edge_bits;
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t return_mask = return_bits >= 32u ? 0xffffffffu : ((1u << return_bits) - 1u);
    M1RsiLaceBridgeCatalogCache *catalog = NULL;
    if (!m1rsi_lace_sparse_bridge_catalog_get(job, idx, return_bits, probe_count, &catalog) ||
        !catalog || catalog->count == 0u) {
        return 0u;
    }
    const uint32_t mitm_fanout = m1rsi_lace_sparse_path_mitm_fanout(idx);
    const uint32_t mitm_left_steps = m1rsi_lace_sparse_path_mitm_left_steps();
    const uint32_t entry_start = (uint32_t)(m1rsi_lace_mix64(ordinal ^ 0x4252494447453146ull) % (uint64_t)catalog->count);

    if (mitm_fanout != 0u) {
        for (uint32_t offset = 0u; offset < catalog->count; ++offset) {
            const uint32_t entry_index = (entry_start + offset) % catalog->count;
            const M1RsiLaceBridgeCatalogEntry *entry = &catalog->entries[entry_index];
            if (m1rsi_lace_generate_sparse_bridge_mitm_template(
                    job,
                    idx,
                    entry,
                    entry_index,
                    tpl,
                    base_start,
                    ordinal,
                    return_bits,
                    mitm_fanout,
                    mitm_left_steps)) {
                return 1u;
            }
        }
        fprintf(stderr,
                "m1rsi: lace_bridge_path_mitm_required_miss bits=%u return_bits=%u fanout=%u left_steps=%u catalog_entries=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                idx->bits,
                return_bits,
                mitm_fanout,
                mitm_left_steps,
                catalog->count);
        return 0u;
    }

    for (uint32_t offset = 0u; offset < catalog->count; ++offset) {
        const uint32_t entry_index = (entry_start + offset) % catalog->count;
        const M1RsiLaceBridgeCatalogEntry *entry = &catalog->entries[entry_index];
        const uint64_t close_a = (uint64_t)entry->edge_a & edge_mask;
        const uint64_t close_b = (uint64_t)entry->edge_b & edge_mask;
        const uint32_t close_a_v = m1rsi_endpoint(job->keys, job->edge_bits, close_a, 1u);
        const uint32_t close_b_v = m1rsi_endpoint(job->keys, job->edge_bits, close_b, 1u);
        if (((close_a_v ^ close_b_v) & return_mask) != 1u) continue;
        const uint32_t start_u = entry->start_u;
        const uint32_t target_current = entry->target_current;
        const uint64_t salt0 = m1rsi_lace_mix64(
            0x4252494447453146ull ^
            m1rsi_lace_key_mix(job) ^
            (ordinal * 0x9e3779b97f4a7c15ull) ^
            ((uint64_t)entry_index * 0x94d049bb133111ebull) ^
            ((uint64_t)return_bits * 0xd6e8feb86659fd93ull));

        uint64_t edges[M1RSI_PROOFSIZE];
        memset(edges, 0, sizeof(edges));
        uint32_t current_endpoint = 0u;
        if (!m1rsi_lace_sparse_lift_pick_side_exact(
                job,
                idx,
                0u,
                start_u,
                return_bits,
                salt0 ^ 0x73746172745f75ull,
                edges,
                0u,
                edge_mask,
                &edges[0],
                &current_endpoint)) {
            continue;
        }

        uint32_t ok = 1u;
        const uint32_t chain_pairs = M1RSI_PROOFSIZE - 3u;
        for (uint32_t j = 0u; j < chain_pairs; ++j) {
            const uint32_t side = m1rsi_lace_delta_side(j);
            const uint32_t want = current_endpoint ^ 1u;
            uint64_t candidate = 0u;
            uint32_t other_endpoint = 0u;
            if (!m1rsi_lace_sparse_lift_pick_side_exact(
                    job,
                    idx,
                    side,
                    want,
                    return_bits,
                    salt0 ^ ((uint64_t)j * 0xa0761d6478bd642full),
                    edges,
                    j + 1u,
                    edge_mask,
                    &candidate,
                    &other_endpoint)) {
                ok = 0u;
                break;
            }
            edges[j + 1u] = candidate;
            current_endpoint = other_endpoint;
        }
        if (!ok) continue;
        if (((current_endpoint ^ target_current) & return_mask) != 0u) continue;
        edges[M1RSI_PROOFSIZE - 2u] = close_a;
        edges[M1RSI_PROOFSIZE - 1u] = close_b;
        if (!m1rsi_lace_edges_are_distinct(edges)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, idx->bits)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, return_bits)) continue;
        for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
            tpl->offsets[i] = (edges[i] - base_start) & edge_mask;
        }
        fprintf(stderr,
                "m1rsi: lace_bridge_first_template bits=%u return_bits=%u probes=%u catalog_entries=%u ordinal=%llu entry=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                idx->bits,
                return_bits,
                probe_count,
                catalog->count,
                (unsigned long long)ordinal,
                entry_index);
        return 1u;
    }
    return 0u;
}

static uint32_t m1rsi_lace_generate_sparse_lift_template_range(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal,
    uint32_t restart_begin,
    uint32_t restart_end,
    atomic_uint *stop_flag) {
    if (!job || !idx || !tpl || !idx->side_edges[0] || !idx->side_edges[1] || idx->bits == 0u || idx->bits > 32u || idx->bits > job->edge_bits) return 0u;
    const uint32_t bridge_edges = idx->bridge_edges ? idx->bridge_edges : 1u;
    if (bridge_edges <= 1u && (!idx->dual_keys || !idx->dual_edges)) return 0u;
    if (bridge_edges >= 2u && (!idx->side_other[0] || !idx->side_other[1])) return 0u;
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t pick_bits = m1rsi_lace_sparse_pick_bits(job, idx);
    const uint32_t return_bits = m1rsi_lace_sparse_return_bits(job, idx);
    if (pick_bits == 0u || return_bits == 0u) return 0u;
    const uint32_t beam_size = m1rsi_lace_sparse_template_beam_width(idx);
    const uint32_t use_beam_solver = (beam_size > 1u || return_bits > idx->bits) ? 1u : 0u;
    const uint32_t exact_lift_requires_beam = return_bits > idx->bits ? 1u : 0u;
    const uint32_t next_cap = (use_beam_solver && idx->way_count != 0u && beam_size <= UINT32_MAX / idx->way_count)
        ? beam_size * idx->way_count
        : 0u;
    M1RsiLaceSparseBeamState *beam = NULL;
    M1RsiLaceSparseBeamState *next = NULL;
    if (use_beam_solver && next_cap == 0u) return 0u;
    if (use_beam_solver && next_cap != 0u) {
        beam = (M1RsiLaceSparseBeamState *)calloc((size_t)beam_size, sizeof(*beam));
        next = (M1RsiLaceSparseBeamState *)calloc((size_t)next_cap, sizeof(*next));
        if (!beam || !next) {
            free(beam);
            free(next);
            if (exact_lift_requires_beam) return 0u;
            beam = NULL;
            next = NULL;
        }
    }
    const uint64_t seed0 = m1rsi_lace_mix64(0x535041525345544dull ^ m1rsi_lace_key_mix(job) ^ (ordinal * 0xd6e8feb86659fd93ull));
    uint64_t edges[M1RSI_PROOFSIZE];

    for (uint32_t restart = restart_begin; restart < restart_end; ++restart) {
        if (stop_flag && atomic_load_explicit(stop_flag, memory_order_relaxed)) {
            free(beam);
            free(next);
            return 0u;
        }
        const uint64_t seed = m1rsi_lace_mix64(seed0 ^ ((uint64_t)restart * 0x9e3779b97f4a7c15ull));
        if (beam && next) {
            if (m1rsi_lace_generate_sparse_lift_template_beam_restart(
                    job, idx, tpl, base_start, edge_mask, seed, restart, pick_bits, return_bits, beam_size, beam, next, next_cap)) {
                free(beam);
                free(next);
                return 1u;
            }
            continue;
        }
        memset(edges, 0, sizeof(edges));
        edges[0] = m1rsi_lace_mix64(seed ^ 0x6c69667462617365ull) & edge_mask;
        uint32_t current_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edges[0], 1u);
        uint32_t start_u_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edges[0], 0u);

        uint32_t ok = 1u;
        const uint32_t chain_pairs = bridge_edges >= 2u ? (M1RSI_PROOFSIZE - 3u) : (M1RSI_PROOFSIZE - 2u);
        for (uint32_t j = 0u; j < chain_pairs; ++j) {
            const uint32_t side = m1rsi_lace_delta_side(j);
            const uint32_t want = current_endpoint ^ 1u;
            uint64_t candidate = 0u;
            uint32_t other_endpoint = 0u;
            const uint64_t salt = seed ^ ((uint64_t)j * 0xbf58476d1ce4e5b9ull) ^ ((uint64_t)restart << 32u);
            if (!m1rsi_lace_sparse_lift_pick_side(job, idx, side, want, pick_bits, salt, edges, j + 1u, edge_mask, &candidate, &other_endpoint)) {
                ok = 0u;
                break;
            }
            edges[j + 1u] = candidate;
            current_endpoint = other_endpoint;
        }
        if (!ok) continue;

        if (bridge_edges >= 2u) {
            const uint32_t want_u_a = current_endpoint ^ 1u;
            const uint32_t want_u_b = start_u_endpoint ^ 1u;
            const uint64_t salt = seed ^ 0x74776f6564676573ull ^ ((uint64_t)restart << 29u);
            M1RsiLaceBridge2Pick close;
            memset(&close, 0, sizeof(close));
            if (!m1rsi_lace_sparse_lift_pick_side_bridge2(
                    job,
                    idx,
                    0u,
                    want_u_a,
                    want_u_b,
                    return_bits > idx->bits ? return_bits : pick_bits,
                    return_bits > idx->bits ? 1u : 0u,
                    salt,
                    edges,
                    M1RSI_PROOFSIZE - 2u,
                    edge_mask,
                    &close)) {
                continue;
            }
            edges[M1RSI_PROOFSIZE - 2u] = close.edge_a;
            edges[M1RSI_PROOFSIZE - 1u] = close.edge_b;
        } else {
            const uint32_t want_v = (current_endpoint ^ 1u) & idx->mask;
            const uint32_t want_u = (start_u_endpoint ^ 1u) & idx->mask;
            const uint64_t dual_key = ((uint64_t)want_v << idx->bits) | (uint64_t)want_u;
            uint64_t close_edge = 0u;
            if (!m1rsi_lace_sparse_lift_lookup_dual(idx, dual_key, edges, M1RSI_PROOFSIZE - 1u, edge_mask, &close_edge)) continue;
            edges[M1RSI_PROOFSIZE - 1u] = close_edge;
        }

        if (!m1rsi_lace_edges_are_distinct(edges)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, idx->bits)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, return_bits)) continue;
        for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
            tpl->offsets[i] = (edges[i] - base_start) & edge_mask;
        }
        free(beam);
        free(next);
        return 1u;
    }
    free(beam);
    free(next);
    return 0u;
}

typedef struct M1RsiLaceSparseTemplateWorker {
    const M1RsiJob *job;
    const M1RsiLaceSparseLiftIndex *idx;
    M1RsiLaceTemplate42 *out_tpl;
    atomic_uint *found_flag;
    uint64_t base_start;
    uint64_t ordinal;
    uint32_t restart_begin;
    uint32_t restart_end;
    uint32_t found_local;
} M1RsiLaceSparseTemplateWorker;

static void *m1rsi_lace_sparse_template_worker_main(void *raw) {
    M1RsiLaceSparseTemplateWorker *w = (M1RsiLaceSparseTemplateWorker *)raw;
    if (!w) return NULL;
    M1RsiLaceTemplate42 local_tpl;
    memset(&local_tpl, 0, sizeof(local_tpl));
    if (m1rsi_lace_generate_sparse_lift_template_range(
            w->job,
            w->idx,
            &local_tpl,
            w->base_start,
            w->ordinal,
            w->restart_begin,
            w->restart_end,
            w->found_flag)) {
        uint32_t expected = 0u;
        if (atomic_compare_exchange_strong_explicit(w->found_flag, &expected, 1u, memory_order_relaxed, memory_order_relaxed)) {
            *w->out_tpl = local_tpl;
            w->found_local = 1u;
        }
    }
    return NULL;
}

static uint32_t m1rsi_lace_generate_sparse_lift_template(
    const M1RsiJob *job,
    const M1RsiLaceSparseLiftIndex *idx,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal) {
    if (!job || !idx || !tpl || idx->bits == 0u || idx->bits > 32u || idx->bits > job->edge_bits) return 0u;
    const uint32_t return_bits = m1rsi_lace_sparse_return_bits(job, idx);
    const uint32_t bridge_first_probes = m1rsi_lace_sparse_bridge_first_probes(idx);
    if (return_bits != 0u && bridge_first_probes != 0u &&
        m1rsi_lace_generate_sparse_bridge_first_template(job, idx, tpl, base_start, ordinal, return_bits, bridge_first_probes)) {
        return 1u;
    }
    const uint32_t default_restarts = idx->bits >= 28u ? (1u << 24u) : (idx->bits >= 24u ? (1u << 22u) : (idx->bits >= 20u ? (1u << 18u) : 16384u));
    uint32_t restarts = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_TEMPLATE_RESTARTS", default_restarts, 1u, 1u << 30u);
    if (g_lace_sparse_config_override.active && g_lace_sparse_config_override.template_restarts != 0u) {
        restarts = g_lace_sparse_config_override.template_restarts;
        if (restarts < 1u) restarts = 1u;
        if (restarts > (1u << 30u)) restarts = 1u << 30u;
    }
    uint32_t threads = m1rsi_lace_sparse_template_thread_count(idx);
    if (threads > restarts) threads = restarts;
    if (threads <= 1u || restarts < 4096u) {
        return m1rsi_lace_generate_sparse_lift_template_range(job, idx, tpl, base_start, ordinal, 0u, restarts, NULL);
    }
    if (threads > 64u) threads = 64u;

    pthread_t tids[64];
    M1RsiLaceSparseTemplateWorker workers[64];
    memset(tids, 0, sizeof(tids));
    memset(workers, 0, sizeof(workers));
    atomic_uint found_flag;
    atomic_init(&found_flag, 0u);

    uint32_t launched = 0u;
    uint32_t create_failed = 0u;
    for (uint32_t t = 0u; t < threads; ++t) {
        const uint32_t begin = (uint32_t)(((uint64_t)restarts * (uint64_t)t) / (uint64_t)threads);
        const uint32_t end = (uint32_t)(((uint64_t)restarts * (uint64_t)(t + 1u)) / (uint64_t)threads);
        workers[t].job = job;
        workers[t].idx = idx;
        workers[t].out_tpl = tpl;
        workers[t].found_flag = &found_flag;
        workers[t].base_start = base_start;
        workers[t].ordinal = ordinal;
        workers[t].restart_begin = begin;
        workers[t].restart_end = end;
        if (pthread_create(&tids[t], NULL, m1rsi_lace_sparse_template_worker_main, &workers[t]) != 0) {
            create_failed = 1u;
            break;
        }
        launched += 1u;
    }
    for (uint32_t t = 0u; t < launched; ++t) pthread_join(tids[t], NULL);
    if (atomic_load_explicit(&found_flag, memory_order_relaxed)) return 1u;
    if (create_failed || launched == 0u) {
        return m1rsi_lace_generate_sparse_lift_template_range(job, idx, tpl, base_start, ordinal, 0u, restarts, NULL);
    }
    return 0u;
}

/*
 * Build one absolute-offset LACE support by satisfying the born low-bit
 * endpoint obligations for this exact SipHash key. This is the
 * key-basin/differential-lift entry point: it does not target a fixed endpoint
 * value and it does not build graph adjacency. It searches for nonce
 * differences whose truncated endpoint self-collision obligations hold, then
 * emits the resulting witness support as a normal LACE template for the Metal
 * residual lift kernel.
 */
static uint32_t m1rsi_lace_generate_keyed_lift_template(
    const M1RsiJob *job,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal,
    uint32_t lift_bits) {
    if (!job || !tpl || job->edge_bits == 0u || job->edge_bits > 32u) return 0u;
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t bits = m1rsi_lace_min_bits(lift_bits ? lift_bits : 8u, job->edge_bits);
    const uint32_t step_trials = m1rsi_lace_env_u32("M1RSI_LACE_KEYED_STEP_TRIALS", 1u << 14u, 256u, 1u << 22u);
    const uint32_t close_trials = m1rsi_lace_env_u32("M1RSI_LACE_KEYED_CLOSE_TRIALS", 1u << 20u, 1024u, 1u << 25u);
    const uint32_t chain_restarts = m1rsi_lace_env_u32("M1RSI_LACE_KEYED_CHAIN_RESTARTS", 8u, 1u, 1024u);
    uint64_t edges[M1RSI_PROOFSIZE];

    const uint64_t key_mix = m1rsi_lace_key_mix(job);

    for (uint32_t restart = 0u; restart < chain_restarts; ++restart) {
        memset(edges, 0, sizeof(edges));
        const uint64_t seed = m1rsi_lace_mix64(
            0x4b4559424153494eull ^ key_mix ^
            (ordinal * 0xd6e8feb86659fd93ull) ^
            ((uint64_t)restart * 0xa0761d6478bd642full));
        edges[0] = m1rsi_lace_mix64(seed ^ 0x626173655f6c6966ull) & edge_mask;

        uint32_t ok = 1u;
        for (uint32_t j = 0u; j + 2u < M1RSI_PROOFSIZE; ++j) {
            const uint32_t side = m1rsi_lace_delta_side(j);
            uint32_t found = 0u;
            const uint64_t step_seed = m1rsi_lace_mix64(seed ^ ((uint64_t)j * 0x94d049bb133111ebull));
            for (uint32_t t = 0u; t < step_trials; ++t) {
                uint64_t candidate = m1rsi_lace_mix64(step_seed + ((uint64_t)t * 0x9e3779b97f4a7c15ull)) & edge_mask;
                if (!m1rsi_lace_edge_distinct_prefix(edges, j + 1u, candidate)) continue;
                if (!m1rsi_lace_endpoint_pair_matches_bits(job, edges[j], candidate, side, bits)) continue;
                edges[j + 1u] = candidate;
                found = 1u;
                break;
            }
            if (!found) {
                ok = 0u;
                break;
            }
        }
        if (!ok) continue;

        /*
         * Close the support by choosing e41 that simultaneously satisfies the
         * final V obligation e40->e41 and the wrap U obligation e41->e0.
         */
        uint32_t closed = 0u;
        const uint64_t close_seed = m1rsi_lace_mix64(seed ^ 0x636c6f73655f3432ull);
        for (uint32_t t = 0u; t < close_trials; ++t) {
            uint64_t candidate = m1rsi_lace_mix64(close_seed + ((uint64_t)t * 0xbf58476d1ce4e5b9ull)) & edge_mask;
            if (!m1rsi_lace_edge_distinct_prefix(edges, M1RSI_PROOFSIZE - 1u, candidate)) continue;
            if (!m1rsi_lace_endpoint_pair_matches_bits(job, edges[M1RSI_PROOFSIZE - 2u], candidate, 1u, bits)) continue;
            if (!m1rsi_lace_endpoint_pair_matches_bits(job, candidate, edges[0], 0u, bits)) continue;
            edges[M1RSI_PROOFSIZE - 1u] = candidate;
            closed = 1u;
            break;
        }
        if (!closed) continue;

        if (!m1rsi_lace_edges_are_distinct(edges)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, bits)) continue;

        for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
            tpl->offsets[i] = (edges[i] - base_start) & edge_mask;
        }
        return 1u;
    }
    return 0u;
}

static uint32_t m1rsi_lace_generate_localized_demand_template(
    const M1RsiJob *job,
    M1RsiLaceTemplate42 *tpl,
    uint64_t base_start,
    uint64_t ordinal,
    uint32_t lift_bits) {
    if (!job || !tpl || job->edge_bits == 0u || job->edge_bits > 32u) return 0u;
    const uint32_t bits = m1rsi_lace_min_bits(lift_bits ? lift_bits : 8u, job->edge_bits);
    if (!m1rsi_lace_local_demand_enabled(bits)) return 0u;

    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t restarts = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_RESTARTS", 8u, 1u, 1024u);
    const uint64_t key_mix = m1rsi_lace_key_mix(job);

    for (uint32_t restart = 0u; restart < restarts; ++restart) {
        uint64_t edges[M1RSI_PROOFSIZE];
        memset(edges, 0, sizeof(edges));
        const uint64_t seed = m1rsi_lace_mix64(
            0x4c4f43414c4c4143ull ^
            key_mix ^
            (ordinal * 0x9e3779b97f4a7c15ull) ^
            ((uint64_t)restart * 0xd6e8feb86659fd93ull));
        edges[0] = m1rsi_lace_mix64(seed ^ 0x6c6f63616c626173ull) & edge_mask;
        if (edges[0] == 0xffffffffull) edges[0] = (edges[0] + 1ull) & edge_mask;

        uint32_t current_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edges[0], 1u);
        uint32_t start_u_endpoint = m1rsi_endpoint(job->keys, job->edge_bits, edges[0], 0u);
        uint32_t ok = 1u;
        uint32_t min_demand_seen = UINT32_MAX;

        const uint32_t chain_pairs = M1RSI_PROOFSIZE - 3u;
        const uint32_t local_trials = m1rsi_lace_local_demand_trials(bits);
        const uint32_t bridge_trials = m1rsi_lace_local_demand_bridge_trials(bits);
        uint32_t chain_metal_prefix = 0u;
        uint32_t chain_bridge_close_metal = 0u;
        uint32_t fused_left_count = 0u;
        uint32_t fused_right_count = 0u;
        const uint64_t edge_period = edge_mask + 1ull;
        if (m1rsi_lace_local_demand_chain_bridge_close_metal_enabled() &&
            m1rsi_lace_local_demand_chain_metal_enabled() &&
            m1rsi_lace_local_demand_bridge_close_metal_enabled() &&
            m1rsi_lace_local_demand_metal_enabled() &&
            m1rsi_lace_local_demand_way_cap() <= M1RSI_LACE_LOCAL_DEMAND_BRIDGE_STACK_WAYS &&
            edge_period != 0ull &&
            (uint64_t)local_trials <= edge_period &&
            (uint64_t)bridge_trials <= edge_period) {
            uint32_t fused_steps = 0u;
            uint32_t fused_failed_step = 0u;
            uint32_t fused_left_overflow = 0u;
            uint32_t fused_right_overflow = 0u;
            const uint32_t metal_st = m1rsi_metal_lace_local_demand_chain_bridge_close(
                job,
                bits,
                seed,
                key_mix,
                edge_mask,
                chain_pairs,
                local_trials,
                bridge_trials,
                m1rsi_lace_local_demand_way_cap(),
                edges,
                &fused_steps,
                &fused_failed_step,
                &fused_left_count,
                &fused_left_overflow,
                &fused_right_count,
                &fused_right_overflow);
            if (metal_st == M1RSI_STATUS_OK && fused_steps == chain_pairs) {
                chain_metal_prefix = 1u;
                chain_bridge_close_metal = 1u;
                min_demand_seen = 1u;
                fprintf(stderr,
                        "m1rsi: lace_local_demand_chain_bridge_close_metal=1 bits=%u restart=%u steps=%u bridge_left=%u bridge_right=%u left_overflow=%u right_overflow=%u fused_command_buffer=1 born_endpoint_bucket=1 localized_build=1 likelihood_gated_build=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                        bits,
                        restart,
                        fused_steps,
                        fused_left_count,
                        fused_right_count,
                        fused_left_overflow,
                        fused_right_overflow);
            } else if (m1rsi_lace_local_demand_require_metal()) {
                ok = 0u;
            }
        }
        if (m1rsi_lace_local_demand_chain_metal_enabled() &&
            m1rsi_lace_local_demand_metal_enabled() &&
            !chain_bridge_close_metal &&
            ok &&
            edge_period != 0ull &&
            (uint64_t)local_trials <= edge_period) {
            uint64_t metal_edges[M1RSI_PROOFSIZE];
            memcpy(metal_edges, edges, sizeof(metal_edges));
            uint32_t metal_current_endpoint = current_endpoint;
            uint32_t metal_start_u_endpoint = start_u_endpoint;
            uint32_t metal_steps = 0u;
            uint32_t metal_failed_step = 0u;
            const uint32_t metal_st = m1rsi_metal_lace_local_demand_chain_prefix(
                job,
                bits,
                seed,
                key_mix,
                edge_mask,
                chain_pairs,
                local_trials,
                metal_edges,
                &metal_current_endpoint,
                &metal_start_u_endpoint,
                &metal_steps,
                &metal_failed_step);
            if (metal_st == M1RSI_STATUS_OK && metal_steps == chain_pairs) {
                memcpy(edges, metal_edges, sizeof(metal_edges));
                current_endpoint = metal_current_endpoint;
                start_u_endpoint = metal_start_u_endpoint;
                chain_metal_prefix = 1u;
                min_demand_seen = 1u;
                fprintf(stderr,
                        "m1rsi: lace_local_demand_chain_metal_prefix=1 bits=%u restart=%u steps=%u chain_command_buffer=1 born_endpoint_bucket=1 localized_build=1 likelihood_gated_build=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                        bits,
                        restart,
                        metal_steps);
            } else if (m1rsi_lace_local_demand_require_metal()) {
                ok = 0u;
            }
        }
        if (!chain_metal_prefix && ok) {
            for (uint32_t j = 0u; j < chain_pairs; ++j) {
                const uint32_t side = m1rsi_lace_delta_side(j);
                const uint32_t want = current_endpoint ^ 1u;
                uint64_t candidate = 0u;
                uint32_t other_endpoint = 0u;
                uint32_t seen = 0u;
                if (!m1rsi_lace_local_demand_pick(
                        job,
                        side,
                        want,
                        bits,
                        seed ^ ((uint64_t)j * 0xbf58476d1ce4e5b9ull),
                        edges,
                        j + 1u,
                        edge_mask,
                        &candidate,
                        &other_endpoint,
                        &seen)) {
                    ok = 0u;
                    break;
                }
                if (seen < min_demand_seen) min_demand_seen = seen;
                edges[j + 1u] = candidate;
                current_endpoint = other_endpoint;
            }
        }
        if (!ok) continue;

        uint64_t close_a = 0u;
        uint64_t close_b = 0u;
        uint32_t left_count = 0u;
        uint32_t right_count = 0u;
        if (chain_bridge_close_metal) {
            left_count = fused_left_count;
            right_count = fused_right_count;
        } else {
            if (!m1rsi_lace_local_demand_pick_bridge2(
                    job,
                    current_endpoint ^ 1u,
                    start_u_endpoint ^ 1u,
                    bits,
                    seed ^ 0x6272696467653255ull,
                    edges,
                    M1RSI_PROOFSIZE - 2u,
                    edge_mask,
                    &close_a,
                    &close_b,
                    &left_count,
                    &right_count)) {
                continue;
            }
            edges[M1RSI_PROOFSIZE - 2u] = close_a;
            edges[M1RSI_PROOFSIZE - 1u] = close_b;
        }
        if (!m1rsi_lace_edges_are_distinct(edges)) continue;
        if (!m1rsi_lace_residual_zero_bits(job, edges, bits)) continue;

        for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
            tpl->offsets[i] = (edges[i] - base_start) & edge_mask;
        }
        fprintf(stderr,
                "m1rsi: lace_localized_demand_template bits=%u ordinal=%llu restart=%u min_step_bucket=%u bridge_left=%u bridge_right=%u trials=%u bridge_trials=%u local_demand_threads=%u local_demand_metal_requested=%u localized_build=1 likelihood_gated_build=1 graph_materialized=0 fixed_endpoint_preimage=0\n",
                bits,
                (unsigned long long)ordinal,
                restart,
                min_demand_seen == UINT32_MAX ? 0u : min_demand_seen,
                left_count,
                right_count,
                m1rsi_lace_local_demand_trials(bits),
                m1rsi_lace_local_demand_bridge_trials(bits),
                m1rsi_lace_local_demand_thread_count(m1rsi_lace_local_demand_bridge_trials(bits)),
                m1rsi_lace_local_demand_metal_enabled());
        return 1u;
    }
    return 0u;
}

typedef struct M1RsiLaceGeneratedBankWorker {
    const M1RsiJob *job;
    const M1RsiLaceDualLowIndex *dual_idx;
    const M1RsiLaceSparseLiftIndex *sparse_idx;
    M1RsiLaceTemplate42 *slots;
    uint8_t *kinds;
    uint64_t base_start;
    uint64_t ordinal_base;
    uint32_t begin;
    uint32_t end;
    uint32_t keyed_bits;
    uint32_t dual_ready;
    uint32_t sparse_ready;
    uint32_t made;
} M1RsiLaceGeneratedBankWorker;

static void *m1rsi_lace_generated_bank_worker_main(void *raw) {
    M1RsiLaceGeneratedBankWorker *w = (M1RsiLaceGeneratedBankWorker *)raw;
    if (!w || !w->job || !w->slots || !w->kinds) return NULL;
    for (uint32_t i = w->begin; i < w->end; ++i) {
        M1RsiLaceTemplate42 tpl;
        memset(&tpl, 0, sizeof(tpl));
        const uint64_t ordinal = w->ordinal_base + (uint64_t)i;
        uint8_t kind = 0u;
        if (w->dual_ready && w->dual_idx && m1rsi_lace_generate_dual_index_template(w->job, w->dual_idx, &tpl, w->base_start, ordinal)) {
            kind = 1u;
        }
        if (kind == 0u && w->sparse_ready && w->sparse_idx &&
            m1rsi_lace_generate_sparse_lift_template(w->job, w->sparse_idx, &tpl, w->base_start, ordinal)) {
            kind = 2u;
        }
        if (kind == 0u && m1rsi_lace_generate_keyed_lift_template(w->job, &tpl, w->base_start, ordinal, w->keyed_bits)) {
            kind = 3u;
        }
        if (kind != 0u) {
            w->slots[i] = tpl;
            w->kinds[i] = kind;
            w->made += 1u;
        }
    }
    return NULL;
}

static uint32_t m1rsi_lace_generated_bank_thread_count(uint32_t keyed_cap, const M1RsiLaceSparseLiftIndex *sparse_idx, uint32_t sparse_ready) {
    uint32_t fallback = keyed_cap >= 1024u ? m1rsi_lace_host_cpu_count() : 1u;
    if (fallback > 32u) fallback = 32u;
    if (sparse_ready && sparse_idx && sparse_idx->bridge_edges >= 2u) fallback = 1u;
    return m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_BANK_THREADS", fallback, 1u, 64u);
}

static uint32_t m1rsi_lace_generate_keyed_bank_parallel(
    const M1RsiJob *job,
    const M1RsiLaceDualLowIndex *dual_idx,
    const M1RsiLaceSparseLiftIndex *sparse_idx,
    M1RsiLaceTemplate42 *out_slots,
    uint32_t keyed_cap,
    uint64_t base_start,
    uint64_t ordinal_base,
    uint32_t keyed_bits,
    uint32_t dual_ready,
    uint32_t sparse_ready,
    uint32_t threads,
    uint32_t *out_dual_made,
    uint32_t *out_sparse_made,
    uint32_t *out_chain_made) {
    if (out_dual_made) *out_dual_made = 0u;
    if (out_sparse_made) *out_sparse_made = 0u;
    if (out_chain_made) *out_chain_made = 0u;
    if (!job || !out_slots || keyed_cap == 0u || threads <= 1u) return 0u;
    if (sparse_ready && sparse_idx && sparse_idx->bridge_edges >= 2u) return 0u;
    if (threads > keyed_cap) threads = keyed_cap;
    if (threads > 64u) threads = 64u;

    uint8_t *kinds = (uint8_t *)calloc((size_t)keyed_cap, sizeof(*kinds));
    if (!kinds) return 0u;
    pthread_t tids[64];
    M1RsiLaceGeneratedBankWorker workers[64];
    memset(tids, 0, sizeof(tids));
    memset(workers, 0, sizeof(workers));

    uint32_t launched = 0u;
    uint32_t create_failed = 0u;
    for (uint32_t t = 0u; t < threads; ++t) {
        workers[t].job = job;
        workers[t].dual_idx = dual_idx;
        workers[t].sparse_idx = sparse_idx;
        workers[t].slots = out_slots;
        workers[t].kinds = kinds;
        workers[t].base_start = base_start;
        workers[t].ordinal_base = ordinal_base;
        workers[t].begin = (uint32_t)(((uint64_t)keyed_cap * (uint64_t)t) / (uint64_t)threads);
        workers[t].end = (uint32_t)(((uint64_t)keyed_cap * (uint64_t)(t + 1u)) / (uint64_t)threads);
        workers[t].keyed_bits = keyed_bits;
        workers[t].dual_ready = dual_ready;
        workers[t].sparse_ready = sparse_ready;
        if (pthread_create(&tids[t], NULL, m1rsi_lace_generated_bank_worker_main, &workers[t]) != 0) {
            create_failed = 1u;
            break;
        }
        launched += 1u;
    }
    for (uint32_t t = 0u; t < launched; ++t) pthread_join(tids[t], NULL);
    if (create_failed || launched == 0u) {
        free(kinds);
        return 0u;
    }

    uint32_t made = 0u;
    uint32_t dual_made = 0u;
    uint32_t sparse_made = 0u;
    uint32_t chain_made = 0u;
    for (uint32_t i = 0u; i < keyed_cap; ++i) {
        const uint8_t kind = kinds[i];
        if (kind == 0u) continue;
        if (made != i) out_slots[made] = out_slots[i];
        made += 1u;
        if (kind == 1u) dual_made += 1u;
        else if (kind == 2u) sparse_made += 1u;
        else if (kind == 3u) chain_made += 1u;
    }
    free(kinds);
    if (out_dual_made) *out_dual_made = dual_made;
    if (out_sparse_made) *out_sparse_made = sparse_made;
    if (out_chain_made) *out_chain_made = chain_made;
    return made;
}

static void m1rsi_lace_generate_structured_template(M1RsiLaceTemplate42 *tpl, uint32_t index) {
    const uint64_t salt = (uint64_t)(index / 8u) + 1ull;
    const uint32_t family = index % 8u;
    const uint64_t seed = m1rsi_lace_mix64(0x4c4143455f44454cull ^ ((uint64_t)index * 0x9e3779b97f4a7c15ull));
    const uint64_t anchor = m1rsi_lace_mix64(seed ^ 0xa0761d6478bd642full);
    const uint64_t stride_a = (m1rsi_lace_mix64(seed ^ 0xe7037ed1a0b428dbull) | 1ull);
    const uint64_t stride_b = (m1rsi_lace_mix64(seed ^ 0x8ebc6af09c88c6e3ull) | 1ull);
    const uint64_t delta = (m1rsi_lace_mix64(seed ^ 0x589965cc75374cc3ull) | 1ull);

    for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
        uint64_t v = 0ull;
        switch (family) {
            case 0u: /* affine corridor */
                v = anchor + (uint64_t)i * stride_a;
                break;
            case 1u: { /* paired offsets: V equality candidates stay adjacent in the template */
                const uint64_t j = (uint64_t)(i >> 1u);
                const uint64_t pair_anchor = anchor + j * stride_a + m1rsi_lace_mix64(seed ^ j);
                v = pair_anchor + (uint64_t)(i & 1u) * delta;
                break;
            }
            case 2u: { /* alternating U/V ladder */
                const uint64_t j = (uint64_t)(i >> 1u);
                v = (i & 1u) ? (anchor + j * stride_b + delta) : (anchor + j * stride_a);
                break;
            }
            case 3u: /* Gray-code low-Hamming walk */
                v = anchor + m1rsi_lace_gray64((uint64_t)i + salt * 43ull) * stride_a;
                break;
            case 4u: /* quadratic spacing to avoid pure-line collapse */
                v = anchor + (uint64_t)i * stride_a + (uint64_t)i * (uint64_t)i * stride_b;
                break;
            case 5u: { /* power-of-two perturbation family */
                const uint32_t bit = (uint32_t)((i * 7u + (uint32_t)salt) & 31u);
                v = anchor + (uint64_t)i * stride_a + (1ull << bit) + ((uint64_t)(i & 1u) * delta);
                break;
            }
            case 6u: { /* mirrored corridor around an anchor */
                const uint64_t j = (uint64_t)(i >> 1u) + 1ull;
                v = (i & 1u) ? (anchor - j * stride_b) : (anchor + j * stride_a);
                break;
            }
            default: /* mixed-offset family inside the structured generator, not a fixed-template cap */
                v = m1rsi_lace_mix64(seed + (uint64_t)i * 0x9e3779b97f4a7c15ull);
                break;
        }
        tpl->offsets[i] = v;
    }
}

static uint32_t m1rsi_lace_count_obligation_matches_bits(const M1RsiJob *job, const uint64_t edges[M1RSI_PROOFSIZE], uint32_t bits) {
    uint32_t matches = 0u;
    for (uint32_t j = 0u; j < M1RSI_BOUNDARY_RUNG_COUNT; ++j) {
        const uint32_t even = j * 2u;
        const uint32_t odd = even + 1u;
        const uint32_t next_even = (odd + 1u) % M1RSI_PROOFSIZE;
        if (m1rsi_lace_endpoint_pair_matches_bits(job, edges[even], edges[odd], 1u, bits)) matches += 1u;
        if (m1rsi_lace_endpoint_pair_matches_bits(job, edges[odd], edges[next_even], 0u, bits)) matches += 1u;
    }
    return matches;
}

typedef struct M1RsiLaceRankedTemplate {
    M1RsiLaceTemplate42 tpl;
    uint64_t score;
    uint32_t ordinal;
} M1RsiLaceRankedTemplate;

static int m1rsi_lace_ranked_cmp(const void *a, const void *b) {
    const M1RsiLaceRankedTemplate *ra = (const M1RsiLaceRankedTemplate *)a;
    const M1RsiLaceRankedTemplate *rb = (const M1RsiLaceRankedTemplate *)b;
    if (ra->score > rb->score) return -1;
    if (ra->score < rb->score) return 1;
    if (ra->ordinal < rb->ordinal) return -1;
    if (ra->ordinal > rb->ordinal) return 1;
    return 0;
}

static uint64_t m1rsi_lace_score_template_lowbits(const M1RsiJob *job, const M1RsiLaceTemplate42 *tpl, uint64_t base_start, uint64_t base_stride) {
    if (!job || !tpl || job->edge_bits == 0u || job->edge_bits > 32u) return 0ull;
    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t stage8 = m1rsi_lace_min_bits(8u, job->edge_bits);
    const uint32_t stage12 = m1rsi_lace_min_bits(12u, job->edge_bits);
    const uint32_t stage16 = m1rsi_lace_min_bits(16u, job->edge_bits);
    const uint64_t stride = base_stride ? base_stride : 1ull;
    uint64_t score = 0ull;
    uint64_t edges[M1RSI_PROOFSIZE];

    for (uint32_t sample = 0u; sample < 4u; ++sample) {
        const uint64_t jump = m1rsi_lace_mix64((uint64_t)sample + 0x51f15e5eed1234ull) & 0xfffffull;
        const uint64_t base = (base_start + ((uint64_t)sample * stride) + jump) & edge_mask;
        for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) edges[i] = (base + tpl->offsets[i]) & edge_mask;
        if (!m1rsi_lace_edges_are_distinct(edges)) continue;
        const uint64_t m8 = (uint64_t)m1rsi_lace_count_obligation_matches_bits(job, edges, stage8);
        const uint64_t m12 = (uint64_t)m1rsi_lace_count_obligation_matches_bits(job, edges, stage12);
        const uint64_t m16 = (uint64_t)m1rsi_lace_count_obligation_matches_bits(job, edges, stage16);
        score += (m8 << 32u) + (m12 << 16u) + m16;
        if (m8 == M1RSI_PROOFSIZE) score += 1ull << 48u;
        if (m12 == M1RSI_PROOFSIZE) score += 1ull << 52u;
        if (m16 == M1RSI_PROOFSIZE) score += 1ull << 56u;
    }
    return score;
}


static void m1rsi_lace_anneal_template_lowbits(const M1RsiJob *job, M1RsiLaceRankedTemplate *ranked, uint64_t base_start, uint64_t base_stride) {
    if (!job || !ranked) return;
    uint64_t best = ranked->score;
    for (uint32_t round = 0u; round < 2u; ++round) {
        for (uint32_t pos = 0u; pos < M1RSI_PROOFSIZE; ++pos) {
            const uint64_t old = ranked->tpl.offsets[pos];
            const uint64_t mutation = (m1rsi_lace_mix64(((uint64_t)ranked->ordinal << 32u) ^ ((uint64_t)round << 16u) ^ (uint64_t)pos) | 1ull);
            ranked->tpl.offsets[pos] = old + mutation;
            uint64_t candidate_score = m1rsi_lace_score_template_lowbits(job, &ranked->tpl, base_start, base_stride);
            if (candidate_score >= best) {
                best = candidate_score;
                ranked->score = candidate_score;
                continue;
            }
            ranked->tpl.offsets[pos] = old ^ (mutation & 0x00000000ffffffffull);
            candidate_score = m1rsi_lace_score_template_lowbits(job, &ranked->tpl, base_start, base_stride);
            if (candidate_score >= best) {
                best = candidate_score;
                ranked->score = candidate_score;
                continue;
            }
            ranked->tpl.offsets[pos] = old;
        }
    }
}

static int m1rsi_lace_parse_template_line(const char *line, M1RsiLaceTemplate42 *tpl) {
    const char *p = line;
    if (!p || !tpl) return 0;
    while (*p && isspace((unsigned char)*p)) ++p;
    if (!*p || *p == '#') return -1;
    for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
        while (*p && (isspace((unsigned char)*p) || *p == ',' || *p == ';')) ++p;
        if (!*p || *p == '#') return 0;
        errno = 0;
        char *end = NULL;
        unsigned long long value = strtoull(p, &end, 0);
        if (end == p || errno == ERANGE) return 0;
        tpl->offsets[i] = (uint64_t)value;
        p = end;
    }
    while (*p && (isspace((unsigned char)*p) || *p == ',' || *p == ';')) ++p;
    return (*p == '\0' || *p == '#') ? 1 : 0;
}

uint32_t m1rsi_lace_load_template_file(const char *path, M1RsiLaceTemplate42 *out_templates, uint32_t cap, uint32_t *out_count) {
    if (out_count) *out_count = 0u;
    if (!path || !*path || !out_templates || cap == 0u) return M1RSI_STATUS_BAD_ARGUMENT;
    FILE *fp = fopen(path, "r");
    if (!fp) return M1RSI_STATUS_BAD_ARGUMENT;
    char line[4096];
    uint32_t count = 0u;
    uint32_t malformed = 0u;
    while (count < cap && fgets(line, sizeof(line), fp)) {
        M1RsiLaceTemplate42 tpl;
        memset(&tpl, 0, sizeof(tpl));
        int parsed = m1rsi_lace_parse_template_line(line, &tpl);
        if (parsed < 0) continue;
        if (parsed == 0) { malformed = 1u; break; }
        out_templates[count++] = tpl;
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return malformed ? M1RSI_STATUS_BAD_ARGUMENT : M1RSI_STATUS_OK;
}

uint32_t m1rsi_lace_builtin_templates(M1RsiLaceTemplate42 *out_templates, uint32_t cap, uint32_t *out_count) {
    if (out_count) *out_count = 0u;
    if (!out_templates || cap == 0u) return M1RSI_STATUS_BAD_ARGUMENT;
    for (uint32_t t = 0u; t < cap; ++t) m1rsi_lace_generate_structured_template(&out_templates[t], t);
    if (out_count) *out_count = cap;
    return M1RSI_STATUS_OK;
}

uint32_t m1rsi_lace_build_template_bank(const M1RsiJob *job, const char *template_file, uint32_t requested_count, uint64_t base_start, uint64_t base_stride, M1RsiLaceTemplate42 *out_templates, uint32_t *out_count) {
    if (out_count) *out_count = 0u;
    if (!out_templates) return M1RSI_STATUS_BAD_ARGUMENT;
    uint32_t requested = requested_count ? requested_count : M1RSI_LACE_TEMPLATE_DEFAULT;
    if (requested > M1RSI_LACE_TEMPLATE_MAX) requested = M1RSI_LACE_TEMPLATE_MAX;

    uint32_t loaded = 0u;
    if (template_file && *template_file) {
        uint32_t st = m1rsi_lace_load_template_file(template_file, out_templates, requested, &loaded);
        if (st != M1RSI_STATUS_OK) return st;
        if (loaded >= requested) {
            if (out_count) *out_count = requested;
            return M1RSI_STATUS_OK;
        }
    }

    uint32_t remaining = requested - loaded;
    if (job && remaining != 0u) {
        const uint32_t keyed_enabled = m1rsi_lace_env_u32("M1RSI_LACE_KEYED_BANK", 1u, 0u, 1u);
        if (keyed_enabled) {
            const uint32_t keyed_bits = m1rsi_lace_env_u32("M1RSI_LACE_KEYED_LIFT_BITS", 16u, 1u, job->edge_bits < 32u ? job->edge_bits : 32u);
            uint32_t keyed_cap = m1rsi_lace_env_u32("M1RSI_LACE_KEYED_TEMPLATE_CAP", remaining, 1u, remaining);
            const uint32_t require_keyed_lift = m1rsi_lace_env_u32("M1RSI_LACE_REQUIRE_KEYED_LIFT", keyed_bits > 24u ? 1u : 0u, 0u, 1u);
            uint32_t made = 0u;
            uint32_t localized_made = 0u;
            uint32_t dual_made = 0u;
            uint32_t sparse_made = 0u;
            uint32_t chain_made = 0u;
            uint32_t fallback8_made = 0u;
            M1RsiLaceDualLowIndex dual_idx;
            memset(&dual_idx, 0, sizeof(dual_idx));
            M1RsiLaceSparseLiftIndex sparse_idx;
            memset(&sparse_idx, 0, sizeof(sparse_idx));
            M1RsiLaceSparseLiftIndex *sparse_idx_ptr = &sparse_idx;
            uint32_t dual_ready = 0u;
            uint32_t sparse_ready = 0u;
            uint32_t sparse_cache_used = 0u;
            uint32_t sparse_cache_hit = 0u;
            uint32_t sparse_template_threads = 0u;
            uint32_t sparse_bank_threads = 1u;
            uint32_t sparse_pick_bits = 0u;
            uint32_t sparse_return_bits = 0u;
            uint32_t sparse_beam = 0u;
            uint32_t sparse_high_bits = 0u;
            uint32_t sparse_high_made = 0u;
            uint32_t sparse_high_cache_used = 0u;
            uint32_t sparse_high_cache_hit = 0u;
            uint32_t sparse_high_template_threads = 0u;
            uint32_t sparse_high_pick_bits = 0u;
            uint32_t sparse_high_return_bits = 0u;
            uint64_t sparse_high_scan = 0ull;
            const uint32_t local_demand_enabled = m1rsi_lace_local_demand_enabled(keyed_bits);
            const uint32_t local_high_bits_raw = job->edge_bits == 0u ? 0u : m1rsi_lace_env_u32(
                "M1RSI_LACE_LOCAL_DEMAND_HIGH_BITS",
                0u,
                0u,
                job->edge_bits < 32u ? job->edge_bits : 32u);
            const uint32_t local_high_bits = local_high_bits_raw ? m1rsi_lace_min_bits(local_high_bits_raw, job->edge_bits) : 0u;
            const uint32_t sparse_high_bits_raw = job->edge_bits == 0u ? 0u : m1rsi_lace_env_u32(
                "M1RSI_LACE_SPARSE_HIGH_BITS",
                0u,
                0u,
                job->edge_bits < 32u ? job->edge_bits : 32u);
            sparse_high_bits = sparse_high_bits_raw ? m1rsi_lace_min_bits(sparse_high_bits_raw, job->edge_bits) : 0u;
            uint32_t localized_cache_hit = 0u;
            uint32_t localized_cache_templates = 0u;
            uint32_t localized_high_cache_hit = 0u;
            uint32_t localized_high_cache_templates = 0u;
            uint32_t localized_high_made = 0u;
            if (local_high_bits > keyed_bits && m1rsi_lace_local_demand_enabled(local_high_bits) && loaded < requested) {
                const uint32_t high_segment_start = loaded;
                const uint32_t high_remaining = requested - loaded;
                const uint32_t high_target = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_HIGH_TEMPLATE_CAP", 1u, 1u, high_remaining);
                localized_high_cache_templates = m1rsi_lace_local_template_cache_lookup(
                    job,
                    local_high_bits,
                    base_start,
                    job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull),
                    &out_templates[loaded],
                    high_target);
                if (localized_high_cache_templates != 0u) {
                    loaded += localized_high_cache_templates;
                    made += localized_high_cache_templates;
                    localized_made += localized_high_cache_templates;
                    localized_high_made += localized_high_cache_templates;
                    localized_high_cache_hit = 1u;
                }
                const uint32_t high_ordinal_base = high_segment_start;
                for (uint32_t i = localized_high_made; i < high_target && loaded < requested; ++i) {
                    M1RsiLaceTemplate42 tpl;
                    memset(&tpl, 0, sizeof(tpl));
                    const uint64_t ordinal = 0x4849474800000000ull + (uint64_t)high_ordinal_base + (uint64_t)i;
                    if (!m1rsi_lace_generate_localized_demand_template(job, &tpl, base_start, ordinal, local_high_bits)) continue;
                    out_templates[loaded++] = tpl;
                    made += 1u;
                    localized_made += 1u;
                    localized_high_made += 1u;
                }
                if (loaded > high_segment_start) {
                    m1rsi_lace_local_template_cache_store(
                        job,
                        local_high_bits,
                        base_start,
                        job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull),
                        &out_templates[high_segment_start],
                        loaded - high_segment_start);
                }
            }
            if (sparse_high_bits > keyed_bits && sparse_high_bits <= job->edge_bits && loaded < requested) {
                const uint32_t high_remaining = requested - loaded;
                const uint32_t high_target = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_TEMPLATE_CAP", 1u, 1u, high_remaining);
                const uint32_t high_segment_start = loaded;
                M1RsiLaceSparseLiftIndex high_idx;
                memset(&high_idx, 0, sizeof(high_idx));
                M1RsiLaceSparseLiftIndex *high_idx_ptr = &high_idx;
                M1RsiLaceSparseConfigOverride saved_override = g_lace_sparse_config_override;
                M1RsiLaceSparseConfigOverride high_override = m1rsi_lace_sparse_high_config(job, sparse_high_bits);
                g_lace_sparse_config_override = high_override;
                sparse_high_cache_used = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_HIGH_LIFT_REUSE", 1u, 0u, 1u);
                uint32_t high_idx_status = sparse_high_cache_used
                    ? m1rsi_lace_sparse_lift_cache_get(job, sparse_high_bits, &high_idx_ptr, &sparse_high_cache_hit)
                    : m1rsi_lace_build_sparse_lift_index(job, sparse_high_bits, &high_idx);
                if (high_idx_status == M1RSI_STATUS_OK && high_idx_ptr) {
                    sparse_high_template_threads = m1rsi_lace_sparse_template_thread_count(high_idx_ptr);
                    sparse_high_pick_bits = m1rsi_lace_sparse_pick_bits(job, high_idx_ptr);
                    sparse_high_return_bits = m1rsi_lace_sparse_return_bits(job, high_idx_ptr);
                    sparse_high_scan = high_idx_ptr->scan_count;
                    for (uint32_t i = 0u; i < high_target && loaded < requested; ++i) {
                        M1RsiLaceTemplate42 tpl;
                        memset(&tpl, 0, sizeof(tpl));
                        const uint64_t ordinal = 0x5350484900000000ull + (uint64_t)high_segment_start + (uint64_t)i;
                        if (!m1rsi_lace_generate_sparse_lift_template(job, high_idx_ptr, &tpl, base_start, ordinal)) continue;
                        out_templates[loaded++] = tpl;
                        made += 1u;
                        sparse_made += 1u;
                        sparse_high_made += 1u;
                    }
                }
                g_lace_sparse_config_override = saved_override;
                if (!sparse_high_cache_used) m1rsi_lace_sparse_lift_index_free(&high_idx);
            }
            const uint32_t localized_segment_start = loaded;
            if (local_demand_enabled && loaded < requested) {
                localized_cache_templates = m1rsi_lace_local_template_cache_lookup(
                    job,
                    keyed_bits,
                    base_start,
                    job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull),
                    &out_templates[loaded],
                    requested - loaded);
                if (localized_cache_templates != 0u) {
                    loaded += localized_cache_templates;
                    made += localized_cache_templates;
                    localized_made += localized_cache_templates;
                    localized_cache_hit = 1u;
                }
            }
            if (local_demand_enabled && loaded < requested) {
                const uint32_t local_cap = m1rsi_lace_env_u32("M1RSI_LACE_LOCAL_DEMAND_TEMPLATE_CAP", keyed_cap, 1u, keyed_cap);
                const uint32_t local_generated_ordinal_base = loaded;
                for (uint32_t i = 0u; i < local_cap && loaded < requested; ++i) {
                    M1RsiLaceTemplate42 tpl;
                    memset(&tpl, 0, sizeof(tpl));
                    const uint64_t ordinal = (uint64_t)local_generated_ordinal_base + (uint64_t)i;
                    if (!m1rsi_lace_generate_localized_demand_template(job, &tpl, base_start, ordinal, keyed_bits)) continue;
                    out_templates[loaded++] = tpl;
                    made += 1u;
                    localized_made += 1u;
                }
            }
            if (localized_made != 0u && loaded > localized_segment_start) {
                m1rsi_lace_local_template_cache_store(
                    job,
                    keyed_bits,
                    base_start,
                    job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull),
                    &out_templates[localized_segment_start],
                    loaded - localized_segment_start);
            }
            if (loaded < requested && keyed_bits > 8u && keyed_bits <= 12u) {
                uint32_t idx_status = m1rsi_lace_build_dual_low_index(job, keyed_bits, &dual_idx);
                dual_ready = idx_status == M1RSI_STATUS_OK ? 1u : 0u;
            } else if (loaded < requested && keyed_bits > 12u && keyed_bits <= 32u) {
                sparse_cache_used = m1rsi_lace_env_u32("M1RSI_LACE_SPARSE_LIFT_REUSE", 1u, 0u, 1u);
                uint32_t idx_status = sparse_cache_used
                    ? m1rsi_lace_sparse_lift_cache_get(job, keyed_bits, &sparse_idx_ptr, &sparse_cache_hit)
                    : m1rsi_lace_build_sparse_lift_index(job, keyed_bits, &sparse_idx);
                sparse_ready = idx_status == M1RSI_STATUS_OK ? 1u : 0u;
                if (sparse_ready) {
                    sparse_template_threads = m1rsi_lace_sparse_template_thread_count(sparse_idx_ptr);
                    sparse_pick_bits = m1rsi_lace_sparse_pick_bits(job, sparse_idx_ptr);
                    sparse_return_bits = m1rsi_lace_sparse_return_bits(job, sparse_idx_ptr);
                    sparse_beam = m1rsi_lace_sparse_template_beam_width(sparse_idx_ptr);
                }
            }
            const uint32_t generated_ordinal_base = loaded;
            const uint32_t generated_remaining = requested - loaded;
            const uint32_t generated_cap = keyed_cap < generated_remaining ? keyed_cap : generated_remaining;
            sparse_bank_threads = m1rsi_lace_generated_bank_thread_count(generated_cap, sparse_idx_ptr, sparse_ready);
            uint32_t serial_begin = 0u;
            if (sparse_bank_threads > 1u && generated_cap >= 2u && loaded < requested) {
                uint32_t parallel_dual_made = 0u;
                uint32_t parallel_sparse_made = 0u;
                uint32_t parallel_chain_made = 0u;
                uint32_t parallel_made = m1rsi_lace_generate_keyed_bank_parallel(
                    job,
                    &dual_idx,
                    sparse_idx_ptr,
                    &out_templates[loaded],
                    generated_cap,
                    base_start,
                    (uint64_t)generated_ordinal_base,
                    keyed_bits,
                    dual_ready,
                    sparse_ready,
                    sparse_bank_threads,
                    &parallel_dual_made,
                    &parallel_sparse_made,
                    &parallel_chain_made);
                if (parallel_made != 0u) {
                    loaded += parallel_made;
                    made += parallel_made;
                    dual_made += parallel_dual_made;
                    sparse_made += parallel_sparse_made;
                    chain_made += parallel_chain_made;
                    serial_begin = generated_cap;
                }
            }
            for (uint32_t i = serial_begin; i < generated_cap && loaded < requested; ++i) {
                M1RsiLaceTemplate42 tpl;
                memset(&tpl, 0, sizeof(tpl));
                const uint64_t ordinal = (uint64_t)generated_ordinal_base + (uint64_t)i;
                uint32_t generated = 0u;
                if (dual_ready) {
                    generated = m1rsi_lace_generate_dual_index_template(job, &dual_idx, &tpl, base_start, ordinal);
                    if (generated) dual_made += 1u;
                }
                if (!generated && sparse_ready) {
                    generated = m1rsi_lace_generate_sparse_lift_template(job, sparse_idx_ptr, &tpl, base_start, ordinal);
                    if (generated) sparse_made += 1u;
                }
                if (!generated) {
                    generated = m1rsi_lace_generate_keyed_lift_template(job, &tpl, base_start, ordinal, keyed_bits);
                    if (generated) chain_made += 1u;
                }
                if (!generated) continue;
                out_templates[loaded++] = tpl;
                made += 1u;
            }
            /*
             * If the requested low-bit lift is too aggressive for the available
             * trial budget, fail back to a guaranteed stage-8 born-support pass
             * before using blind structured templates. This keeps the generated
             * bank inside the differential-lift lane instead of returning to the
             * old all-random residual8-dead bank.
            */
            if (!require_keyed_lift && made == 0u && keyed_bits > 8u && loaded < requested) {
                const uint32_t fallback_ordinal_base = loaded;
                for (uint32_t i = 0u; i < keyed_cap && loaded < requested; ++i) {
                    M1RsiLaceTemplate42 tpl;
                    memset(&tpl, 0, sizeof(tpl));
                    const uint64_t ordinal = (uint64_t)fallback_ordinal_base + (uint64_t)i + 0x80000000ull;
                    if (!m1rsi_lace_generate_keyed_lift_template(job, &tpl, base_start, ordinal, 8u)) continue;
                    out_templates[loaded++] = tpl;
                    made += 1u;
                    fallback8_made += 1u;
                }
            }
            fprintf(stderr,
                    "m1rsi: lace_key_basin_bank requested=%u loaded_file_templates=%u keyed_templates=%u keyed_bits=%u require_keyed_lift=%u localized_demand_enabled=%u localized_high_bits=%u localized_high_templates=%u localized_high_cache_hit=%u localized_high_cache_templates=%u sparse_high_bits=%u sparse_high_templates=%u sparse_high_cache_used=%u sparse_high_cache_hit=%u sparse_high_template_threads=%u sparse_high_pick_bits=%u sparse_high_return_bits=%u sparse_high_scan=%llu localized_template_cache_hit=%u localized_template_cache_templates=%u dual_index_used=%u sparse_lift_used=%u sparse_cache_used=%u sparse_cache_hit=%u sparse_template_threads=%u sparse_bank_threads=%u sparse_pick_bits=%u sparse_return_bits=%u sparse_beam=%u localized_templates=%u dual_templates=%u sparse_templates=%u chain_templates=%u fallback8_templates=%u generated_fallback_remaining=%u localized_build=%u likelihood_gated_build=%u reusable_support_bank=%u graph_materialized=0 fixed_endpoint_preimage=0\n",
                    requested,
                    loaded - made,
                    made,
                    keyed_bits,
                    require_keyed_lift,
                    local_demand_enabled,
                    local_high_bits,
                    localized_high_made,
                    localized_high_cache_hit,
                    localized_high_cache_templates,
                    sparse_high_bits,
                    sparse_high_made,
                    sparse_high_cache_used,
                    sparse_high_cache_hit,
                    sparse_high_template_threads,
                    sparse_high_pick_bits,
                    sparse_high_return_bits,
                    (unsigned long long)sparse_high_scan,
                    localized_cache_hit,
                    localized_cache_templates,
                    dual_ready,
                    sparse_ready,
                    sparse_cache_used,
                    sparse_cache_hit,
                    sparse_template_threads,
                    sparse_bank_threads,
                    sparse_pick_bits,
                    sparse_return_bits,
                    sparse_beam,
                    localized_made,
                    dual_made,
                    sparse_made,
                    chain_made,
                    fallback8_made,
                    requested - loaded,
                    localized_made != 0u ? 1u : 0u,
                    localized_made != 0u ? 1u : 0u,
                    localized_made != 0u ? 1u : 0u);
            m1rsi_lace_dual_index_free(&dual_idx);
            if (!sparse_cache_used) m1rsi_lace_sparse_lift_index_free(&sparse_idx);
            if (require_keyed_lift && loaded < requested) {
                if (out_count) *out_count = loaded;
                return loaded ? M1RSI_STATUS_OK : M1RSI_STATUS_NO_CYCLE;
            }
        }
    }

    remaining = requested - loaded;
    if (remaining == 0u) {
        if (out_count) *out_count = requested;
        return M1RSI_STATUS_OK;
    }

    uint32_t pool_count = remaining * 4u;
    if (pool_count < remaining || pool_count > M1RSI_LACE_TEMPLATE_MAX) pool_count = M1RSI_LACE_TEMPLATE_MAX;
    if (pool_count < remaining) pool_count = remaining;
    M1RsiLaceRankedTemplate *ranked = (M1RsiLaceRankedTemplate *)calloc(pool_count, sizeof(*ranked));
    if (!ranked) return M1RSI_STATUS_INTERNAL;

    for (uint32_t i = 0u; i < pool_count; ++i) {
        const uint32_t ordinal = loaded + i;
        m1rsi_lace_generate_structured_template(&ranked[i].tpl, ordinal);
        ranked[i].ordinal = ordinal;
        ranked[i].score = job ? m1rsi_lace_score_template_lowbits(job, &ranked[i].tpl, base_start, base_stride) : (UINT64_MAX - (uint64_t)ordinal);
    }
    qsort(ranked, pool_count, sizeof(*ranked), m1rsi_lace_ranked_cmp);
    if (job) {
        uint32_t refine_count = remaining < 64u ? remaining : 64u;
        if (refine_count > pool_count) refine_count = pool_count;
        for (uint32_t i = 0u; i < refine_count; ++i) m1rsi_lace_anneal_template_lowbits(job, &ranked[i], base_start, base_stride);
        qsort(ranked, pool_count, sizeof(*ranked), m1rsi_lace_ranked_cmp);
    }
    for (uint32_t i = 0u; i < remaining; ++i) out_templates[loaded + i] = ranked[i].tpl;
    free(ranked);
    if (out_count) *out_count = requested;
    return M1RSI_STATUS_OK;
}

uint32_t m1rsi_lace_mine42(const M1RsiJob *job, const M1RsiLaceTemplate42 *templates, uint32_t template_count, uint64_t base_start, uint64_t base_count, uint64_t base_stride, M1RsiProof42 *out_proof, M1RsiReceipt *receipt, M1RsiLaceStats *stats) {
    if (stats) memset(stats, 0, sizeof(*stats));
    if (receipt) memset(receipt, 0, sizeof(*receipt));
    if (out_proof) memset(out_proof, 0, sizeof(*out_proof));
    if (!job || !templates || template_count == 0u || base_count == 0u || base_stride == 0u || !out_proof) {
        if (stats) stats->status = M1RSI_STATUS_BAD_ARGUMENT;
        if (receipt) receipt->status = M1RSI_STATUS_BAD_ARGUMENT;
        return M1RSI_STATUS_BAD_ARGUMENT;
    }
    if (job->proof_size != M1RSI_PROOFSIZE) {
        if (stats) { stats->status = M1RSI_STATUS_BAD_PROOF_SIZE; stats->edge_bits = job->edge_bits; }
        if (receipt) receipt->status = M1RSI_STATUS_BAD_PROOF_SIZE;
        return M1RSI_STATUS_BAD_PROOF_SIZE;
    }
    if (job->edge_bits == 0u || job->edge_bits > 32u) {
        if (stats) { stats->status = M1RSI_STATUS_BAD_EDGE_BITS; stats->edge_bits = job->edge_bits; }
        if (receipt) receipt->status = M1RSI_STATUS_BAD_EDGE_BITS;
        return M1RSI_STATUS_BAD_EDGE_BITS;
    }

    const uint64_t edge_mask = job->edge_bits == 32u ? 0xffffffffull : ((1ull << job->edge_bits) - 1ull);
    const uint32_t stage8 = m1rsi_lace_min_bits(8u, job->edge_bits);
    const uint32_t stage12 = m1rsi_lace_min_bits(12u, job->edge_bits);
    const uint32_t stage16 = m1rsi_lace_min_bits(16u, job->edge_bits);
    const uint32_t stage20 = m1rsi_lace_min_bits(20u, job->edge_bits);
    const uint32_t stage24 = m1rsi_lace_min_bits(24u, job->edge_bits);
    const uint32_t full_bits = job->edge_bits;
    if (stats) {
        stats->edge_bits = job->edge_bits;
        stats->stage8_bits = stage8;
        stats->stage12_bits = stage12;
        stats->stage16_bits = stage16;
        stats->stage20_bits = stage20;
        stats->stage24_bits = stage24;
        stats->full_bits = full_bits;
        stats->found_template = UINT64_MAX;
        stats->found_base = UINT64_MAX;
    }

    uint64_t edges[M1RSI_PROOFSIZE];
    M1RsiProof42 proof;
    M1RsiReceipt local_receipt;
    for (uint32_t ti = 0u; ti < template_count; ++ti) {
        if (stats) stats->templates_tested += 1u;
        uint64_t base = base_start & edge_mask;
        for (uint64_t bi = 0u; bi < base_count; ++bi) {
            if (stats) { stats->bases_tested += 1u; stats->candidates_tested += 1u; }
            for (uint32_t i = 0u; i < M1RSI_PROOFSIZE; ++i) {
                edges[i] = (base + templates[ti].offsets[i]) & edge_mask;
            }
            if (!m1rsi_lace_edges_are_distinct(edges)) {
                if (stats) stats->duplicate_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (!m1rsi_lace_residual_zero_bits(job, edges, stage8)) {
                if (stats) stats->residual8_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (stats) stats->residual8_passes += 1u;
            if (!m1rsi_lace_residual_zero_bits(job, edges, stage12)) {
                if (stats) stats->residual12_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (stats) stats->residual12_passes += 1u;
            if (!m1rsi_lace_residual_zero_bits(job, edges, stage16)) {
                if (stats) stats->residual16_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (stats) stats->residual16_passes += 1u;
            if (!m1rsi_lace_residual_zero_bits(job, edges, stage20)) {
                if (stats) stats->residual20_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (stats) stats->residual20_passes += 1u;
            if (!m1rsi_lace_residual_zero_bits(job, edges, stage24)) {
                if (stats) stats->residual24_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (stats) stats->residual24_passes += 1u;
            if (!m1rsi_lace_residual_zero_bits(job, edges, full_bits)) {
                if (stats) stats->full_residual_rejects += 1u;
                base = (base + base_stride) & edge_mask;
                continue;
            }
            if (stats) {
                stats->full_residual_zero += 1u;
                stats->candidate_cycles += 1u;
                stats->exact_verify_calls += 1u;
            }
            m1rsi_lace_make_candidate_proof(edges, &proof);
            uint32_t st = m1rsi_verify42_scaffold_cycle(job, &proof, &local_receipt);
            if (st == M1RSI_STATUS_OK && local_receipt.exact_cycle_ok == 1u) {
                *out_proof = proof;
                if (receipt) *receipt = local_receipt;
                if (stats) {
                    stats->status = M1RSI_STATUS_OK;
                    stats->found_template = ti;
                    stats->found_base = base;
                }
                return M1RSI_STATUS_OK;
            }
            base = (base + base_stride) & edge_mask;
        }
    }
    if (receipt) {
        receipt->status = M1RSI_STATUS_NO_CYCLE;
        receipt->edge_bits = job->edge_bits;
        receipt->proof_size = job->proof_size;
    }
    if (stats) stats->status = M1RSI_STATUS_NO_CYCLE;
    return M1RSI_STATUS_NO_CYCLE;
}

uint32_t m1rsi_build_submit_packet(const M1RsiJob *job, const M1RsiProof42 *proof, uint32_t target_ok, uint32_t same_job_ok, M1RsiSubmitPacket *packet, M1RsiReceipt *receipt) {
    if (!job || !proof || !packet) return M1RSI_STATUS_BAD_ARGUMENT;
    memset(packet, 0, sizeof(*packet));
    uint32_t st = m1rsi_verify42_scaffold_cycle(job, proof, receipt);
    packet->status = st;
    if (st != M1RSI_STATUS_OK) return st;
    if (!target_ok) { packet->status = M1RSI_STATUS_TARGET_FAILED; if (receipt) receipt->status = packet->status; return packet->status; }
    if (!same_job_ok) { packet->status = M1RSI_STATUS_STALE_JOB; if (receipt) receipt->status = packet->status; return packet->status; }
    packet->ready = 1u;
    packet->status = M1RSI_STATUS_OK;
    packet->exact_cycle_ok = 1u;
    packet->target_ok = 1u;
    packet->same_job_ok = 1u;
    packet->edge_bits = job->edge_bits;
    packet->proof_size = job->proof_size;
    packet->scaffold_coordinate_submitted = 0u;
    packet->height = job->height;
    packet->job_id = job->job_id;
    packet->stratum_nonce = job->stratum_nonce;
    memcpy(packet->nonces, proof->nonces, sizeof(packet->nonces));
    if (receipt) receipt->stratum_shape_ok = 1u;
    return M1RSI_STATUS_OK;
}

size_t m1rsi_format_stratum_submit_json(const M1RsiSubmitPacket *packet, const char *request_id, char *out, size_t cap) {
    if (!packet || !request_id) return 0u;
    size_t used = 0u;
#define APPEND_FMT(...) do { \
    int n_ = snprintf((out && used < cap) ? out + used : NULL, (out && used < cap) ? cap - used : 0u, __VA_ARGS__); \
    if (n_ < 0) return 0u; \
    used += (size_t)n_; \
} while (0)
    APPEND_FMT("{\"id\":\"%s\",\"jsonrpc\":\"2.0\",\"method\":\"submit\",\"params\":{", request_id);
    APPEND_FMT("\"edge_bits\":%u,\"height\":%llu,\"job_id\":%llu,\"nonce\":%llu,\"pow\":[",
               packet->edge_bits,
               (unsigned long long)packet->height,
               (unsigned long long)packet->job_id,
               (unsigned long long)packet->stratum_nonce);
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        APPEND_FMT("%s%llu", i ? "," : "", (unsigned long long)packet->nonces[i]);
    }
    APPEND_FMT("]}}\n");
#undef APPEND_FMT
    if (out && cap) out[(used < cap) ? used : cap - 1u] = '\0';
    return used;
}

/* ---- Grin parity helpers: BLAKE2b-256, pre_pow+nonce key derivation, proof hash/difficulty. ---- */

typedef struct M1RsiBlake2bState {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[128];
    size_t buflen;
    size_t outlen;
} M1RsiBlake2bState;

static const uint64_t m1rsi_blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t m1rsi_blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

static uint64_t m1rsi_load64_le(const uint8_t *p) {
    uint64_t x = 0;
    for (unsigned i = 0; i < 8; ++i) x |= ((uint64_t)p[i]) << (8u * i);
    return x;
}

static uint64_t m1rsi_load64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56u) | ((uint64_t)p[1] << 48u) | ((uint64_t)p[2] << 40u) | ((uint64_t)p[3] << 32u) |
           ((uint64_t)p[4] << 24u) | ((uint64_t)p[5] << 16u) | ((uint64_t)p[6] << 8u) | (uint64_t)p[7];
}

static void m1rsi_store64_le(uint8_t *p, uint64_t x) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(x >> (8u * i));
}

#define B2B_ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define B2B_G(r,i,a,b,c,d) do { \
    a = a + b + m[m1rsi_blake2b_sigma[r][2*i+0]]; \
    d = B2B_ROTR64(d ^ a, 32); \
    c = c + d; \
    b = B2B_ROTR64(b ^ c, 24); \
    a = a + b + m[m1rsi_blake2b_sigma[r][2*i+1]]; \
    d = B2B_ROTR64(d ^ a, 16); \
    c = c + d; \
    b = B2B_ROTR64(b ^ c, 63); \
} while (0)

static void m1rsi_blake2b_compress(M1RsiBlake2bState *S, const uint8_t block[128]) {
    uint64_t m[16];
    uint64_t v[16];
    for (unsigned i = 0; i < 16; ++i) m[i] = m1rsi_load64_le(block + i * 8u);
    for (unsigned i = 0; i < 8; ++i) v[i] = S->h[i];
    for (unsigned i = 0; i < 8; ++i) v[i + 8] = m1rsi_blake2b_iv[i];
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    v[14] ^= S->f[0];
    v[15] ^= S->f[1];
    for (unsigned r = 0; r < 12; ++r) {
        B2B_G(r,0,v[0],v[4],v[8],v[12]);
        B2B_G(r,1,v[1],v[5],v[9],v[13]);
        B2B_G(r,2,v[2],v[6],v[10],v[14]);
        B2B_G(r,3,v[3],v[7],v[11],v[15]);
        B2B_G(r,4,v[0],v[5],v[10],v[15]);
        B2B_G(r,5,v[1],v[6],v[11],v[12]);
        B2B_G(r,6,v[2],v[7],v[8],v[13]);
        B2B_G(r,7,v[3],v[4],v[9],v[14]);
    }
    for (unsigned i = 0; i < 8; ++i) S->h[i] ^= v[i] ^ v[i + 8];
}
#undef B2B_G
#undef B2B_ROTR64

static void m1rsi_blake2b_init(M1RsiBlake2bState *S, size_t outlen) {
    memset(S, 0, sizeof(*S));
    for (unsigned i = 0; i < 8; ++i) S->h[i] = m1rsi_blake2b_iv[i];
    S->h[0] ^= 0x01010000u ^ (uint32_t)outlen;
    S->outlen = outlen;
}

static void m1rsi_blake2b_increment(M1RsiBlake2bState *S, uint64_t inc) {
    S->t[0] += inc;
    if (S->t[0] < inc) S->t[1]++;
}

static void m1rsi_blake2b_update(M1RsiBlake2bState *S, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = 128u - left;
        if (inlen > fill) {
            memcpy(S->buf + left, in, fill);
            S->buflen = 0;
            m1rsi_blake2b_increment(S, 128u);
            m1rsi_blake2b_compress(S, S->buf);
            in += fill;
            inlen -= fill;
        } else {
            memcpy(S->buf + left, in, inlen);
            S->buflen = left + inlen;
            return;
        }
    }
}

static void m1rsi_blake2b_final(M1RsiBlake2bState *S, uint8_t *out) {
    uint8_t buffer[64];
    m1rsi_blake2b_increment(S, (uint64_t)S->buflen);
    S->f[0] = ~0ULL;
    memset(S->buf + S->buflen, 0, 128u - S->buflen);
    m1rsi_blake2b_compress(S, S->buf);
    for (unsigned i = 0; i < 8; ++i) m1rsi_store64_le(buffer + i * 8u, S->h[i]);
    memcpy(out, buffer, S->outlen);
}

static void m1rsi_blake2b_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    M1RsiBlake2bState S;
    m1rsi_blake2b_init(&S, 32u);
    m1rsi_blake2b_update(&S, in, inlen);
    m1rsi_blake2b_final(&S, out);
}

uint32_t m1rsi_hex_to_bytes(const char *hex, uint8_t *out, size_t cap, size_t *out_len) {
    if (!hex || !out || !out_len) return M1RSI_STATUS_BAD_ARGUMENT;
    size_t n = strlen(hex);
    if ((n & 1u) != 0u || n / 2u > cap) return M1RSI_STATUS_OVERFLOW;
    for (size_t i = 0; i < n / 2u; ++i) {
        int v = 0;
        for (int k = 0; k < 2; ++k) {
            char c = hex[2u*i + (size_t)k];
            int d = (c >= '0' && c <= '9') ? c - '0' :
                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (d < 0) return M1RSI_STATUS_BAD_ARGUMENT;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    *out_len = n / 2u;
    return M1RSI_STATUS_OK;
}

uint32_t m1rsi_grin_keys_from_pre_pow_nonce(const uint8_t *pre_pow, size_t pre_pow_len, uint64_t nonce, M1RsiKeys *out_keys) {
    if (!pre_pow || pre_pow_len == 0u || !out_keys) return M1RSI_STATUS_BAD_ARGUMENT;
    uint8_t local[M1RSI_HEX_HEADER_MAX_BYTES + 8u];
    if (pre_pow_len > M1RSI_HEX_HEADER_MAX_BYTES) return M1RSI_STATUS_OVERFLOW;
    memcpy(local, pre_pow, pre_pow_len);
    /* Grin Stratum pre_pow excludes the nonce. BlockHeader::pre_pow() and
     * from_pre_pow_and_proof serialize the PoW nonce as big-endian u64 after
     * pre_pow, then BLAKE2b-256 derives the four SipHash keys. */
    for (uint32_t i = 0u; i < 8u; ++i) local[pre_pow_len + i] = (uint8_t)(nonce >> (56u - 8u * i));
    uint8_t digest[32];
    m1rsi_blake2b_256(local, pre_pow_len + 8u, digest);
    out_keys->k0 = m1rsi_load64_le(digest + 0u);
    out_keys->k1 = m1rsi_load64_le(digest + 8u);
    out_keys->k2 = m1rsi_load64_le(digest + 16u);
    out_keys->k3 = m1rsi_load64_le(digest + 24u);
    return M1RSI_STATUS_OK;
}

uint32_t m1rsi_grin_keys_from_hex_pre_pow_nonce(const char *pre_pow_hex, uint64_t nonce, M1RsiKeys *out_keys) {
    uint8_t bytes[M1RSI_HEX_HEADER_MAX_BYTES];
    size_t len = 0;
    uint32_t st = m1rsi_hex_to_bytes(pre_pow_hex, bytes, sizeof(bytes), &len);
    if (st != M1RSI_STATUS_OK) return st;
    return m1rsi_grin_keys_from_pre_pow_nonce(bytes, len, nonce, out_keys);
}

uint64_t m1rsi_graph_weight(uint64_t height, uint32_t edge_bits) {
    const uint64_t YEAR_HEIGHT = 524160ull;
    const uint64_t WEEK_HEIGHT = 10080ull;
    const uint32_t BASE_EDGE_BITS = 24u;
    uint64_t x = edge_bits;
    if (edge_bits == 31u && height >= YEAR_HEIGHT) {
        uint64_t dec = 1ull + (height - YEAR_HEIGHT) / WEEK_HEIGHT;
        x = x > dec ? x - dec : 0ull;
    }
    if (edge_bits < BASE_EDGE_BITS) return 0ull;
    return (2ull << (edge_bits - BASE_EDGE_BITS)) * x;
}

uint32_t m1rsi_proof_hash32(const M1RsiProof42 *proof, uint32_t edge_bits, uint8_t out32[32]) {
    if (!proof || !out32 || edge_bits == 0u || edge_bits > 63u) return M1RSI_STATUS_BAD_ARGUMENT;
    const size_t bits = (size_t)edge_bits * M1RSI_PROOFSIZE;
    const size_t bytes = (bits + 7u) / 8u;
    uint8_t packed[512];
    if (bytes > sizeof(packed)) return M1RSI_STATUS_OVERFLOW;
    memset(packed, 0, bytes);
    for (uint32_t i = 0; i < M1RSI_PROOFSIZE; ++i) {
        uint64_t val = proof->nonces[i];
        size_t start = (size_t)i * edge_bits;
        for (uint32_t b = 0; b < edge_bits; ++b) {
            if ((val >> b) & 1ull) {
                size_t pos = start + b;
                packed[pos >> 3u] |= (uint8_t)(1u << (pos & 7u));
            }
        }
    }
    m1rsi_blake2b_256(packed, bytes, out32);
    return M1RSI_STATUS_OK;
}

uint64_t m1rsi_proof_difficulty(const M1RsiProof42 *proof, uint32_t edge_bits, uint64_t graph_weight) {
    uint8_t h[32];
    if (m1rsi_proof_hash32(proof, edge_bits, h) != M1RSI_STATUS_OK) return 0ull;
    uint64_t lo = m1rsi_load64_be(h);
    if (lo == 0ull) lo = 1ull;
#if defined(__SIZEOF_INT128__)
    __uint128_t num = ((__uint128_t)graph_weight) << 64;
    __uint128_t q = num / lo;
    if (q > UINT64_MAX) return UINT64_MAX;
    return (uint64_t)q;
#else
    return graph_weight == 0 ? 0 : (UINT64_MAX / lo) * graph_weight;
#endif
}

static const char *m1rsi_find_json_key(const char *s, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    return strstr(s, needle);
}

static uint32_t m1rsi_json_get_u64(const char *line, const char *key, uint64_t *out) {
    const char *p = m1rsi_find_json_key(line, key);
    if (!p) return M1RSI_STATUS_BAD_ARGUMENT;
    p = strchr(p, ':');
    if (!p) return M1RSI_STATUS_BAD_ARGUMENT;
    ++p;
    while (*p == ' ' || *p == '\t' || *p == '"') ++p;
    uint64_t v = 0;
    int any = 0;
    while (*p >= '0' && *p <= '9') { any = 1; v = v * 10u + (uint64_t)(*p - '0'); ++p; }
    if (!any) return M1RSI_STATUS_BAD_ARGUMENT;
    *out = v;
    return M1RSI_STATUS_OK;
}

static uint32_t m1rsi_json_get_string(const char *line, const char *key, char *out, size_t cap) {
    const char *p = m1rsi_find_json_key(line, key);
    if (!p || !out || cap == 0u) return M1RSI_STATUS_BAD_ARGUMENT;
    p = strchr(p, ':');
    if (!p) return M1RSI_STATUS_BAD_ARGUMENT;
    ++p;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p != '"') return M1RSI_STATUS_BAD_ARGUMENT;
    ++p;
    size_t n = 0;
    while (*p && *p != '"') {
        if (n + 1u >= cap) return M1RSI_STATUS_OVERFLOW;
        out[n++] = *p++;
    }
    out[n] = 0;
    return *p == '"' ? M1RSI_STATUS_OK : M1RSI_STATUS_BAD_ARGUMENT;
}

uint32_t m1rsi_parse_stratum_job_line(const char *line, M1RsiStratumJob *job) {
    if (!line || !job) return M1RSI_STATUS_BAD_ARGUMENT;
    memset(job, 0, sizeof(*job));
    uint32_t st = m1rsi_json_get_u64(line, "height", &job->height);
    if (st != M1RSI_STATUS_OK) return st;
    st = m1rsi_json_get_u64(line, "job_id", &job->job_id);
    if (st != M1RSI_STATUS_OK) return st;
    st = m1rsi_json_get_u64(line, "difficulty", &job->difficulty);
    if (st != M1RSI_STATUS_OK) return st;
    st = m1rsi_json_get_string(line, "pre_pow", job->pre_pow_hex, sizeof(job->pre_pow_hex));
    if (st != M1RSI_STATUS_OK) return st;
    return m1rsi_hex_to_bytes(job->pre_pow_hex, job->pre_pow_bytes, sizeof(job->pre_pow_bytes), &job->pre_pow_len);
}

uint32_t m1rsi_format_login_json(const char *request_id, const char *login, const char *password, const char *agent, char *out, size_t cap) {
    if (!request_id || !login || !password || !agent || !out || cap == 0u) return M1RSI_STATUS_BAD_ARGUMENT;
    int n = snprintf(out, cap, "{\"id\":\"%s\",\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"%s\"}}\n", request_id, login, password, agent);
    return (n > 0 && (size_t)n < cap) ? M1RSI_STATUS_OK : M1RSI_STATUS_OVERFLOW;
}
