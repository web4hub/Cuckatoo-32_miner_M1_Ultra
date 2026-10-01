#ifndef M1ULTRA_GRIN_RSI_H
#define M1ULTRA_GRIN_RSI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M1RSI_PROOFSIZE 42u
#define M1RSI_MAX_INLINE_FIBER 8u
#define M1RSI_STATUS_OK 0u
#define M1RSI_STATUS_BAD_ARGUMENT 1u
#define M1RSI_STATUS_BAD_EDGE_BITS 2u
#define M1RSI_STATUS_BAD_PROOF_SIZE 3u
#define M1RSI_STATUS_NON_SORTED 4u
#define M1RSI_STATUS_DUPLICATE 5u
#define M1RSI_STATUS_RANGE 6u
#define M1RSI_STATUS_ENDPOINT_DEGREE 7u
#define M1RSI_STATUS_NOT_SINGLE_CYCLE 8u
#define M1RSI_STATUS_TARGET_FAILED 9u
#define M1RSI_STATUS_STALE_JOB 10u
#define M1RSI_STATUS_OVERFLOW 11u
#define M1RSI_STATUS_NO_CYCLE 12u
#define M1RSI_STATUS_INTERNAL 255u
#define M1RSI_SOLVER_MODE_METAL 0u
#define M1RSI_SOLVER_MODE_LACE 1u
#define M1RSI_LACE_TEMPLATE_DEFAULT 4096u
#define M1RSI_LACE_TEMPLATE_MAX 1048576u

/* SipHash state produced by the exact Grin job/header nonce path. */
typedef struct M1RsiKeys {
    uint64_t k0;
    uint64_t k1;
    uint64_t k2;
    uint64_t k3;
} M1RsiKeys;

/* Job fields that must stay byte-for-byte tied to the Stratum job. */
typedef struct M1RsiJob {
    uint32_t edge_bits;       /* 32 for the requested production C32 target. */
    uint32_t proof_size;      /* 42. */
    uint64_t height;          /* Stratum height. */
    uint64_t job_id;          /* Stratum job_id; must be echoed. */
    uint64_t stratum_nonce;   /* Header/PoW nonce submitted to Stratum. */
    M1RsiKeys keys;           /* Live SipHash keys for this exact job nonce. */
} M1RsiJob;

typedef struct M1RsiProof42 {
    uint64_t nonces[M1RSI_PROOFSIZE]; /* sorted exact proof-edge nonces */
} M1RsiProof42;

typedef struct M1RsiSubmitPacket {
    uint32_t ready;
    uint32_t status;
    uint32_t exact_cycle_ok;
    uint32_t target_ok;
    uint32_t same_job_ok;
    uint32_t edge_bits;
    uint32_t proof_size;
    uint32_t scaffold_coordinate_submitted;
    uint64_t height;
    uint64_t job_id;
    uint64_t stratum_nonce;
    uint64_t nonces[M1RSI_PROOFSIZE];
} M1RsiSubmitPacket;

typedef struct M1RsiReceipt {
    uint32_t status;
    uint32_t edge_bits;
    uint32_t proof_size;
    uint32_t sorted_distinct_ok;
    uint32_t range_ok;
    uint32_t endpoint_degree_ok;
    uint32_t single_cycle_ok;
    uint32_t exact_cycle_ok;
    uint32_t stratum_shape_ok;
    uint32_t full_search_used;
    uint32_t scaffold_coordinate_submitted;
    uint32_t cache_table_used;
    uint32_t cache_table_complete;
    uint32_t cache_table_probe_only;
    uint32_t gpu_lace_used;
    uint64_t nonce_sites;
    uint64_t relation_slots;
    uint64_t cache_table_start_nonce;
    uint64_t cache_table_lanes;
    uint64_t cache_table_stride;
} M1RsiReceipt;


#define M1RSI_STRATUM_LINE_MAX 65536u
#define M1RSI_HEX_HEADER_MAX_BYTES 4096u

typedef struct M1RsiStratumConfig {
    const char *host;
    uint16_t port;
    const char *login;
    const char *password;
    const char *agent;
    const char *lace_template_file;
    uint32_t edge_bits;
    uint32_t max_attempts_per_job;
    uint32_t max_jobs;
    uint32_t keepalive_interval_sec;
    uint32_t build_full_index;
    uint32_t solver_mode;
    uint32_t lace_template_count;
    uint32_t require_share_target;
    uint64_t first_nonce;
    uint64_t nonce_stride;
    uint64_t lace_base_start;
    uint64_t lace_base_count;
    uint64_t lace_base_stride;
} M1RsiStratumConfig;

typedef struct M1RsiStratumJob {
    uint64_t difficulty;
    uint64_t height;
    uint64_t job_id;
    char pre_pow_hex[8192];
    uint8_t pre_pow_bytes[4096];
    size_t pre_pow_len;
} M1RsiStratumJob;

typedef struct M1RsiRunReceipt {
    uint32_t status;
    uint32_t max_attempts_per_job;
    uint32_t max_jobs;
    uint32_t attempts_started;
    uint32_t attempts_completed;
    uint32_t jobs_polled;
    uint32_t job_switches;
    uint32_t no_cycle_attempts;
    uint32_t target_rejected_attempts;
    uint32_t pre_submit_job_refreshes;
    uint32_t stale_submit_skipped;
    uint32_t connected;
    uint32_t logged_in;
    uint32_t job_received;
    uint32_t metal_started;
    uint32_t solve_status;
    uint32_t candidate_found;
    uint32_t exact_verified;
    uint32_t target_ok;
    uint32_t submit_sent;
    uint32_t submit_accepted;
    uint32_t block_found;
    uint32_t full_search_used;
    uint32_t lace_used;
    uint32_t gpu_lace_used;
    uint32_t cache_table_used;
    uint32_t cache_table_complete;
    uint32_t cache_table_probe_only;
    uint64_t height;
    uint64_t job_id;
    uint64_t nonce;
    uint64_t next_nonce;
    uint64_t stratum_difficulty;
    uint64_t proof_difficulty;
    uint64_t full_index_bytes;
    uint64_t cache_table_start_nonce;
    uint64_t cache_table_lanes;
    uint64_t cache_table_stride;
    uint64_t lace_templates_tested;
    uint64_t lace_bases_tested;
    uint64_t lace_candidates_tested;
    uint64_t lace_duplicate_rejects;
    uint64_t lace_residual8_passes;
    uint64_t lace_residual8_rejects;
    uint64_t lace_residual12_passes;
    uint64_t lace_residual12_rejects;
    uint64_t lace_residual16_passes;
    uint64_t lace_residual16_rejects;
    uint64_t lace_residual20_passes;
    uint64_t lace_residual20_rejects;
    uint64_t lace_residual24_passes;
    uint64_t lace_residual24_rejects;
    uint64_t lace_full_residual_rejects;
    uint64_t lace_full_residual_zero;
    uint64_t lace_exact_verify_calls;
    uint64_t lace_verified_cycles;
} M1RsiRunReceipt;

typedef struct M1RsiMemoryPlan {
    uint32_t edge_bits;
    uint64_t nonce_sites;
    uint64_t endpoint_sites_per_side;
    uint64_t head_bytes_per_side;
    uint64_t next_bytes_per_side;
    uint64_t lock_bytes_per_side;
    uint64_t head_valid_bytes_per_side;
    uint64_t next_valid_bytes_per_side;
    uint64_t total_index_bytes;
    double total_index_gib;
} M1RsiMemoryPlan;

typedef struct M1RsiBoundarySupportStats {
    uint32_t status;
    uint32_t edge_bits;
    uint32_t peel_rounds;
    uint32_t reserved0;
    uint64_t edges_scanned;
    uint64_t killed_edges;
    uint64_t survivor_edges;
    uint64_t u_rungs;
    uint64_t v_rungs;
    uint64_t fragments_len2;
    uint64_t fragments_len4;
    uint64_t fragments_len8;
    uint64_t fragments_len16;
    uint64_t fragments_len32;
    uint64_t fragment_joins;
    uint64_t zero_boundary_closures;
    uint64_t exact_verify_calls;
    uint64_t dfs_steps;
    uint64_t candidate_cycles;
} M1RsiBoundarySupportStats;

typedef struct M1RsiLaceTemplate42 {
    uint64_t offsets[M1RSI_PROOFSIZE];
} M1RsiLaceTemplate42;

typedef struct M1RsiLaceStats {
    uint32_t status;
    uint32_t edge_bits;
    uint32_t stage8_bits;
    uint32_t stage12_bits;
    uint32_t stage16_bits;
    uint32_t stage20_bits;
    uint32_t stage24_bits;
    uint32_t full_bits;
    uint64_t templates_tested;
    uint64_t bases_tested;
    uint64_t candidates_tested;
    uint64_t duplicate_rejects;
    uint64_t residual8_passes;
    uint64_t residual8_rejects;
    uint64_t residual12_passes;
    uint64_t residual12_rejects;
    uint64_t residual16_passes;
    uint64_t residual16_rejects;
    uint64_t residual20_passes;
    uint64_t residual20_rejects;
    uint64_t residual24_passes;
    uint64_t residual24_rejects;
    uint64_t full_residual_rejects;
    uint64_t full_residual_zero;
    uint64_t exact_verify_calls;
    uint64_t candidate_cycles;
    uint64_t found_template;
    uint64_t found_base;
} M1RsiLaceStats;

uint64_t m1rsi_siphash24(M1RsiKeys keys, uint64_t nonce);
uint32_t m1rsi_endpoint(M1RsiKeys keys, uint32_t edge_bits, uint64_t edge, uint32_t side);
uint32_t m1rsi_relation_id(uint32_t edge_bits, uint32_t side, uint32_t endpoint);
uint32_t m1rsi_endpoint_pair(uint32_t endpoint);
uint32_t m1rsi_endpoint_low(uint32_t endpoint);
uint64_t m1rsi_nonce_limit(uint32_t edge_bits);
M1RsiMemoryPlan m1rsi_memory_plan(uint32_t edge_bits);

uint32_t m1rsi_verify42_scaffold_cycle(const M1RsiJob *job, const M1RsiProof42 *proof, M1RsiReceipt *receipt);
uint32_t m1rsi_reconstruct42_scaffold_order(const M1RsiJob *job, const uint64_t unordered_nonces[M1RSI_PROOFSIZE], uint64_t ordered_nonces[M1RSI_PROOFSIZE], M1RsiReceipt *receipt);
uint32_t m1rsi_build_submit_packet(const M1RsiJob *job, const M1RsiProof42 *proof, uint32_t target_ok, uint32_t same_job_ok, M1RsiSubmitPacket *packet, M1RsiReceipt *receipt);
uint32_t m1rsi_boundary_support_mine42(const M1RsiJob *job, M1RsiProof42 *out_proof, M1RsiReceipt *receipt, M1RsiBoundarySupportStats *stats);
uint32_t m1rsi_lace_mine42(const M1RsiJob *job, const M1RsiLaceTemplate42 *templates, uint32_t template_count, uint64_t base_start, uint64_t base_count, uint64_t base_stride, M1RsiProof42 *out_proof, M1RsiReceipt *receipt, M1RsiLaceStats *stats);
uint32_t m1rsi_lace_builtin_templates(M1RsiLaceTemplate42 *out_templates, uint32_t cap, uint32_t *out_count);
uint32_t m1rsi_lace_load_template_file(const char *path, M1RsiLaceTemplate42 *out_templates, uint32_t cap, uint32_t *out_count);
uint32_t m1rsi_lace_build_template_bank(const M1RsiJob *job, const char *template_file, uint32_t requested_count, uint64_t base_start, uint64_t base_stride, M1RsiLaceTemplate42 *out_templates, uint32_t *out_count);

/* JSON-RPC 2.0 Stratum submit formatting. Returns required bytes excluding trailing NUL. */
size_t m1rsi_format_stratum_submit_json(const M1RsiSubmitPacket *packet, const char *request_id, char *out, size_t cap);

uint32_t m1rsi_hex_to_bytes(const char *hex, uint8_t *out, size_t cap, size_t *out_len);
uint32_t m1rsi_grin_keys_from_pre_pow_nonce(const uint8_t *pre_pow, size_t pre_pow_len, uint64_t nonce, M1RsiKeys *out_keys);
uint32_t m1rsi_grin_keys_from_hex_pre_pow_nonce(const char *pre_pow_hex, uint64_t nonce, M1RsiKeys *out_keys);
uint64_t m1rsi_graph_weight(uint64_t height, uint32_t edge_bits);
uint32_t m1rsi_proof_hash32(const M1RsiProof42 *proof, uint32_t edge_bits, uint8_t out32[32]);
uint64_t m1rsi_proof_difficulty(const M1RsiProof42 *proof, uint32_t edge_bits, uint64_t graph_weight);
uint32_t m1rsi_parse_stratum_job_line(const char *line, M1RsiStratumJob *job);
uint32_t m1rsi_format_login_json(const char *request_id, const char *login, const char *password, const char *agent, char *out, size_t cap);
uint32_t m1rsi_run_stratum_miner(const M1RsiStratumConfig *cfg, M1RsiRunReceipt *receipt);

/* Implemented by native/m1ultra_grin_rsi_metal_host.m on macOS. The Linux test build supplies a no-op stub. */
uint32_t m1rsi_metal_solve_one_job(const M1RsiJob *job, M1RsiProof42 *out_proof, M1RsiReceipt *out_receipt);
uint32_t m1rsi_metal_lace_mine42(const M1RsiJob *job, const M1RsiLaceTemplate42 *templates, uint32_t template_count, uint64_t base_start, uint64_t base_count, uint64_t base_stride, M1RsiProof42 *out_proof, M1RsiReceipt *receipt, M1RsiLaceStats *stats);
uint32_t m1rsi_metal_lace_local_demand_fill(const M1RsiJob *job, uint32_t side, uint32_t want_endpoint, uint32_t bits, uint64_t edge_start, uint64_t stride, uint64_t edge_mask, const uint64_t *prefix_edges, uint32_t prefix_count, uint64_t *out_edges, uint32_t *out_other_endpoints, uint32_t cap, uint32_t trials, uint32_t *out_count, uint32_t *out_overflow);
uint32_t m1rsi_metal_lace_local_demand_fill_pair(const M1RsiJob *job, uint32_t side_a, uint32_t want_endpoint_a, uint32_t side_b, uint32_t want_endpoint_b, uint32_t bits, uint64_t edge_start_a, uint64_t stride_a, uint64_t edge_start_b, uint64_t stride_b, uint64_t edge_mask, const uint64_t *prefix_edges, uint32_t prefix_count, uint64_t *out_edges_a, uint32_t *out_other_endpoints_a, uint32_t cap_a, uint64_t *out_edges_b, uint32_t *out_other_endpoints_b, uint32_t cap_b, uint32_t trials, uint32_t *out_count_a, uint32_t *out_overflow_a, uint32_t *out_count_b, uint32_t *out_overflow_b);
uint32_t m1rsi_metal_lace_local_demand_bridge_close(const M1RsiJob *job, uint32_t side_a, uint32_t want_endpoint_a, uint32_t side_b, uint32_t want_endpoint_b, uint32_t bits, uint64_t edge_start_a, uint64_t stride_a, uint64_t edge_start_b, uint64_t stride_b, uint64_t edge_mask, const uint64_t *prefix_edges, uint32_t prefix_count, uint32_t cap, uint32_t trials, uint64_t *out_edge_a, uint64_t *out_edge_b, uint32_t *out_count_a, uint32_t *out_overflow_a, uint32_t *out_count_b, uint32_t *out_overflow_b);
uint32_t m1rsi_metal_lace_local_demand_chain_prefix(const M1RsiJob *job, uint32_t bits, uint64_t seed, uint64_t key_mix, uint64_t edge_mask, uint32_t chain_pairs, uint32_t trials, uint64_t *out_edges, uint32_t *out_current_endpoint, uint32_t *out_start_u_endpoint, uint32_t *out_steps, uint32_t *out_failed_step);
uint32_t m1rsi_metal_lace_local_demand_chain_bridge_close(const M1RsiJob *job, uint32_t bits, uint64_t seed, uint64_t key_mix, uint64_t edge_mask, uint32_t chain_pairs, uint32_t chain_trials, uint32_t bridge_trials, uint32_t cap, uint64_t *out_edges, uint32_t *out_steps, uint32_t *out_failed_step, uint32_t *out_count_a, uint32_t *out_overflow_a, uint32_t *out_count_b, uint32_t *out_overflow_b);
uint32_t m1rsi_metal_order42_scaffold(const M1RsiJob *job, const uint64_t unordered_nonces[M1RSI_PROOFSIZE], uint64_t ordered_nonces[M1RSI_PROOFSIZE]);


#ifdef __cplusplus
}
#endif

#endif /* M1ULTRA_GRIN_RSI_H */
