#ifndef M1MEAN_SIDECAR_SUBMIT_H
#define M1MEAN_SIDECAR_SUBMIT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M1MEAN_SIDECAR_PROOFSIZE 42u
#define M1MEAN_SIDECAR_PRE_POW_ID_BYTES 32u

typedef enum M1MeanSidecarSubmitStatus {
    M1MEAN_SIDECAR_SUBMIT_OK = 0,
    M1MEAN_SIDECAR_SUBMIT_BAD_ARGUMENT = 1,
    M1MEAN_SIDECAR_SUBMIT_BAD_REQUEST_ID = 2,
    M1MEAN_SIDECAR_SUBMIT_BAD_EDGE_BITS = 3,
    M1MEAN_SIDECAR_SUBMIT_BAD_PROOF_SIZE = 4,
    M1MEAN_SIDECAR_SUBMIT_NON_SORTED = 5,
    M1MEAN_SIDECAR_SUBMIT_DUPLICATE = 6,
    M1MEAN_SIDECAR_SUBMIT_RANGE = 7,
    M1MEAN_SIDECAR_SUBMIT_ZERO_DIFFICULTY = 8,
    M1MEAN_SIDECAR_SUBMIT_LOW_DIFFICULTY = 9,
    M1MEAN_SIDECAR_SUBMIT_OVERFLOW = 10
} M1MeanSidecarSubmitStatus;

typedef enum M1MeanSidecarResponseKind {
    M1MEAN_SIDECAR_RESPONSE_UNKNOWN = 0,
    M1MEAN_SIDECAR_RESPONSE_ACCEPTED = 1,
    M1MEAN_SIDECAR_RESPONSE_BLOCKFOUND = 2,
    M1MEAN_SIDECAR_RESPONSE_STALE = 3,
    M1MEAN_SIDECAR_RESPONSE_LOW_DIFFICULTY = 4,
    M1MEAN_SIDECAR_RESPONSE_VALIDATION_FAILED = 5,
    M1MEAN_SIDECAR_RESPONSE_REJECTED = 6,
    M1MEAN_SIDECAR_RESPONSE_NETWORK_FAILURE = 7
} M1MeanSidecarResponseKind;

typedef struct M1MeanSidecarJobSnapshot {
    uint64_t generation;
    uint64_t height;
    uint64_t job_id;
    uint64_t difficulty;
    uint64_t nonce;
    uint32_t edge_bits;
    uint8_t pre_pow_id[M1MEAN_SIDECAR_PRE_POW_ID_BYTES];
} M1MeanSidecarJobSnapshot;

typedef struct M1MeanSidecarSolutionEvent {
    M1MeanSidecarJobSnapshot solved_snapshot;
    uint64_t proof_difficulty;
    uint32_t pow_count;
    uint64_t pow[M1MEAN_SIDECAR_PROOFSIZE];
} M1MeanSidecarSolutionEvent;

typedef struct M1MeanSidecarCurrentJobView {
    uint32_t valid;
    uint64_t generation;
    uint64_t height;
    uint64_t job_id;
    uint8_t pre_pow_id[M1MEAN_SIDECAR_PRE_POW_ID_BYTES];
} M1MeanSidecarCurrentJobView;

typedef struct M1MeanSidecarSubmitBuildResult {
    M1MeanSidecarSubmitStatus status;
    uint32_t difficulty_gate_ok;
    uint32_t solved_snapshot_stale_against_current;
    uint64_t serialized_height;
    uint64_t serialized_job_id;
    uint64_t serialized_nonce;
    size_t bytes_required;
} M1MeanSidecarSubmitBuildResult;

M1MeanSidecarSubmitStatus m1mean_sidecar_validate_solution_event(
    const M1MeanSidecarSolutionEvent *event);

size_t m1mean_sidecar_format_submit_frame(
    const M1MeanSidecarSolutionEvent *event,
    const M1MeanSidecarCurrentJobView *current,
    const char *request_id,
    char *out,
    size_t cap,
    M1MeanSidecarSubmitBuildResult *result);

M1MeanSidecarResponseKind m1mean_sidecar_classify_submit_response(const char *line);

#ifdef __cplusplus
}
#endif

#endif /* M1MEAN_SIDECAR_SUBMIT_H */
