#ifndef M1MEAN_SIDECAR_JOB_ASSIGNER_H
#define M1MEAN_SIDECAR_JOB_ASSIGNER_H

#include "m1mean_sidecar_submit.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M1MEAN_SIDECAR_PRE_POW_HEX_MAX 8192u

typedef enum M1MeanSidecarJobStatus {
    M1MEAN_SIDECAR_JOB_OK = 0,
    M1MEAN_SIDECAR_JOB_BAD_ARGUMENT = 1,
    M1MEAN_SIDECAR_JOB_OVERFLOW = 2,
    M1MEAN_SIDECAR_JOB_PARSE_FAILED = 3,
    M1MEAN_SIDECAR_JOB_ZERO_DIFFICULTY = 4,
    M1MEAN_SIDECAR_JOB_NONCE_RANGE = 5
} M1MeanSidecarJobStatus;

typedef struct M1MeanSidecarJobTemplate {
    uint64_t height;
    uint64_t job_id;
    uint64_t difficulty;
    char pre_pow_hex[M1MEAN_SIDECAR_PRE_POW_HEX_MAX];
    uint8_t pre_pow_id[M1MEAN_SIDECAR_PRE_POW_ID_BYTES];
} M1MeanSidecarJobTemplate;

typedef struct M1MeanSidecarJobAssigner {
    uint64_t next_generation;
    uint64_t next_nonce;
    uint64_t nonce_stride;
    uint32_t edge_bits;
} M1MeanSidecarJobAssigner;

typedef struct M1MeanSidecarPublishedSnapshot {
    M1MeanSidecarJobSnapshot snapshot;
    uint32_t interrupt_now;
} M1MeanSidecarPublishedSnapshot;

M1MeanSidecarJobStatus m1mean_sidecar_job_assigner_init(
    M1MeanSidecarJobAssigner *assigner,
    uint64_t first_nonce,
    uint64_t nonce_stride,
    uint32_t edge_bits);

M1MeanSidecarJobStatus m1mean_sidecar_parse_job_template(
    const char *line,
    M1MeanSidecarJobTemplate *out_template);

M1MeanSidecarJobStatus m1mean_sidecar_publish_job_snapshot(
    M1MeanSidecarJobAssigner *assigner,
    const M1MeanSidecarJobTemplate *job,
    M1MeanSidecarPublishedSnapshot *out_snapshot);

size_t m1mean_sidecar_format_getjobtemplate_frame(
    const char *request_id,
    char *out,
    size_t cap);

size_t m1mean_sidecar_format_status_frame(
    const char *request_id,
    char *out,
    size_t cap);

size_t m1mean_sidecar_format_keepalive_frame(
    const char *request_id,
    char *out,
    size_t cap);

size_t m1mean_sidecar_format_login_frame(
    const char *request_id,
    const char *login,
    const char *password,
    const char *agent,
    char *out,
    size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* M1MEAN_SIDECAR_JOB_ASSIGNER_H */
