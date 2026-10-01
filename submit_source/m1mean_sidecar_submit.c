#include "m1mean_sidecar_submit.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static uint32_t m1mean_safe_request_id(const char *request_id) {
    if (!request_id || !*request_id) return 0u;
    for (const unsigned char *p = (const unsigned char *)request_id; *p; ++p) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= 'a' && *p <= 'z') ||
            *p == '_' || *p == '-' || *p == '.' || *p == ':') {
            continue;
        }
        return 0u;
    }
    return 1u;
}

static uint32_t m1mean_pre_pow_same(const uint8_t a[M1MEAN_SIDECAR_PRE_POW_ID_BYTES],
                                    const uint8_t b[M1MEAN_SIDECAR_PRE_POW_ID_BYTES]) {
    return memcmp(a, b, M1MEAN_SIDECAR_PRE_POW_ID_BYTES) == 0 ? 1u : 0u;
}

static uint32_t m1mean_snapshot_stale_against_current(const M1MeanSidecarSolutionEvent *event,
                                                      const M1MeanSidecarCurrentJobView *current) {
    if (!event || !current || !current->valid) return 0u;
    const M1MeanSidecarJobSnapshot *s = &event->solved_snapshot;
    if (s->generation != current->generation) return 1u;
    if (s->height != current->height) return 1u;
    if (s->job_id != current->job_id) return 1u;
    if (!m1mean_pre_pow_same(s->pre_pow_id, current->pre_pow_id)) return 1u;
    return 0u;
}

static int m1mean_appendf(char *out, size_t cap, size_t *used, const char *fmt, ...) {
    if (!used || !fmt) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf((out && *used < cap) ? out + *used : NULL,
                      (out && *used < cap) ? cap - *used : 0u,
                      fmt,
                      ap);
    va_end(ap);
    if (n < 0) return -1;
    *used += (size_t)n;
    return 0;
}

M1MeanSidecarSubmitStatus m1mean_sidecar_validate_solution_event(
    const M1MeanSidecarSolutionEvent *event) {
    if (!event) return M1MEAN_SIDECAR_SUBMIT_BAD_ARGUMENT;
    const M1MeanSidecarJobSnapshot *s = &event->solved_snapshot;
    if (s->edge_bits == 0u || s->edge_bits >= 63u) return M1MEAN_SIDECAR_SUBMIT_BAD_EDGE_BITS;
    if (event->pow_count != M1MEAN_SIDECAR_PROOFSIZE) return M1MEAN_SIDECAR_SUBMIT_BAD_PROOF_SIZE;
    if (s->difficulty == 0u) return M1MEAN_SIDECAR_SUBMIT_ZERO_DIFFICULTY;
    /* Reference grin-miner filters solutions below job difficulty before emitting
     * FoundSolution to the submit lane. Preserve that pre-submit filter here. */
    if (event->proof_difficulty < s->difficulty) return M1MEAN_SIDECAR_SUBMIT_LOW_DIFFICULTY;

    const uint64_t limit = 1ull << s->edge_bits;
    for (uint32_t i = 0u; i < M1MEAN_SIDECAR_PROOFSIZE; ++i) {
        if (event->pow[i] >= limit) return M1MEAN_SIDECAR_SUBMIT_RANGE;
        if (i != 0u) {
            if (event->pow[i] == event->pow[i - 1u]) return M1MEAN_SIDECAR_SUBMIT_DUPLICATE;
            if (event->pow[i] < event->pow[i - 1u]) return M1MEAN_SIDECAR_SUBMIT_NON_SORTED;
        }
    }
    return M1MEAN_SIDECAR_SUBMIT_OK;
}

size_t m1mean_sidecar_format_submit_frame(
    const M1MeanSidecarSolutionEvent *event,
    const M1MeanSidecarCurrentJobView *current,
    const char *request_id,
    char *out,
    size_t cap,
    M1MeanSidecarSubmitBuildResult *result) {
    M1MeanSidecarSubmitBuildResult local;
    memset(&local, 0, sizeof(local));
    if (result) memset(result, 0, sizeof(*result));

    if (!event || !request_id) {
        local.status = M1MEAN_SIDECAR_SUBMIT_BAD_ARGUMENT;
        if (result) *result = local;
        return 0u;
    }
    if (!m1mean_safe_request_id(request_id)) {
        local.status = M1MEAN_SIDECAR_SUBMIT_BAD_REQUEST_ID;
        if (result) *result = local;
        return 0u;
    }

    local.status = m1mean_sidecar_validate_solution_event(event);
    local.difficulty_gate_ok = (local.status == M1MEAN_SIDECAR_SUBMIT_OK) ? 1u : 0u;
    local.solved_snapshot_stale_against_current = m1mean_snapshot_stale_against_current(event, current);
    local.serialized_height = event->solved_snapshot.height;
    local.serialized_job_id = event->solved_snapshot.job_id;
    local.serialized_nonce = event->solved_snapshot.nonce;
    if (local.status != M1MEAN_SIDECAR_SUBMIT_OK) {
        if (result) *result = local;
        return 0u;
    }

    size_t used = 0u;
    if (m1mean_appendf(out, cap, &used,
                       "{\"id\":\"%s\",\"jsonrpc\":\"2.0\",\"method\":\"submit\",\"params\":{",
                       request_id) != 0) {
        local.status = M1MEAN_SIDECAR_SUBMIT_OVERFLOW;
        if (result) *result = local;
        return 0u;
    }
    if (m1mean_appendf(out, cap, &used,
                       "\"edge_bits\":%u,\"height\":%llu,\"job_id\":%llu,\"nonce\":%llu,\"pow\":[",
                       event->solved_snapshot.edge_bits,
                       (unsigned long long)event->solved_snapshot.height,
                       (unsigned long long)event->solved_snapshot.job_id,
                       (unsigned long long)event->solved_snapshot.nonce) != 0) {
        local.status = M1MEAN_SIDECAR_SUBMIT_OVERFLOW;
        if (result) *result = local;
        return 0u;
    }
    for (uint32_t i = 0u; i < M1MEAN_SIDECAR_PROOFSIZE; ++i) {
        if (m1mean_appendf(out, cap, &used, "%s%llu", i ? "," : "", (unsigned long long)event->pow[i]) != 0) {
            local.status = M1MEAN_SIDECAR_SUBMIT_OVERFLOW;
            if (result) *result = local;
            return 0u;
        }
    }
    if (m1mean_appendf(out, cap, &used, "]}}\n") != 0) {
        local.status = M1MEAN_SIDECAR_SUBMIT_OVERFLOW;
        if (result) *result = local;
        return 0u;
    }

    local.bytes_required = used;
    if (out && cap != 0u) out[(used < cap) ? used : cap - 1u] = '\0';
    if (used + 1u > cap) local.status = M1MEAN_SIDECAR_SUBMIT_OVERFLOW;
    if (result) *result = local;
    return used;
}

M1MeanSidecarResponseKind m1mean_sidecar_classify_submit_response(const char *line) {
    if (!line || !*line) return M1MEAN_SIDECAR_RESPONSE_NETWORK_FAILURE;
    if (strstr(line, "blockfound") || strstr(line, "blockfound -")) return M1MEAN_SIDECAR_RESPONSE_BLOCKFOUND;
    if (strstr(line, "\"result\":\"ok\"") || strstr(line, "\"result\": \"ok\"")) return M1MEAN_SIDECAR_RESPONSE_ACCEPTED;
    if (strstr(line, "-32503") || strstr(line, "too late") || strstr(line, "Too late")) return M1MEAN_SIDECAR_RESPONSE_STALE;
    if (strstr(line, "-32501") || strstr(line, "low difficulty") || strstr(line, "Low difficulty")) return M1MEAN_SIDECAR_RESPONSE_LOW_DIFFICULTY;
    if (strstr(line, "-32502") || strstr(line, "validate solution") || strstr(line, "Validate solution")) return M1MEAN_SIDECAR_RESPONSE_VALIDATION_FAILED;
    if (strstr(line, "\"error\"") && !strstr(line, "\"error\":null")) return M1MEAN_SIDECAR_RESPONSE_REJECTED;
    return M1MEAN_SIDECAR_RESPONSE_UNKNOWN;
}
