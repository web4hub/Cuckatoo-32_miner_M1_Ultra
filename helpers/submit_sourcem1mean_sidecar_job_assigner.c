#include "m1mean_sidecar_job_assigner.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static uint32_t m1mean_request_id_ok(const char *request_id) {
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

static int m1mean_append_raw(char *out, size_t cap, size_t *used, const char *s) {
    if (!used || !s) return -1;
    while (*s) {
        if (out && cap != 0u && *used + 1u < cap) out[*used] = *s;
        ++(*used);
        ++s;
    }
    if (out && cap != 0u) out[(*used < cap) ? *used : cap - 1u] = 0;
    return 0;
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
    if (out && cap != 0u) out[(*used < cap) ? *used : cap - 1u] = 0;
    return 0;
}

static int m1mean_append_json_string(char *out, size_t cap, size_t *used, const char *s) {
    if (m1mean_append_raw(out, cap, used, "\"") != 0) return -1;
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; ++p) {
        switch (*p) {
            case '\\': if (m1mean_append_raw(out, cap, used, "\\\\") != 0) return -1; break;
            case '"': if (m1mean_append_raw(out, cap, used, "\\\"") != 0) return -1; break;
            case '\b': if (m1mean_append_raw(out, cap, used, "\\b") != 0) return -1; break;
            case '\f': if (m1mean_append_raw(out, cap, used, "\\f") != 0) return -1; break;
            case '\n': if (m1mean_append_raw(out, cap, used, "\\n") != 0) return -1; break;
            case '\r': if (m1mean_append_raw(out, cap, used, "\\r") != 0) return -1; break;
            case '\t': if (m1mean_append_raw(out, cap, used, "\\t") != 0) return -1; break;
            default:
                if (*p < 0x20u) {
                    if (m1mean_appendf(out, cap, used, "\\u%04x", (unsigned)*p) != 0) return -1;
                } else {
                    if (out && cap != 0u && *used + 1u < cap) out[*used] = (char)*p;
                    ++(*used);
                    if (out && cap != 0u) out[(*used < cap) ? *used : cap - 1u] = 0;
                }
        }
    }
    return m1mean_append_raw(out, cap, used, "\"");
}

static const char *m1mean_find_json_key(const char *s, const char *key) {
    char needle[128];
    if (!s || !key) return NULL;
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n <= 0 || (size_t)n >= sizeof(needle)) return NULL;
    return strstr(s, needle);
}

static M1MeanSidecarJobStatus m1mean_json_get_u64(const char *line, const char *key, uint64_t *out) {
    const char *p = m1mean_find_json_key(line, key);
    if (!p || !out) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    p = strchr(p, ':');
    if (!p) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    ++p;
    while (*p == ' ' || *p == '\t' || *p == '"') ++p;
    uint64_t v = 0u;
    uint32_t any = 0u;
    while (*p >= '0' && *p <= '9') {
        any = 1u;
        uint64_t old = v;
        v = v * 10u + (uint64_t)(*p - '0');
        if (v < old) return M1MEAN_SIDECAR_JOB_OVERFLOW;
        ++p;
    }
    if (!any) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    *out = v;
    return M1MEAN_SIDECAR_JOB_OK;
}

static M1MeanSidecarJobStatus m1mean_json_get_string(const char *line, const char *key, char *out, size_t cap) {
    const char *p = m1mean_find_json_key(line, key);
    if (!p || !out || cap == 0u) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    p = strchr(p, ':');
    if (!p) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    ++p;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p != '"') return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    ++p;
    size_t n = 0u;
    while (*p && *p != '"') {
        if (n + 1u >= cap) return M1MEAN_SIDECAR_JOB_OVERFLOW;
        out[n++] = *p++;
    }
    if (*p != '"') return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    out[n] = 0;
    return M1MEAN_SIDECAR_JOB_OK;
}

static uint32_t m1mean_hex_nibble(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return 1u; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return 1u; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return 1u; }
    return 0u;
}

static M1MeanSidecarJobStatus m1mean_pre_pow_identity(const char *hex, uint8_t out[M1MEAN_SIDECAR_PRE_POW_ID_BYTES]) {
    if (!hex || !out) return M1MEAN_SIDECAR_JOB_BAD_ARGUMENT;
    memset(out, 0, M1MEAN_SIDECAR_PRE_POW_ID_BYTES);
    size_t len = strlen(hex);
    if ((len & 1u) != 0u) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
    for (size_t i = 0u; i < len; i += 2u) {
        uint8_t hi = 0u;
        uint8_t lo = 0u;
        if (!m1mean_hex_nibble(hex[i], &hi) || !m1mean_hex_nibble(hex[i + 1u], &lo)) return M1MEAN_SIDECAR_JOB_PARSE_FAILED;
        uint8_t byte = (uint8_t)((hi << 4u) | lo);
        size_t byte_index = i / 2u;
        out[byte_index % M1MEAN_SIDECAR_PRE_POW_ID_BYTES] ^= byte;
        out[(byte_index * 7u + 3u) % M1MEAN_SIDECAR_PRE_POW_ID_BYTES] =
            (uint8_t)(out[(byte_index * 7u + 3u) % M1MEAN_SIDECAR_PRE_POW_ID_BYTES] + (uint8_t)(byte + byte_index));
    }
    return M1MEAN_SIDECAR_JOB_OK;
}

M1MeanSidecarJobStatus m1mean_sidecar_job_assigner_init(
    M1MeanSidecarJobAssigner *assigner,
    uint64_t first_nonce,
    uint64_t nonce_stride,
    uint32_t edge_bits) {
    if (!assigner || nonce_stride == 0u) return M1MEAN_SIDECAR_JOB_BAD_ARGUMENT;
    if (edge_bits == 0u || edge_bits >= 63u) return M1MEAN_SIDECAR_JOB_BAD_ARGUMENT;
    memset(assigner, 0, sizeof(*assigner));
    assigner->next_generation = 1u;
    assigner->next_nonce = first_nonce;
    assigner->nonce_stride = nonce_stride;
    assigner->edge_bits = edge_bits;
    return M1MEAN_SIDECAR_JOB_OK;
}

M1MeanSidecarJobStatus m1mean_sidecar_parse_job_template(
    const char *line,
    M1MeanSidecarJobTemplate *out_template) {
    if (!line || !out_template) return M1MEAN_SIDECAR_JOB_BAD_ARGUMENT;
    memset(out_template, 0, sizeof(*out_template));
    M1MeanSidecarJobStatus st = m1mean_json_get_u64(line, "height", &out_template->height);
    if (st != M1MEAN_SIDECAR_JOB_OK) return st;
    st = m1mean_json_get_u64(line, "job_id", &out_template->job_id);
    if (st != M1MEAN_SIDECAR_JOB_OK) return st;
    st = m1mean_json_get_u64(line, "difficulty", &out_template->difficulty);
    if (st != M1MEAN_SIDECAR_JOB_OK) return st;
    if (out_template->difficulty == 0u) return M1MEAN_SIDECAR_JOB_ZERO_DIFFICULTY;
    st = m1mean_json_get_string(line, "pre_pow", out_template->pre_pow_hex, sizeof(out_template->pre_pow_hex));
    if (st != M1MEAN_SIDECAR_JOB_OK) return st;
    return m1mean_pre_pow_identity(out_template->pre_pow_hex, out_template->pre_pow_id);
}

M1MeanSidecarJobStatus m1mean_sidecar_publish_job_snapshot(
    M1MeanSidecarJobAssigner *assigner,
    const M1MeanSidecarJobTemplate *job,
    M1MeanSidecarPublishedSnapshot *out_snapshot) {
    if (!assigner || !job || !out_snapshot) return M1MEAN_SIDECAR_JOB_BAD_ARGUMENT;
    if (job->difficulty == 0u) return M1MEAN_SIDECAR_JOB_ZERO_DIFFICULTY;
    const uint64_t limit = 1ull << assigner->edge_bits;
    if (assigner->next_nonce >= limit) return M1MEAN_SIDECAR_JOB_NONCE_RANGE;
    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->snapshot.generation = assigner->next_generation++;
    out_snapshot->snapshot.height = job->height;
    out_snapshot->snapshot.job_id = job->job_id;
    out_snapshot->snapshot.difficulty = job->difficulty;
    out_snapshot->snapshot.nonce = assigner->next_nonce;
    out_snapshot->snapshot.edge_bits = assigner->edge_bits;
    memcpy(out_snapshot->snapshot.pre_pow_id, job->pre_pow_id, sizeof(out_snapshot->snapshot.pre_pow_id));
    out_snapshot->interrupt_now = (job->job_id == 0u) ? 1u : 0u;
    assigner->next_nonce += assigner->nonce_stride;
    return M1MEAN_SIDECAR_JOB_OK;
}

static size_t m1mean_format_no_params_frame(const char *request_id, const char *method, char *out, size_t cap) {
    if (!m1mean_request_id_ok(request_id) || !method) return 0u;
    size_t used = 0u;
    if (m1mean_appendf(out, cap, &used,
                       "{\"id\":\"%s\",\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":null}\n",
                       request_id,
                       method) != 0) return 0u;
    return used;
}

size_t m1mean_sidecar_format_getjobtemplate_frame(const char *request_id, char *out, size_t cap) {
    return m1mean_format_no_params_frame(request_id, "getjobtemplate", out, cap);
}

size_t m1mean_sidecar_format_status_frame(const char *request_id, char *out, size_t cap) {
    return m1mean_format_no_params_frame(request_id, "status", out, cap);
}

size_t m1mean_sidecar_format_keepalive_frame(const char *request_id, char *out, size_t cap) {
    return m1mean_format_no_params_frame(request_id, "keepalive", out, cap);
}

size_t m1mean_sidecar_format_login_frame(
    const char *request_id,
    const char *login,
    const char *password,
    const char *agent,
    char *out,
    size_t cap) {
    if (!m1mean_request_id_ok(request_id) || !login || !password || !agent) return 0u;
    size_t used = 0u;
    if (m1mean_appendf(out, cap, &used, "{\"id\":\"%s\",\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{", request_id) != 0) return 0u;
    if (m1mean_append_raw(out, cap, &used, "\"login\":") != 0) return 0u;
    if (m1mean_append_json_string(out, cap, &used, login) != 0) return 0u;
    if (m1mean_append_raw(out, cap, &used, ",\"pass\":") != 0) return 0u;
    if (m1mean_append_json_string(out, cap, &used, password) != 0) return 0u;
    if (m1mean_append_raw(out, cap, &used, ",\"agent\":") != 0) return 0u;
    if (m1mean_append_json_string(out, cap, &used, agent) != 0) return 0u;
    if (m1mean_append_raw(out, cap, &used, "}}\n") != 0) return 0u;
    return used;
}
