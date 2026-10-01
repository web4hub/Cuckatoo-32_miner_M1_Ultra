// mine34_range_harness: offline range loader for the mine34 Metal engine.
//
// This is intentionally a test harness, not a live miner. It compiles the
// current mine34_live.m engine into this translation unit with its main renamed,
// then drives the same seed/trim/peel/recover path with explicit key loaders.
#define main mine34_live_main
#include "mine34_live.m"
#undef main

typedef enum {
  HARNESS_MODE_NONE = 0,
  HARNESS_MODE_GRIN_PREPOW = 1,
  HARNESS_MODE_TROMP_HEADER80 = 2
} HarnessMode;

typedef struct {
  HarnessMode mode;
  uint32_t edge_bits;
  uint32_t rounds;
  uint64_t nonce;
  uint64_t range;
  uint8_t input[8192];
  size_t input_len;
  const char *input_label;
  const char *export_dir; // --export-survivors: dump (idx,u,v) at trim depth `rounds`, skip peel/recover
} HarnessCfg;

// d2 survivor export: full (uf,vf) node ids per surviving edge at trim depth `rounds`. Full ids,
// not >>1: cuckatoo cycle adjacency is same (node>>1) with opposite lsb (see verify()), so a
// downstream arc build keys on >>1 and may refine on lsb. The CPU sipc here is probe-only cost
// (about 2 s at 140M survivors), never the speed path.
static int harness_export_survivors(const char *dir, uint32_t eb, uint32_t rounds, uint64_t nonce,
                                    const uint64_t kk[4], const u32 *edge_idx, u32 ne, word_t nodemask) {
  char path[1024];
  snprintf(path, sizeof path, "%s/d2sv_eb%u_r%u_n%llu.bin", dir, eb, rounds, (unsigned long long)nonce);
  FILE *f = fopen(path, "wb");
  if (!f) { fprintf(stderr, "EXPORT_OPEN_FAIL %s\n", path); return -1; }
  const uint32_t magic = 0x56534432u; // "D2SV" little-endian
  const uint32_t ver = 1;
  double t0 = now_s();
  fwrite(&magic, 4, 1, f); fwrite(&ver, 4, 1, f);
  fwrite(&eb, 4, 1, f); fwrite(&rounds, 4, 1, f);
  fwrite(&nonce, 8, 1, f); fwrite(kk, 8, 4, f); fwrite(&ne, 4, 1, f);
  for (u32 i = 0; i < ne; i++) {
    word_t uf = sipc(2ULL * edge_idx[i]) & nodemask, vf = sipc(2ULL * edge_idx[i] + 1) & nodemask;
    u32 rec3[3] = { edge_idx[i], (u32)uf, (u32)vf };
    if (fwrite(rec3, 4, 3, f) != 3) { fprintf(stderr, "EXPORT_WRITE_FAIL %s\n", path); fclose(f); return -1; }
  }
  if (fclose(f) != 0) { fprintf(stderr, "EXPORT_CLOSE_FAIL %s\n", path); return -1; }
  printf("EXPORT nonce=%llu r=%u ne=%u -> %s (%.3fs, %.2f GB)\n",
    (unsigned long long)nonce, rounds, ne, path, now_s() - t0, (double)ne * 12.0 / 1e9);
  return 0;
}

typedef struct HarnessBlake2bState {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t buf[128];
  size_t buflen;
  size_t outlen;
} HarnessBlake2bState;

static const uint64_t harness_blake2b_iv[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t harness_blake2b_sigma[12][16] = {
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

static uint64_t harness_load64_le(const uint8_t *p) {
  uint64_t x = 0;
  for (unsigned i = 0; i < 8; ++i) x |= ((uint64_t)p[i]) << (8u * i);
  return x;
}

static void harness_store64_le(uint8_t *p, uint64_t x) {
  for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(x >> (8u * i));
}

#define HARNESS_B2B_ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define HARNESS_B2B_G(r,i,a,b,c,d) do { \
  a = a + b + m[harness_blake2b_sigma[r][2*i+0]]; \
  d = HARNESS_B2B_ROTR64(d ^ a, 32); \
  c = c + d; \
  b = HARNESS_B2B_ROTR64(b ^ c, 24); \
  a = a + b + m[harness_blake2b_sigma[r][2*i+1]]; \
  d = HARNESS_B2B_ROTR64(d ^ a, 16); \
  c = c + d; \
  b = HARNESS_B2B_ROTR64(b ^ c, 63); \
} while (0)

static void harness_blake2b_compress(HarnessBlake2bState *S, const uint8_t block[128]) {
  uint64_t m[16], v[16];
  for (unsigned i = 0; i < 16; ++i) m[i] = harness_load64_le(block + i * 8u);
  for (unsigned i = 0; i < 8; ++i) v[i] = S->h[i];
  for (unsigned i = 0; i < 8; ++i) v[i + 8] = harness_blake2b_iv[i];
  v[12] ^= S->t[0];
  v[13] ^= S->t[1];
  v[14] ^= S->f[0];
  v[15] ^= S->f[1];
  for (unsigned r = 0; r < 12; ++r) {
    HARNESS_B2B_G(r,0,v[0],v[4],v[8],v[12]);
    HARNESS_B2B_G(r,1,v[1],v[5],v[9],v[13]);
    HARNESS_B2B_G(r,2,v[2],v[6],v[10],v[14]);
    HARNESS_B2B_G(r,3,v[3],v[7],v[11],v[15]);
    HARNESS_B2B_G(r,4,v[0],v[5],v[10],v[15]);
    HARNESS_B2B_G(r,5,v[1],v[6],v[11],v[12]);
    HARNESS_B2B_G(r,6,v[2],v[7],v[8],v[13]);
    HARNESS_B2B_G(r,7,v[3],v[4],v[9],v[14]);
  }
  for (unsigned i = 0; i < 8; ++i) S->h[i] ^= v[i] ^ v[i + 8];
}
#undef HARNESS_B2B_G
#undef HARNESS_B2B_ROTR64

static void harness_blake2b_init(HarnessBlake2bState *S, size_t outlen) {
  memset(S, 0, sizeof(*S));
  for (unsigned i = 0; i < 8; ++i) S->h[i] = harness_blake2b_iv[i];
  S->h[0] ^= 0x01010000u ^ (uint32_t)outlen;
  S->outlen = outlen;
}

static void harness_blake2b_increment(HarnessBlake2bState *S, uint64_t inc) {
  S->t[0] += inc;
  if (S->t[0] < inc) S->t[1]++;
}

static void harness_blake2b_update(HarnessBlake2bState *S, const uint8_t *in, size_t inlen) {
  while (inlen > 0) {
    size_t left = S->buflen, fill = 128u - left;
    if (inlen > fill) {
      memcpy(S->buf + left, in, fill);
      S->buflen = 0;
      harness_blake2b_increment(S, 128u);
      harness_blake2b_compress(S, S->buf);
      in += fill;
      inlen -= fill;
    } else {
      memcpy(S->buf + left, in, inlen);
      S->buflen = left + inlen;
      return;
    }
  }
}

static void harness_blake2b_final(HarnessBlake2bState *S, uint8_t *out) {
  uint8_t buffer[64];
  harness_blake2b_increment(S, (uint64_t)S->buflen);
  S->f[0] = ~0ULL;
  memset(S->buf + S->buflen, 0, 128u - S->buflen);
  harness_blake2b_compress(S, S->buf);
  for (unsigned i = 0; i < 8; ++i) harness_store64_le(buffer + i * 8u, S->h[i]);
  memcpy(out, buffer, S->outlen);
}

static void harness_blake2b_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
  HarnessBlake2bState S;
  harness_blake2b_init(&S, 32u);
  harness_blake2b_update(&S, in, inlen);
  harness_blake2b_final(&S, out);
}

static int harness_hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int harness_hex_to_bytes(const char *hex, uint8_t *out, size_t cap, size_t *out_len) {
  size_t n = strlen(hex);
  if ((n & 1u) || n / 2u > cap) return -1;
  for (size_t i = 0; i < n / 2u; ++i) {
    int a = harness_hexval(hex[2u * i]);
    int b = harness_hexval(hex[2u * i + 1u]);
    if (a < 0 || b < 0) return -1;
    out[i] = (uint8_t)((a << 4) | b);
  }
  *out_len = n / 2u;
  return 0;
}

static int harness_parse_u64(const char *s, uint64_t *out) {
  char *end = NULL;
  errno = 0;
  unsigned long long v = strtoull(s, &end, 0);
  if (errno || !end || *end) return -1;
  *out = (uint64_t)v;
  return 0;
}

static int harness_parse_u32(const char *s, uint32_t *out) {
  uint64_t v = 0;
  if (harness_parse_u64(s, &v) != 0 || v > UINT32_MAX) return -1;
  *out = (uint32_t)v;
  return 0;
}

static void harness_usage(const char *argv0) {
  fprintf(stderr,
    "usage:\n"
    "  %s --mode grin-prepow --prepow <hex> -n <u64> -r <count> [-e 32] [-m rounds]\n"
    "  %s --mode tromp-header80 -x <160 hex chars> -n <u32> -r <count> [-e 32] [-m rounds]\n"
    "  %s --mode tromp-header80 -h <ascii-header> -n <u32> -r <count> [-e 32] [-m rounds]\n"
    "\n"
    "notes:\n"
    "  grin-prepow:     BLAKE2b-256(pre_pow || nonce_be_u64) -> k0..k3\n"
    "  tromp-header80:  patch nonce_le_u32 into bytes 76..79, BLAKE2b-256(header80) -> k0..k3\n"
    "  every graph prints: nonce N k0 k1 k2 k3 ...\n"
    "  --export-survivors <dir>: write d2sv_eb<e>_r<m>_n<N>.bin (idx,u,v per survivor at depth -m)\n"
    "                            and SKIP peel/recover (probe mode; -m is the D2 cut R*)\n",
    argv0, argv0, argv0);
}

static int harness_set_mode(HarnessCfg *cfg, const char *mode) {
  if (strcmp(mode, "grin-prepow") == 0 || strcmp(mode, "grin") == 0) {
    cfg->mode = HARNESS_MODE_GRIN_PREPOW;
    return 0;
  }
  if (strcmp(mode, "tromp-header80") == 0 || strcmp(mode, "tromp") == 0 || strcmp(mode, "header80") == 0) {
    cfg->mode = HARNESS_MODE_TROMP_HEADER80;
    return 0;
  }
  return -1;
}

static int harness_derive_keys(const HarnessCfg *cfg, uint64_t nonce, M1RsiKeys *out) {
  if (cfg->mode == HARNESS_MODE_GRIN_PREPOW) {
    return m1rsi_grin_keys_from_pre_pow_nonce(cfg->input, cfg->input_len, nonce, out) == M1RSI_STATUS_OK ? 0 : -1;
  }
  if (cfg->mode == HARNESS_MODE_TROMP_HEADER80) {
    if (nonce > UINT32_MAX) return -1;
    uint8_t header[80], digest[32];
    memcpy(header, cfg->input, sizeof(header));
    uint32_t n32 = (uint32_t)nonce;
    header[76] = (uint8_t)n32;
    header[77] = (uint8_t)(n32 >> 8u);
    header[78] = (uint8_t)(n32 >> 16u);
    header[79] = (uint8_t)(n32 >> 24u);
    harness_blake2b_256(header, sizeof(header), digest);
    out->k0 = harness_load64_le(digest + 0u);
    out->k1 = harness_load64_le(digest + 8u);
    out->k2 = harness_load64_le(digest + 16u);
    out->k3 = harness_load64_le(digest + 24u);
    return 0;
  }
  return -1;
}

int main(int argc, char **argv) {
 @autoreleasepool {
  HarnessCfg cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.edge_bits = 32;
  cfg.rounds = 160;
  cfg.range = 1;

  for (int i = 1; i < argc; ++i) {
    const char *a = argv[i];
    if (strcmp(a, "--help") == 0) {
      harness_usage(argv[0]);
      return 0;
    } else if (strcmp(a, "--mode") == 0 && i + 1 < argc) {
      if (harness_set_mode(&cfg, argv[++i]) != 0) { fprintf(stderr, "bad mode: %s\n", argv[i]); return 2; }
    } else if (strcmp(a, "--prepow") == 0 && i + 1 < argc) {
      if (harness_hex_to_bytes(argv[++i], cfg.input, sizeof(cfg.input), &cfg.input_len) != 0 || cfg.input_len == 0) {
        fprintf(stderr, "bad --prepow hex\n"); return 2;
      }
      if (cfg.mode == HARNESS_MODE_NONE) cfg.mode = HARNESS_MODE_GRIN_PREPOW;
      cfg.input_label = "--prepow";
    } else if ((strcmp(a, "--header80") == 0 || strcmp(a, "-x") == 0) && i + 1 < argc) {
      if (harness_hex_to_bytes(argv[++i], cfg.input, sizeof(cfg.input), &cfg.input_len) != 0 || cfg.input_len != 80u) {
        fprintf(stderr, "bad header80 hex: expected exactly 160 hex chars\n"); return 2;
      }
      if (cfg.mode == HARNESS_MODE_NONE) cfg.mode = HARNESS_MODE_TROMP_HEADER80;
      cfg.input_label = strcmp(a, "-x") == 0 ? "-x" : "--header80";
    } else if ((strcmp(a, "--header-ascii") == 0 || strcmp(a, "-h") == 0) && i + 1 < argc) {
      const char *s = argv[++i];
      size_t n = strlen(s);
      if (n > 80u) { fprintf(stderr, "bad header ascii: max 80 bytes\n"); return 2; }
      memset(cfg.input, 0, 80u);
      memcpy(cfg.input, s, n);
      cfg.input_len = 80u;
      if (cfg.mode == HARNESS_MODE_NONE) cfg.mode = HARNESS_MODE_TROMP_HEADER80;
      cfg.input_label = strcmp(a, "-h") == 0 ? "-h" : "--header-ascii";
    } else if ((strcmp(a, "--nonce") == 0 || strcmp(a, "-n") == 0) && i + 1 < argc) {
      if (harness_parse_u64(argv[++i], &cfg.nonce) != 0) { fprintf(stderr, "bad nonce\n"); return 2; }
    } else if ((strcmp(a, "--range") == 0 || strcmp(a, "-r") == 0) && i + 1 < argc) {
      if (harness_parse_u64(argv[++i], &cfg.range) != 0 || cfg.range == 0) { fprintf(stderr, "bad range\n"); return 2; }
    } else if ((strcmp(a, "--rounds") == 0 || strcmp(a, "-m") == 0) && i + 1 < argc) {
      if (harness_parse_u32(argv[++i], &cfg.rounds) != 0) { fprintf(stderr, "bad rounds\n"); return 2; }
      cfg.rounds &= ~1u;
      if (cfg.rounds == 0) { fprintf(stderr, "rounds must be positive\n"); return 2; }
    } else if ((strcmp(a, "--edge-bits") == 0 || strcmp(a, "-e") == 0) && i + 1 < argc) {
      if (harness_parse_u32(argv[++i], &cfg.edge_bits) != 0 || cfg.edge_bits < 20u || cfg.edge_bits > 32u) {
        fprintf(stderr, "bad edge bits: expected 20..32\n"); return 2;
      }
    } else if (strcmp(a, "--export-survivors") == 0 && i + 1 < argc) {
      cfg.export_dir = argv[++i];
    } else {
      fprintf(stderr, "unknown or incomplete arg: %s\n", a);
      harness_usage(argv[0]);
      return 2;
    }
  }

  if (cfg.mode == HARNESS_MODE_NONE || cfg.input_len == 0) {
    fprintf(stderr, "missing loader input\n");
    harness_usage(argv[0]);
    return 2;
  }
  if (cfg.range && UINT64_MAX - cfg.nonce < cfg.range - 1u) {
    fprintf(stderr, "nonce range overflows u64\n");
    return 2;
  }
  if (cfg.mode == HARNESS_MODE_TROMP_HEADER80 &&
      (cfg.nonce > UINT32_MAX || cfg.range - 1u > (uint64_t)UINT32_MAX - cfg.nonce)) {
    fprintf(stderr, "tromp-header80 mode requires u32 nonce range\n");
    return 2;
  }

  u32 eb = cfg.edge_bits, rounds = cfg.rounds;
  u64 nedges = 1ULL << eb;
  u32 zbits = 17;
  u32 nodemask = (eb >= 32) ? 0xFFFFFFFFu : ((1u << eb) - 1u);
  u32 buckbits = eb - zbits, coarsebits = (buckbits > 7) ? 7 : buckbits, finebits = buckbits - coarsebits;
  u32 coarse_n = 1u << coarsebits, fine_n = 1u << finebits, nb = coarse_n * fine_n;
  u32 coarse_cap = (u32)(nedges / coarse_n) + (u32)(nedges / coarse_n / 16) + (1u << 16);
  u32 fine_cap = (u32)(nedges / nb) + (u32)(nedges / nb / 16) + 4096;
  u32 coarse_shift = zbits + finebits, fine_shift = zbits, fine_mask = fine_n - 1u;
  NODEMASK_G = nodemask;

  id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
  if (!dev) { fprintf(stderr, "METAL_DEVICE_FAIL\n"); return 3; }
  NSError *err = nil;
  id<MTLLibrary> lib = [dev newLibraryWithSource:kSrc options:nil error:&err];
  if (!lib) { printf("COMPILE_FAIL %s\n", err.localizedDescription.UTF8String); return 3; }
  id<MTLComputePipelineState> psL1 = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"L1v"] error:&err];
  id<MTLComputePipelineState> psTS = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"trim_stage"] error:&err];
  id<MTLComputePipelineState> psL2 = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"L2"] error:&err];
  id<MTLComputePipelineState> psPC = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pclr"] error:&err];
  id<MTLComputePipelineState> psPN = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pcnt"] error:&err];
  id<MTLComputePipelineState> psPK = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pkil"] error:&err];
  id<MTLComputePipelineState> psGR = [dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"gridk"] error:&err];
  if (!psL1 || !psTS || !psL2 || !psPC || !psPN || !psPK || !psGR) { fprintf(stderr, "PIPELINE_FAIL\n"); return 3; }

  id<MTLCommandQueue> q = [dev newCommandQueue];
  id<MTLBuffer> bK = [dev newBufferWithLength:32 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fcA = [dev newBufferWithLength:(u64)nb * 4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fcB = [dev newBufferWithLength:(u64)nb * 4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> ccn = [dev newBufferWithLength:(u64)coarse_n * 4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fiA = [dev newBufferWithLength:(u64)nb * fine_cap * 8 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fiB = [dev newBufferWithLength:(u64)nb * fine_cap * 8 options:MTLResourceStorageModeShared];
  id<MTLBuffer> cEP = [dev newBufferWithLength:4096 options:MTLResourceStorageModePrivate];
  id<MTLBuffer> cIDX = [dev newBufferWithLength:(u64)coarse_n * coarse_cap * 4 options:MTLResourceStorageModePrivate];
  id<MTLBuffer> bParT = [dev newBufferWithLength:sizeof(P) options:MTLResourceStorageModeShared];
  id<MTLBuffer> bParL = [dev newBufferWithLength:sizeof(P) options:MTLResourceStorageModeShared];
  id<MTLBuffer> bGrid = [dev newBufferWithLength:12 options:MTLResourceStorageModePrivate];
  u32 TPBv = TPB;
  id<MTLBuffer> bCN = [dev newBufferWithBytes:&coarse_n length:4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> bTPB = [dev newBufferWithBytes:&TPBv length:4 options:MTLResourceStorageModeShared];
  if (!q || !bK || !fcA || !fcB || !ccn || !fiA || !fiB || !cEP || !cIDX || !bParT || !bParL || !bGrid || !bCN || !bTPB) {
    fprintf(stderr, "BUFFER_ALLOC_FAIL\n");
    return 3;
  }

  tel_init(); // env-gated (M1_TELEMETRY_PATH); unset => no-op, harness behavior unchanged
  // ---- d2 mode ladder mirror of mine34_live.m (same env vars M1_D2 / M1_D2_CUT / M1_D2_EMIT_CAP; same
  // emit+verdict+receipt at the cut; kernels/helpers shared via the #include). Kept textually identical to
  // the live block where possible so the two stay diff-auditable. Note: --export-survivors with M1_D2=abort
  // makes no sense (abort skips the gather, so the export would contain ne=0); don't combine them.
  int D2M=0; const char* d2name="off";
  { const char* e=getenv("M1_D2"); if(e&&*e&&strcmp(e,"0")!=0){ if(!strcmp(e,"emit")){D2M=1;d2name="emit";} else if(!strcmp(e,"shadow")){D2M=2;d2name="shadow";} else if(!strcmp(e,"abort")){D2M=3;d2name="abort";} else printf("M1_D2: unknown mode '%s' -> off\n",e); } }
  u32 D2CUT=getenv("M1_D2_CUT")?(u32)atoi(getenv("M1_D2_CUT")):64u;
  u32 D2CAP=getenv("M1_D2_EMIT_CAP")?(u32)atoi(getenv("M1_D2_EMIT_CAP")):(16u<<20);
  u32 D2HT=1; while(D2HT<2*D2CAP) D2HT<<=1; // hash slots: pow2 >= 2x cap -> load <=50%
  id<MTLComputePipelineState> psD2E=nil,psD2H=nil,psD2C=nil,psD2A=nil,psD2D=nil;
  id<MTLBuffer> d2N=nil,d2Idx=nil,d2KU=nil,d2KV=nil,d2HU=nil,d2HV=nil,d2Cnt=nil,d2Off=nil,d2Adj=nil,d2P=nil,d2Found=nil,d2Cand=nil,d2Ccap=nil,d2Dcap=nil;
  if(D2M){ // one-time allocation, mirrors live
    psD2E=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"d2emit"] error:&err];
    psD2H=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_hbuild"] error:&err];
    psD2C=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_count"] error:&err];
    psD2A=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_emit"] error:&err];
    psD2D=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_dfs"] error:&err];
    d2N=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
    d2Idx=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2KU=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2KV=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2HU=[dev newBufferWithLength:(u64)D2HT*4 options:MTLResourceStorageModeShared]; // hash multimaps keyU/keyV->edge, 2x cap slots
    d2HV=[dev newBufferWithLength:(u64)D2HT*4 options:MTLResourceStorageModeShared];
    d2Cnt=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2Off=[dev newBufferWithLength:((u64)D2CAP+1)*4 options:MTLResourceStorageModeShared]; // n+1 entries: k_d2_dfs reads adj_off[src+1]
    d2Adj=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];     // arc cap == emit cap (arcs measure about 1.00n)
    d2P=[dev newBufferWithLength:sizeof(D2PAR) options:MTLResourceStorageModeShared];
    d2Found=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
    d2Cand=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
    u32 one=1; d2Ccap=[dev newBufferWithBytes:&one length:4 options:MTLResourceStorageModeShared];
    d2Dcap=[dev newBufferWithBytes:&D2CAP length:4 options:MTLResourceStorageModeShared];
    if(!psD2E||!psD2H||!psD2C||!psD2A||!psD2D||!d2N||!d2Idx||!d2KU||!d2KV||!d2HU||!d2HV||!d2Cnt||!d2Off||!d2Adj||!d2P||!d2Found||!d2Cand||!d2Ccap||!d2Dcap){ printf("D2: pipeline/alloc FAIL -> mode forced off\n"); D2M=0; }
    else printf("D2: mode=%s cut=%u emit_cap=%u buffers=%.2fGB%s\n",d2name,D2CUT,D2CAP,((double)D2CAP*24+(double)D2HT*8)/1e9,(D2CUT>=rounds)?" (WARNING: cut>=rounds, verdict never fires)":"");
  }

  double memGB = ((double)nb * fine_cap * 4 * 2 + (double)coarse_n * coarse_cap * 4 * 2) / 1e9;
  const char *mode_name = cfg.mode == HARNESS_MODE_GRIN_PREPOW ? "grin-prepow" : "tromp-header80";
  printf("mine34_range_harness: mode=%s input=%s input_bytes=%zu cuckatoo%u rounds=%u nonce=%llu range=%llu mem~%.0fGB\n",
    mode_name, cfg.input_label ? cfg.input_label : "", cfg.input_len, eb, rounds,
    (unsigned long long)cfg.nonce, (unsigned long long)cfg.range, memGB);

  double(^doL2)(P,id<MTLBuffer>,id<MTLBuffer>) = ^double(P pr, id<MTLBuffer> dFC, id<MTLBuffer> dFI) {
    *(P*)bParL.contents = pr;
    id<MTLBuffer> bP = bParL;
    memset(dFC.contents, 0, (u64)nb * 4);
    u32 maxc = 0;
    u32 *cc = (u32*)ccn.contents;
    for (u32 i = 0; i < coarse_n; i++) if (cc[i] > maxc) maxc = cc[i];
    u32 mc = (maxc + TPB - 1) / TPB;
    if (mc < 1) mc = 1;
    id<MTLCommandBuffer> c = [q commandBuffer];
    id<MTLComputeCommandEncoder> e = [c computeCommandEncoder];
    [e setComputePipelineState:psL2];
    [e setBuffer:bP offset:0 atIndex:0];
    [e setBuffer:ccn offset:0 atIndex:1];
    [e setBuffer:cEP offset:0 atIndex:2];
    [e setBuffer:cIDX offset:0 atIndex:3];
    [e setBuffer:dFC offset:0 atIndex:4];
    [e setBuffer:dFI offset:0 atIndex:5];
    [e setBuffer:bK offset:0 atIndex:6];
    [e dispatchThreadgroups:MTLSizeMake(mc,coarse_n,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];
    [e endEncoding];
    [c commit];
    [c waitUntilCompleted];
    return 0;
  };

  u32 sol[PROOFSIZE];
  u32 *nonces = malloc((size_t)(nedges / 4 + 16) * 4 * 4);
  if (!nonces) { fprintf(stderr, "HOST_ALLOC_FAIL\n"); return 3; }

  double t0 = now_s();
  uint64_t sols = 0;
  for (uint64_t graph = 0; graph < cfg.range; ++graph) { @autoreleasepool {
    uint64_t nonce = cfg.nonce + graph;
    M1RsiKeys rk;
    if (harness_derive_keys(&cfg, nonce, &rk) != 0) {
      fprintf(stderr, "KEY_DERIVE_FAIL nonce=%llu\n", (unsigned long long)nonce);
      free(nonces);
      return 4;
    }
    u64 kk[4] = { rk.k0, rk.k1, rk.k2, rk.k3 };
    SK0 = kk[0]; SK1 = kk[1]; SK2 = kk[2]; SK3 = kk[3];
    memcpy(bK.contents, kk, 32);
    printf("nonce %llu k0 k1 k2 k3 %016llx %016llx %016llx %016llx\n",
      (unsigned long long)nonce,
      (unsigned long long)kk[0], (unsigned long long)kk[1],
      (unsigned long long)kk[2], (unsigned long long)kk[3]);

    double tkey = now_s();
    P ps = { nodemask, zbits, coarse_shift, coarse_n, coarse_cap, fine_shift, fine_mask, fine_n, fine_cap, 0 };
    id<MTLBuffer> bPs = [dev newBufferWithBytes:&ps length:sizeof(P) options:MTLResourceStorageModeShared];
    memset(ccn.contents, 0, (u64)coarse_n * 4);
    u64 CH = 1ull << 28;
    {
      id<MTLCommandBuffer> c = [q commandBuffer];
      id<MTLComputeCommandEncoder> e = [c computeCommandEncoder];
      [e setComputePipelineState:psL1];
      [e setBuffer:bK offset:0 atIndex:0];
      [e setBuffer:bPs offset:0 atIndex:1];
      [e setBuffer:ccn offset:0 atIndex:2];
      [e setBuffer:cEP offset:0 atIndex:3];
      [e setBuffer:cIDX offset:0 atIndex:4];
      for (u64 base = 0; base < nedges; base += CH) {
        u32 b32 = (u32)base;
        u64 n = (nedges - base < CH) ? (nedges - base) : CH;
        id<MTLBuffer> bB = [dev newBufferWithBytes:&b32 length:4 options:MTLResourceStorageModeShared];
        [e setBuffer:bB offset:0 atIndex:5];
        [e dispatchThreadgroups:MTLSizeMake((n + TPB - 1) / TPB,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];
      }
      [e endEncoding];
      [c commit];
      [c waitUntilCompleted];
    }
    doL2(ps, fcA, fiA);
    double tSeed = now_s() - tkey, tRoundGPU = 0;

    id<MTLBuffer> curFC = fcA, curFI = fiA, dstFC = fcB, dstFI = fiB;
    double d2_emit_ms=0,d2_sort_ms=0,d2_arc_ms=0,d2_dfs_ms=0,d2_saved_ms=0; u64 d2_arc_n=0; u32 d2_emit_n=0,d2_cand=0; int d2_would=0,d2_abort=0,d2_ovf=0; char d2sfx[160]; d2sfx[0]=0; // inert when D2M==0
    for (u32 r = 0; r < rounds; r++) {
      u32 cur = r & 1, nxt = cur ^ 1;
      P pt = { nodemask, zbits, coarse_shift, coarse_n, coarse_cap, fine_shift, fine_mask, fine_n, fine_cap, cur };
      P pn = { nodemask, zbits, coarse_shift, coarse_n, coarse_cap, fine_shift, fine_mask, fine_n, fine_cap, nxt };
      *(P*)bParT.contents = pt;
      *(P*)bParL.contents = pn;
      memset(ccn.contents, 0, (u64)coarse_n * 4);
      memset(dstFC.contents, 0, (u64)nb * 4);
      id<MTLCommandBuffer> c = [q commandBuffer];
      id<MTLComputeCommandEncoder> e = [c computeCommandEncoder];
      [e setComputePipelineState:psTS];
      [e setBuffer:bK offset:0 atIndex:0];
      [e setBuffer:bParT offset:0 atIndex:1];
      [e setBuffer:curFC offset:0 atIndex:2];
      [e setBuffer:curFI offset:0 atIndex:3];
      [e setBuffer:ccn offset:0 atIndex:4];
      [e setBuffer:cEP offset:0 atIndex:5];
      [e setBuffer:cIDX offset:0 atIndex:6];
      [e dispatchThreadgroups:MTLSizeMake(nb,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];
      [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
      [e setComputePipelineState:psGR];
      [e setBuffer:ccn offset:0 atIndex:0];
      [e setBuffer:bCN offset:0 atIndex:1];
      [e setBuffer:bTPB offset:0 atIndex:2];
      [e setBuffer:bGrid offset:0 atIndex:3];
      [e dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
      [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
      [e setComputePipelineState:psL2];
      [e setBuffer:bParL offset:0 atIndex:0];
      [e setBuffer:ccn offset:0 atIndex:1];
      [e setBuffer:cEP offset:0 atIndex:2];
      [e setBuffer:cIDX offset:0 atIndex:3];
      [e setBuffer:dstFC offset:0 atIndex:4];
      [e setBuffer:dstFI offset:0 atIndex:5];
      [e setBuffer:bK offset:0 atIndex:6];
      [e dispatchThreadgroupsWithIndirectBuffer:bGrid indirectBufferOffset:0 threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];
      [e endEncoding];
      [c commit];
      [c waitUntilCompleted];
      tRoundGPU += (c.GPUEndTime - c.GPUStartTime);
      id<MTLBuffer> t;
      t = curFC; curFC = dstFC; dstFC = t;
      t = curFI; curFI = dstFI; dstFI = t;
      if(D2M && r==D2CUT){ // d2 at the cut (post-swap: curFC/curFI = round-r survivors); textual mirror of mine34_live.m, key field = nonce here
        *(u32*)d2N.contents=0;
        { id<MTLCommandBuffer>cd=[q commandBuffer];id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
          [e setComputePipelineState:psD2E];[e setBuffer:bK offset:0 atIndex:0];[e setBuffer:bParT offset:0 atIndex:1];[e setBuffer:curFC offset:0 atIndex:2];[e setBuffer:curFI offset:0 atIndex:3];[e setBuffer:d2N offset:0 atIndex:4];[e setBuffer:d2Idx offset:0 atIndex:5];[e setBuffer:d2KU offset:0 atIndex:6];[e setBuffer:d2KV offset:0 atIndex:7];[e setBuffer:d2Dcap offset:0 atIndex:8];
          [e dispatchThreadgroups:MTLSizeMake(nb,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2emit");
          d2_emit_ms=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
        d2_emit_n=*(u32*)d2N.contents; u32 dn_=d2_emit_n>D2CAP?D2CAP:d2_emit_n; if(d2_emit_n>D2CAP)d2_ovf=1;
        if(D2M>=2 && !d2_ovf){
          *(D2PAR*)d2P.contents=(D2PAR){dn_,1u,D2HT-1u}; u32 ag=(dn_+255u)/256u; if(ag<1u)ag=1u;
          if(dn_){ // one command buffer: blit-fill both hash tables to empty -> hbuild (CAS inserts) -> count (probe). No host sort.
            id<MTLCommandBuffer>cd=[q commandBuffer];
            id<MTLBlitCommandEncoder> bl=[cd blitCommandEncoder];
            [bl fillBuffer:d2HU range:NSMakeRange(0,(u64)D2HT*4) value:0xFF];[bl fillBuffer:d2HV range:NSMakeRange(0,(u64)D2HT*4) value:0xFF];[bl endEncoding];
            id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
            [e setComputePipelineState:psD2H];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2KU offset:0 atIndex:1];[e setBuffer:d2KV offset:0 atIndex:2];[e setBuffer:d2HU offset:0 atIndex:3];[e setBuffer:d2HV offset:0 atIndex:4];
            [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];
            [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
            [e setComputePipelineState:psD2C];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2KU offset:0 atIndex:1];[e setBuffer:d2KV offset:0 atIndex:2];[e setBuffer:d2HU offset:0 atIndex:3];[e setBuffer:d2HV offset:0 atIndex:4];[e setBuffer:d2Cnt offset:0 atIndex:5];
            [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2hash"); d2_arc_ms+=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
          { double ts0=now_s(); u32* ac=(u32*)d2Cnt.contents; u32* ao=(u32*)d2Off.contents; u64 tot=0; for(u32 i=0;i<dn_;i++){ ao[i]=(u32)tot; tot+=ac[i]; } ao[dn_]=(u32)tot; d2_arc_n=tot; d2_sort_ms=(now_s()-ts0)*1e3; }
          if(d2_arc_n>(u64)D2CAP) d2_ovf=2;
          else{
            if(d2_arc_n){ id<MTLCommandBuffer>cd=[q commandBuffer];id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
              [e setComputePipelineState:psD2A];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2KU offset:0 atIndex:1];[e setBuffer:d2KV offset:0 atIndex:2];[e setBuffer:d2HU offset:0 atIndex:3];[e setBuffer:d2HV offset:0 atIndex:4];[e setBuffer:d2Off offset:0 atIndex:5];[e setBuffer:d2Adj offset:0 atIndex:6];
              [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2arc"); d2_arc_ms+=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
            *(u32*)d2Found.contents=0; *(u32*)d2Cand.contents=0;
            if(dn_){ id<MTLCommandBuffer>cd=[q commandBuffer];id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
              [e setComputePipelineState:psD2D];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2Off offset:0 atIndex:1];[e setBuffer:d2Adj offset:0 atIndex:2];[e setBuffer:d2Found offset:0 atIndex:3];[e setBuffer:d2Cand offset:0 atIndex:4];[e setBuffer:d2Ccap offset:0 atIndex:5];
              [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2dfs"); d2_dfs_ms=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
            d2_cand=*(u32*)d2Cand.contents; d2_would=(d2_cand==0);
          }
        }
        if(d2_would){ double avg_ms=(now_s()-tkey-tSeed)/(double)(r+1)*1e3; d2_saved_ms=avg_ms*(double)(rounds-1u-r); }
        if(D2M==3 && d2_would) d2_abort=1;
        tel_write("{\"receipt_kind\":\"mine34_d2.v1\",\"key\":%u,\"mode\":\"%s\",\"cut\":%u,\"emit_n\":%u,\"emit_ms\":%.3f,\"sort_ms\":%.3f,\"arc_n\":%llu,\"arc_ms\":%.3f,\"dfs_ms\":%.3f,\"candidates\":%u,\"overflow\":%d,\"would_abort\":%d,\"aborted\":%d,\"saved_est_ms\":%.1f,\"timestamp_ms\":%llu}\n",
          (u32)nonce,d2name,D2CUT,d2_emit_n,d2_emit_ms,d2_sort_ms,(unsigned long long)d2_arc_n,d2_arc_ms,d2_dfs_ms,d2_cand,d2_ovf,d2_would,d2_abort,d2_saved_ms,(unsigned long long)wall_ms());
        snprintf(d2sfx,sizeof d2sfx," | d2[%s@%u] n=%u arcs=%llu cand=%u%s%s%s",d2name,D2CUT,d2_emit_n,(unsigned long long)d2_arc_n,d2_cand,d2_ovf?" OVERFLOW":"",d2_would?" would_abort":"",d2_abort?" ABORT":"");
        if(d2_abort) break;
      }
    }
    double tRound = now_s() - tkey - tSeed;

    u32 *fc = (u32*)curFC.contents;
    u32 *fi = (u32*)curFI.contents;
    u32 ne = 0;
    if (!d2_abort) for (u32 b = 0; b < nb; b++) { // d2 abort: ne=0 -> peel+recover skip = rec=0 path (export would see ne=0 too; don't combine)
      u32 cnt = fc[b];
      if (cnt > fine_cap) cnt = fine_cap;
      u64 bs = (u64)b * fine_cap;
      for (u32 i = 0; i < cnt; i++) nonces[ne++] = fi[2 * (bs + i)];
    }

    if (cfg.export_dir) {
      if (harness_export_survivors(cfg.export_dir, eb, rounds, nonce, kk, nonces, ne, nodemask) != 0) {
        free(nonces);
        return 5;
      }
      continue; // probe mode: no peel/recover (recover explodes at shallow trim depths)
    }

    u32 ne2 = ne;
    double tPeel = 0, tRec = 0;
    if (ne >= PROOFSIZE) {
      double tp0 = now_s();
      double ts_ = now_s();
      u32 *up = malloc((size_t)ne * 4), *vp = malloc((size_t)ne * 4), *du = malloc((size_t)ne * 4), *dv = malloc((size_t)ne * 4);
      if (!up || !vp || !du || !dv) { fprintf(stderr, "PEEL_ALLOC_FAIL\n"); free(up); free(vp); free(du); free(dv); free(nonces); return 3; }
      for (u32 i = 0; i < ne; i++) {
        word_t uf = sipc(2ULL * nonces[i]) & nodemask, vf = sipc(2ULL * nonces[i] + 1) & nodemask;
        up[i] = (u32)(uf >> 1);
        vp[i] = (u32)(vf >> 1);
      }
      (void)ts_;
      u32 *su = malloc((size_t)ne * 4), *sv = malloc((size_t)ne * 4);
      if (!su || !sv) { fprintf(stderr, "SORT_ALLOC_FAIL\n"); free(up); free(vp); free(du); free(dv); free(su); free(sv); free(nonces); return 3; }
      memcpy(su, up, (size_t)ne * 4);
      memcpy(sv, vp, (size_t)ne * 4);
      radix_u32(su, ne);
      radix_u32(sv, ne);
      u32 mU = 0, mV = 0;
      for (u32 i = 0; i < ne; i++) if (i == 0 || su[i] != su[i-1]) su[mU++] = su[i];
      for (u32 i = 0; i < ne; i++) if (i == 0 || sv[i] != sv[i-1]) sv[mV++] = sv[i];
      for (u32 i = 0; i < ne; i++) {
        du[i] = g_lb(su, mU, up[i]);
        dv[i] = g_lb(sv, mV, vp[i]);
      }
      id<MTLBuffer> bDu = [dev newBufferWithBytes:du length:(u64)ne * 4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bDv = [dev newBufferWithBytes:dv length:(u64)ne * 4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bAl = [dev newBufferWithLength:ne options:MTLResourceStorageModeShared];
      memset(bAl.contents, 1, ne);
      id<MTLBuffer> bNe = [dev newBufferWithBytes:&ne length:4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bChg = [dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bDegU = [dev newBufferWithLength:(u64)(mU ? mU : 1) * 4 options:MTLResourceStorageModePrivate];
      id<MTLBuffer> bDegV = [dev newBufferWithLength:(u64)(mV ? mV : 1) * 4 options:MTLResourceStorageModePrivate];
      u32 grid = (ne + TPB - 1) / TPB;
      MTLSize gd = MTLSizeMake(grid,1,1), tg = MTLSizeMake(TPB,1,1);
      const int PM = 16;
      for (int pit = 0; pit < 4096; pit += PM) {
        *(u32*)bChg.contents = 0;
        id<MTLCommandBuffer> c = [q commandBuffer];
        id<MTLComputeCommandEncoder> e = [c computeCommandEncoder];
        [e setBuffer:bDu offset:0 atIndex:0];
        [e setBuffer:bDv offset:0 atIndex:1];
        [e setBuffer:bNe offset:0 atIndex:2];
        [e setBuffer:bAl offset:0 atIndex:3];
        [e setBuffer:bDegU offset:0 atIndex:4];
        [e setBuffer:bDegV offset:0 atIndex:5];
        [e setBuffer:bChg offset:0 atIndex:6];
        for (int m = 0; m < PM; m++) {
          [e setComputePipelineState:psPC]; [e dispatchThreadgroups:gd threadsPerThreadgroup:tg]; [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
          [e setComputePipelineState:psPN]; [e dispatchThreadgroups:gd threadsPerThreadgroup:tg]; [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
          [e setComputePipelineState:psPK]; [e dispatchThreadgroups:gd threadsPerThreadgroup:tg]; [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
        }
        [e endEncoding];
        [c commit];
        [c waitUntilCompleted];
        if (*(u32*)bChg.contents == 0) break;
      }
      unsigned char *al = (unsigned char*)bAl.contents;
      ne2 = 0;
      for (u32 i = 0; i < ne; i++) if (al[i]) nonces[ne2++] = nonces[i];
      free(up); free(vp); free(du); free(dv); free(su); free(sv);
      tPeel = now_s() - tp0;
    }

    double tr0 = now_s();
    int rec = (ne2 >= PROOFSIZE) ? recover(nodemask, nonces, ne2, sol) : 0;
    tRec = now_s() - tr0;
    if (graph < 6 || (graph % 50) == 0 || rec) {
      printf("graph %llu nonce=%llu 2core=%u | seed %.3f round %.3f (GPU %.3f, sync %.3f) peel %.3f recover %.3f | WALL %.3fs%s\n",
        (unsigned long long)graph, (unsigned long long)nonce, ne2, tSeed, tRound, tRoundGPU, tRound - tRoundGPU, tPeel, tRec, now_s() - tkey, d2sfx);
    }
    if (rec) {
      word_t we[PROOFSIZE];
      for (int i = 0; i < PROOFSIZE; i++) we[i] = sol[i];
      int ok = (verify(we) == 0);
      sols++;
      printf("Solution nonce=%llu", (unsigned long long)nonce);
      for (int i = 0; i < PROOFSIZE; i++) printf(" %jx", (uintmax_t)we[i]);
      printf("\nVerified %s\n", ok ? "POW_OK" : "FAIL");
    }
  }}

  tel_close();
  printf("%llu total solutions | %.1fs\n", (unsigned long long)sols, now_s() - t0);
  free(nonces);
 }
 return 0;
}
