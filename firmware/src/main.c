/*
 * Hybrid X25519 + ML-KEM key-exchange benchmark for the Raspberry Pi Pico
 * (RP2040), wolfCrypt. ML-KEM-512 (L1), ML-KEM-768 (L3), ML-KEM-1024 (L5).
 *
 * Each round runs a complete hybrid exchange between a client and a server
 * that hold separate key objects, and times every step:
 *   client: X25519 keygen, ML-KEM keygen, serialise (X25519 pk || ML-KEM ek)
 *   server: parse, X25519 keygen, X25519 shared secret, ML-KEM encapsulation,
 *           combiner, serialise (X25519 pk || ML-KEM ct)
 *   client: parse, X25519 shared secret, ML-KEM decapsulation, combiner
 * Two combiners are timed on both sides and checked for agreement:
 *   - HKDF-SHA256 over ss_MLKEM || ss_X25519 (TLS 1.3 hybrid concatenation
 *     fed to an HKDF extract/expand; the full TLS key schedule is not run)
 *   - X-Wing-style SHA3-256(label || ss_MLKEM || ss_X25519 || ct_X || pk_X)
 * Every sample is printed as a RAW line; role totals are formed in analysis.
 *
 * Optional (-DWITH_P256): P-256 ECDH (wolfCrypt SP math with ARMv6-M Thumb
 * assembly) as an alternative classical component.
 *
 * After the timing loop, a memory pass measures peak stack and peak heap per
 * operation and re-runs each operation under emulated RFC 7228 RAM budgets.
 *
 * Core 0 services USB serial; core 1 runs the benchmark on a dedicated stack.
 */
#define FW_NAME            "kem"
#define CORE1_STACK_WORDS  (64 * 1024 / 4)
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha3.h>
#ifdef WITH_P256
#include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifndef KEM_ROUNDS
#define KEM_ROUNDS         100
#endif
#define WARMUP_ROUNDS      1
#define SS_LEN             32
#define X_LEN              CURVE25519_KEYSIZE   /* 32 */
#define CT_MAX             1568                 /* ML-KEM-1024 ciphertext */
#define EK_MAX             1568                 /* ML-KEM-1024 encapsulation key */

typedef struct { const char *name, *hybrid, *level; int type; } kem_param_t;
static const kem_param_t KEMS[] = {
    { "ML-KEM-512",  "X25519+ML-KEM-512",  "L1", WC_ML_KEM_512  },
    { "ML-KEM-768",  "X25519+ML-KEM-768",  "L3", WC_ML_KEM_768  },
    { "ML-KEM-1024", "X25519+ML-KEM-1024", "L5", WC_ML_KEM_1024 },
};
#define N_KEMS (sizeof(KEMS) / sizeof(KEMS[0]))

/* Operations timed per round (index into stats and RAW op names). */
enum {
    OP_C_XKG, OP_C_KKG, OP_C_SER,
    OP_S_PARSE, OP_S_XKG, OP_S_XDH, OP_S_ENC, OP_S_HKDF, OP_S_XWING, OP_S_SER,
    OP_C_PARSE, OP_C_XDH, OP_C_DEC, OP_C_HKDF, OP_C_XWING,
    N_OPS
};
static const char *OPN[N_OPS] = {
    "client_x25519_keygen", "client_kem_keygen", "client_serialise",
    "server_parse", "server_x25519_keygen", "server_x25519_shared", "server_kem_encaps",
    "server_combine_hkdf", "server_combine_xwing", "server_serialise",
    "client_parse", "client_x25519_shared", "client_kem_decaps",
    "client_combine_hkdf", "client_combine_xwing",
};
static stat_t ST[N_KEMS][N_OPS];

/* Key objects and buffers (static: not counted as stack) */
static curve25519_key x_cli, x_srv, x_cli_peer, x_srv_peer;
static MlKemKey       kem_cli, kem_srv;
static uint8_t        msg_c2s[X_LEN + EK_MAX];   /* X25519 pk || ML-KEM ek */
static uint8_t        msg_s2c[X_LEN + CT_MAX];   /* X25519 pk || ML-KEM ct */
static uint8_t        ct[CT_MAX];
static uint8_t        ss_k_srv[SS_LEN], ss_k_cli[SS_LEN];
static uint8_t        ss_x_srv[X_LEN],  ss_x_cli[X_LEN];
static uint8_t        key_hkdf_srv[32], key_hkdf_cli[32], key_xw_srv[32], key_xw_cli[32];
static word32         ek_len, ct_len;

/* ------------------------------------------------------------------------ */
/* Combiners                                                                 */
/* ------------------------------------------------------------------------ */
static const byte HKDF_INFO[] = "rp2040 hybrid x25519+mlkem";
static int combine_hkdf(const uint8_t *ss_k, const uint8_t *ss_x, uint8_t *out)
{
    uint8_t ikm[SS_LEN + X_LEN];
    memcpy(ikm, ss_k, SS_LEN); memcpy(ikm + SS_LEN, ss_x, X_LEN);
    return wc_HKDF(WC_SHA256, ikm, sizeof ikm, NULL, 0, HKDF_INFO, sizeof HKDF_INFO - 1, out, 32);
}
/* X-Wing label "\.//^\" (6 bytes) */
static const uint8_t XWING_LABEL[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };
static int combine_xwing(const uint8_t *ss_k, const uint8_t *ss_x,
                         const uint8_t *ct_x, const uint8_t *pk_x, uint8_t *out)
{
    uint8_t in[6 + SS_LEN + X_LEN + X_LEN + X_LEN];
    memcpy(in, XWING_LABEL, 6);
    memcpy(in + 6, ss_k, SS_LEN);
    memcpy(in + 6 + SS_LEN, ss_x, X_LEN);
    memcpy(in + 6 + SS_LEN + X_LEN, ct_x, X_LEN);
    memcpy(in + 6 + SS_LEN + 2 * X_LEN, pk_x, X_LEN);
    return wc_Sha3_256Hash(in, sizeof in, out);
}

/* ------------------------------------------------------------------------ */
/* One complete hybrid exchange                                              */
/* ------------------------------------------------------------------------ */
static int run_round(unsigned k, WC_RNG *rng, bool record, uint32_t idx)
{
    int ret;
    uint64_t t[N_OPS];
    word32 len;
    memset(t, 0, sizeof t);

    wc_curve25519_init(&x_cli); wc_curve25519_init(&x_srv);
    wc_curve25519_init(&x_cli_peer); wc_curve25519_init(&x_srv_peer);
    if ((ret = wc_MlKemKey_Init(&kem_cli, KEMS[k].type, NULL, INVALID_DEVID)) != 0) goto out;
    if ((ret = wc_MlKemKey_Init(&kem_srv, KEMS[k].type, NULL, INVALID_DEVID)) != 0) goto out;
    if ((ret = wc_MlKemKey_PublicKeySize(&kem_cli, &ek_len)) != 0) goto out;
    if ((ret = wc_MlKemKey_CipherTextSize(&kem_cli, &ct_len)) != 0) goto out;

    /* ---- client: key generation and first message ---- */
    TIMED(t[OP_C_XKG], wc_curve25519_make_key(rng, X_LEN, &x_cli));   if (ret) goto out;
    TIMED(t[OP_C_KKG], wc_MlKemKey_MakeKey(&kem_cli, rng));           if (ret) goto out;
    len = X_LEN;
    TIMED(t[OP_C_SER], (wc_curve25519_export_public_ex(&x_cli, msg_c2s, &len, EC25519_LITTLE_ENDIAN) ||
                        wc_MlKemKey_EncodePublicKey(&kem_cli, msg_c2s + X_LEN, ek_len)) ? -1 : 0);
    if (ret) goto out;

    /* ---- server ---- */
    TIMED(t[OP_S_PARSE], (wc_curve25519_import_public_ex(msg_c2s, X_LEN, &x_srv_peer, EC25519_LITTLE_ENDIAN) ||
                          wc_MlKemKey_DecodePublicKey(&kem_srv, msg_c2s + X_LEN, ek_len)) ? -1 : 0);
    if (ret) goto out;
    TIMED(t[OP_S_XKG], wc_curve25519_make_key(rng, X_LEN, &x_srv));   if (ret) goto out;
    len = X_LEN;
    TIMED(t[OP_S_XDH], wc_curve25519_shared_secret_ex(&x_srv, &x_srv_peer, ss_x_srv, &len, EC25519_LITTLE_ENDIAN));
    if (ret) goto out;
    TIMED(t[OP_S_ENC], wc_MlKemKey_Encapsulate(&kem_srv, ct, ss_k_srv, rng)); if (ret) goto out;
    len = X_LEN;
    TIMED(t[OP_S_SER], (wc_curve25519_export_public_ex(&x_srv, msg_s2c, &len, EC25519_LITTLE_ENDIAN) ? -1 :
                        (memcpy(msg_s2c + X_LEN, ct, ct_len), 0)));
    if (ret) goto out;
    TIMED(t[OP_S_HKDF],  combine_hkdf(ss_k_srv, ss_x_srv, key_hkdf_srv)); if (ret) goto out;
    TIMED(t[OP_S_XWING], combine_xwing(ss_k_srv, ss_x_srv, msg_s2c, msg_c2s, key_xw_srv)); if (ret) goto out;

    /* ---- client: second half ---- */
    TIMED(t[OP_C_PARSE], wc_curve25519_import_public_ex(msg_s2c, X_LEN, &x_cli_peer, EC25519_LITTLE_ENDIAN));
    if (ret) goto out;
    len = X_LEN;
    TIMED(t[OP_C_XDH], wc_curve25519_shared_secret_ex(&x_cli, &x_cli_peer, ss_x_cli, &len, EC25519_LITTLE_ENDIAN));
    if (ret) goto out;
    TIMED(t[OP_C_DEC], wc_MlKemKey_Decapsulate(&kem_cli, ss_k_cli, msg_s2c + X_LEN, ct_len)); if (ret) goto out;
    TIMED(t[OP_C_HKDF],  combine_hkdf(ss_k_cli, ss_x_cli, key_hkdf_cli)); if (ret) goto out;
    TIMED(t[OP_C_XWING], combine_xwing(ss_k_cli, ss_x_cli, msg_s2c, msg_c2s, key_xw_cli)); if (ret) goto out;

    /* Correctness: component secrets and both combined keys must agree */
    if (memcmp(ss_x_cli, ss_x_srv, X_LEN) || memcmp(ss_k_cli, ss_k_srv, SS_LEN) ||
        memcmp(key_hkdf_cli, key_hkdf_srv, 32) || memcmp(key_xw_cli, key_xw_srv, 32)) {
        ret = -9999; goto out;
    }

    if (record) {
        for (int o = 0; o < N_OPS; o++) {
            st_add(&ST[k][o], t[o]);
            raw(KEMS[k].hybrid, KEMS[k].level, OPN[o], idx, t[o]);
        }
    }
out:
    wc_MlKemKey_Free(&kem_cli); wc_MlKemKey_Free(&kem_srv);
    wc_curve25519_free(&x_cli); wc_curve25519_free(&x_srv);
    wc_curve25519_free(&x_cli_peer); wc_curve25519_free(&x_srv_peer);
    return ret;
}

#ifdef WITH_P256
/* ------------------------------------------------------------------------ */
/* P-256 ECDH (alternative classical component)                             */
/* ------------------------------------------------------------------------ */
static ecc_key p_cli, p_srv;
static int bench_p256(WC_RNG *rng)
{
    int ret = 0;
    stat_t kg, dh; st_init(&kg); st_init(&dh);
    uint8_t s1[32], s2[32];
    for (int i = -WARMUP_ROUNDS; i < KEM_ROUNDS; i++) {
        uint64_t a, b, c, d; word32 l1 = 32, l2 = 32;
        wc_ecc_init(&p_cli); wc_ecc_init(&p_srv);
        wc_ecc_set_rng(&p_cli, rng); wc_ecc_set_rng(&p_srv, rng);
        TIMED(a, wc_ecc_make_key_ex(rng, 32, &p_cli, ECC_SECP256R1)); if (ret) goto e;
        TIMED(b, wc_ecc_make_key_ex(rng, 32, &p_srv, ECC_SECP256R1)); if (ret) goto e;
        TIMED(c, wc_ecc_shared_secret(&p_srv, &p_cli, s1, &l1));      if (ret) goto e;
        TIMED(d, wc_ecc_shared_secret(&p_cli, &p_srv, s2, &l2));      if (ret) goto e;
        if (l1 != l2 || memcmp(s1, s2, l1)) { ret = -9998; goto e; }
        if (i >= 0) {
            st_add(&kg, a); st_add(&kg, b); st_add(&dh, c); st_add(&dh, d);
            raw("P-256", "--", "keygen", 2 * i, a);  raw("P-256", "--", "keygen", 2 * i + 1, b);
            raw("P-256", "--", "shared", 2 * i, c);  raw("P-256", "--", "shared", 2 * i + 1, d);
        }
        wc_ecc_free(&p_cli); wc_ecc_free(&p_srv);
        continue;
e:      wc_ecc_free(&p_cli); wc_ecc_free(&p_srv);
        printf("ERROR: P-256 round %d: %d\n", i, ret);
        return ret;
    }
    printf("CSV,latency_us,--,P-256 keygen,%lu,%llu,%llu,%llu\n", (unsigned long)kg.n,
           (unsigned long long)st_avg(&kg), (unsigned long long)kg.min, (unsigned long long)kg.max);
    printf("CSV,latency_us,--,P-256 shared,%lu,%llu,%llu,%llu\n", (unsigned long)dh.n,
           (unsigned long long)st_avg(&dh), (unsigned long long)dh.min, (unsigned long long)dh.max);
    return 0;
}
#endif

/* ------------------------------------------------------------------------ */
/* Backward-compatible summary lines (CSV,latency_us,...)                    */
/* ------------------------------------------------------------------------ */
static void csvl(const char *lvl, const char *op, const stat_t *s)
{
    printf("CSV,latency_us,%s,%s,%lu,%llu,%llu,%llu\n", lvl, op, (unsigned long)s->n,
           (unsigned long long)st_avg(s), (unsigned long long)s->min, (unsigned long long)s->max);
}
static void print_summary(void)
{
    for (unsigned k = 0; k < N_KEMS; k++)
        for (int o = 0; o < N_OPS; o++)
            csvl(KEMS[k].level, OPN[o], &ST[k][o]);
}

/* ------------------------------------------------------------------------ */
/* Memory pass: per-operation peak stack and heap, then RAM budgets          */
/* ------------------------------------------------------------------------ */
typedef struct { WC_RNG *rng; unsigned k; } kctx_t;

static int op_x_keygen(void *c) { kctx_t *x = c; return wc_curve25519_make_key(x->rng, X_LEN, &x_cli); }
static int op_x_shared(void *c) { (void)c; word32 l = X_LEN;
    return wc_curve25519_shared_secret_ex(&x_cli, &x_cli_peer, ss_x_cli, &l, EC25519_LITTLE_ENDIAN); }
static int op_k_keygen(void *c) { kctx_t *x = c; return wc_MlKemKey_MakeKey(&kem_cli, x->rng); }
static int op_k_encode(void *c) { (void)c; return wc_MlKemKey_EncodePublicKey(&kem_cli, msg_c2s + X_LEN, ek_len); }
static int op_k_decode(void *c) { (void)c; return wc_MlKemKey_DecodePublicKey(&kem_srv, msg_c2s + X_LEN, ek_len); }
static int op_k_encaps(void *c) { kctx_t *x = c; return wc_MlKemKey_Encapsulate(&kem_srv, ct, ss_k_srv, x->rng); }
static int op_k_decaps(void *c) { (void)c; return wc_MlKemKey_Decapsulate(&kem_cli, ss_k_cli, ct, ct_len); }
static int op_hkdf(void *c)     { (void)c; return combine_hkdf(ss_k_cli, ss_x_cli, key_hkdf_cli); }
static int op_xwing(void *c)    { (void)c; return combine_xwing(ss_k_cli, ss_x_cli, msg_s2c, msg_c2s, key_xw_cli); }

static void measure(const char *scheme, const char *lvl, const char *op, op_fn fn, void *ctx, size_t static_b)
{
    mem_t m;
    mem_measure(scheme, lvl, op, fn, ctx, static_b, &m);
    mem_budget(scheme, lvl, op, fn, ctx, static_b, &m);
    fn(ctx);   /* unconstrained re-run: restores state if a capped run failed midway */
}

static void memory_pass(WC_RNG *rng)
{
    kctx_t c = { rng, 0 };
    const size_t XK = sizeof(curve25519_key), KK = sizeof(MlKemKey);
    printf("\n--- Memory pass (stack, heap, RAM budgets) ---\n");

    wc_curve25519_init(&x_cli); wc_curve25519_init(&x_cli_peer); wc_curve25519_init(&x_srv);
    wc_curve25519_make_key(rng, X_LEN, &x_srv);
    { word32 l = X_LEN; wc_curve25519_export_public_ex(&x_srv, msg_s2c, &l, EC25519_LITTLE_ENDIAN); }
    wc_curve25519_import_public_ex(msg_s2c, X_LEN, &x_cli_peer, EC25519_LITTLE_ENDIAN);
    measure("X25519", "--", "keygen", op_x_keygen, &c, XK);
    measure("X25519", "--", "shared", op_x_shared, &c, 2 * XK + X_LEN);

    for (unsigned k = 0; k < N_KEMS; k++) {
        c.k = k;
        wc_MlKemKey_Init(&kem_cli, KEMS[k].type, NULL, INVALID_DEVID);
        wc_MlKemKey_Init(&kem_srv, KEMS[k].type, NULL, INVALID_DEVID);
        wc_MlKemKey_PublicKeySize(&kem_cli, &ek_len);
        wc_MlKemKey_CipherTextSize(&kem_cli, &ct_len);
        printf("CSV,meta,ml_kem_sizes_%s,ek=%u ct=%u\n", KEMS[k].level, (unsigned)ek_len, (unsigned)ct_len);
        measure(KEMS[k].name, KEMS[k].level, "keygen", op_k_keygen, &c, KK);
        measure(KEMS[k].name, KEMS[k].level, "encode_ek", op_k_encode, &c, KK + ek_len);
        measure(KEMS[k].name, KEMS[k].level, "decode_ek", op_k_decode, &c, KK + ek_len);
        measure(KEMS[k].name, KEMS[k].level, "encaps", op_k_encaps, &c, KK + ct_len + SS_LEN);
        measure(KEMS[k].name, KEMS[k].level, "decaps", op_k_decaps, &c, KK + ct_len + SS_LEN);
        wc_MlKemKey_Free(&kem_cli); wc_MlKemKey_Free(&kem_srv);
    }
    measure("HKDF-SHA256", "--", "combine", op_hkdf, &c, SS_LEN + X_LEN + 32);
    measure("X-Wing-SHA3-256", "--", "combine", op_xwing, &c, SS_LEN + 3 * X_LEN + 32);
    wc_curve25519_free(&x_cli); wc_curve25519_free(&x_cli_peer); wc_curve25519_free(&x_srv);
}

/* ------------------------------------------------------------------------ */
/* Core 1                                                                    */
/* ------------------------------------------------------------------------ */
static void core1_entry(void)
{
    WC_RNG rng;
    int ret;
    char cfg[96];

    snprintf(cfg, sizeof cfg, "rounds=%d warmup=%d%s", KEM_ROUNDS, WARMUP_ROUNDS,
#ifdef WITH_P256
             " p256=1"
#else
             ""
#endif
    );
    meta_print(cfg);
    printf("CSV,meta,sizeof_MlKemKey,%u\n", (unsigned)sizeof(MlKemKey));
    printf("CSV,meta,sizeof_curve25519_key,%u\n", (unsigned)sizeof(curve25519_key));

    if ((ret = heaptrk_install()) != 0) { printf("ERROR: allocator hook (%d)\n", ret); goto halt; }
    ret = wolfCrypt_Init();
    if (ret == 0) ret = wc_InitRng(&rng);
    if (ret != 0) { printf("ERROR: wolfCrypt/RNG init failed (%d)\n", ret); goto halt; }

    for (unsigned k = 0; k < N_KEMS; k++)
        for (int o = 0; o < N_OPS; o++) st_init(&ST[k][o]);

    for (unsigned k = 0; k < N_KEMS; k++) {
        printf("\n[%s / %s]\n", KEMS[k].name, KEMS[k].level);
        for (int i = 0; i < WARMUP_ROUNDS; i++)
            if ((ret = run_round(k, &rng, false, 0)) != 0) { printf("ERROR: warm-up %d\n", ret); goto halt; }
        for (uint32_t i = 0; i < KEM_ROUNDS; i++) {
            if ((ret = run_round(k, &rng, true, i)) != 0) {
                printf("ERROR: %s round %lu: %d%s\n", KEMS[k].name, (unsigned long)i, ret,
                       ret == -9999 ? " (secrets do not match)" : "");
                goto halt;
            }
        }
        printf("  %s: %d rounds ok\n", KEMS[k].name, KEM_ROUNDS);
    }
    print_summary();

#ifdef WITH_P256
    printf("\n[P-256 ECDH]\n");
    bench_p256(&rng);
#endif

    memory_pass(&rng);

    {
        struct mallinfo mi = mallinfo();
        printf("CSV,heap_arena_bytes,all,%u\n", (unsigned)mi.arena);
        printf("CSV,heap_tracked_peak_bytes,all,%u\n", (unsigned)ht.peak);
    }
    wc_FreeRng(&rng);
    printf("\n=== PQC benchmark done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "PQC benchmark start (hybrid X25519 + ML-KEM L1/L3/L5, wolfCrypt)");
}
