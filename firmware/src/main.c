/*
 * Hybrid X25519 + ML-KEM benchmark for the Raspberry Pi Pico (RP2040), wolfCrypt.
 * ML-KEM-512 (L1), ML-KEM-768 (L3) and ML-KEM-1024 (L5). X25519 does not
 * depend on the level and is measured once.
 *
 * Core 0 services USB serial. Core 1 runs the benchmark on a dedicated 64 KB
 * stack, which keeps USB interrupts out of the timed code and allows exact
 * stack measurement.
 */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <malloc.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/rand.h"
#include "hardware/clocks.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#define WARMUP_ROUNDS      1
#define ROUNDS             20
#define CORE1_STACK_WORDS  (64 * 1024 / 4)
#define PAINT              0xC0FFEE11u
#define SS_LEN             32
#define CT_MAX             1568   /* ML-KEM-1024 ciphertext, the largest here */

static uint32_t core1_stack[CORE1_STACK_WORDS];

/* ML-KEM levels under test */
typedef struct {
    const char *name;   /* e.g. "ML-KEM-768" */
    const char *level;  /* NIST level tag: "L1"/"L3"/"L5" */
    int         type;   /* WC_ML_KEM_512 / _768 / _1024 */
} kem_param_t;

static const kem_param_t KEMS[] = {
    { "ML-KEM-512",  "L1", WC_ML_KEM_512  },
    { "ML-KEM-768",  "L3", WC_ML_KEM_768  },
    { "ML-KEM-1024", "L5", WC_ML_KEM_1024 },
};
#define N_KEMS (sizeof(KEMS)/sizeof(KEMS[0]))

/* Entropy hook for wolfCrypt */
int pico_rng_seed(unsigned char *out, unsigned int sz)
{
    while (sz > 0) {
        uint32_t r = get_rand_32();
        unsigned int n = (sz < 4) ? sz : 4;
        memcpy(out, &r, n);
        out += n;
        sz  -= n;
    }
    return 0;
}

/* Statistics */
typedef struct { uint64_t sum, min, max; uint32_t n; } stat_t;

static void stat_init(stat_t *s) { s->sum = 0; s->min = UINT64_MAX; s->max = 0; s->n = 0; }
static void stat_add(stat_t *s, uint64_t us)
{
    s->sum += us;
    if (us < s->min) s->min = us;
    if (us > s->max) s->max = us;
    s->n++;
}
static uint64_t stat_avg(const stat_t *s) { return s->n ? s->sum / s->n : 0; }

/* X25519 baseline (level-independent) */
static stat_t x_keygen, x_dh;

/* Per-level ML-KEM and hybrid stats */
static stat_t kem_keygen[N_KEMS], kem_encaps[N_KEMS], kem_decaps[N_KEMS];
static stat_t hyb_ckeygen[N_KEMS], hyb_sencaps[N_KEMS], hyb_cdecaps[N_KEMS];

/* Crypto objects (static: not counted as stack) */
static curve25519_key x_client, x_server;
static MlKemKey       kem;
static uint8_t        ct[CT_MAX], ss_enc[SS_LEN], ss_dec[SS_LEN];
static uint8_t        xss_client[CURVE25519_KEYSIZE], xss_server[CURVE25519_KEYSIZE];

#define TIMED(dst, call) do { uint64_t t0_ = time_us_64(); ret = (call); \
                              (dst) = time_us_64() - t0_; } while (0)

/* One hybrid round at a given ML-KEM level. record==false for warm-up. */
static int run_round(int k, WC_RNG *rng, bool record)
{
    int ret;
    word32 ct_len = 0;
    word32 len_c = sizeof(xss_client), len_s = sizeof(xss_server);
    uint64_t xkg_c = 0, xkg_s = 0, xdh_s = 0, xdh_c = 0, kkg = 0, kenc = 0, kdec = 0;

    wc_curve25519_init(&x_client);
    wc_curve25519_init(&x_server);
    ret = wc_MlKemKey_Init(&kem, KEMS[k].type, NULL, INVALID_DEVID);
    if (ret != 0) goto out;

    /* Client: hybrid key generation */
    TIMED(xkg_c, wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &x_client));            if (ret) goto out;
    TIMED(kkg,   wc_MlKemKey_MakeKey(&kem, rng));                                         if (ret) goto out;

    /* Server: ephemeral X25519 + shared secret + ML-KEM encapsulation */
    TIMED(xkg_s, wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &x_server));            if (ret) goto out;
    TIMED(xdh_s, wc_curve25519_shared_secret(&x_server, &x_client, xss_server, &len_s)); if (ret) goto out;
    TIMED(kenc,  wc_MlKemKey_Encapsulate(&kem, ct, ss_enc, rng));                         if (ret) goto out;

    /* Client: X25519 shared secret + ML-KEM decapsulation */
    ret = wc_MlKemKey_CipherTextSize(&kem, &ct_len);                                      if (ret) goto out;
    TIMED(xdh_c, wc_curve25519_shared_secret(&x_client, &x_server, xss_client, &len_c)); if (ret) goto out;
    TIMED(kdec,  wc_MlKemKey_Decapsulate(&kem, ss_dec, ct, ct_len));                      if (ret) goto out;

    /* Correctness: both sides must derive identical secrets */
    if (len_c != len_s || memcmp(xss_client, xss_server, len_c) != 0 ||
        memcmp(ss_enc, ss_dec, SS_LEN) != 0) {
        ret = -9999;
        goto out;
    }

    if (record) {
        /* X25519 is identical across levels; record it only on the first level
         * so its sample count is not triple-counted. */
        if (k == 0) {
            stat_add(&x_keygen, xkg_c); stat_add(&x_keygen, xkg_s);
            stat_add(&x_dh, xdh_s);     stat_add(&x_dh, xdh_c);
        }
        stat_add(&kem_keygen[k], kkg);
        stat_add(&kem_encaps[k], kenc);
        stat_add(&kem_decaps[k], kdec);
        stat_add(&hyb_ckeygen[k], xkg_c + kkg);
        stat_add(&hyb_sencaps[k], xkg_s + xdh_s + kenc);
        stat_add(&hyb_cdecaps[k], xdh_c + kdec);
    }

out:
    wc_MlKemKey_Free(&kem);
    wc_curve25519_free(&x_client);
    wc_curve25519_free(&x_server);
    return ret;
}

static void row(const char *label, const stat_t *s)
{
    printf("  %-28s %10llu %10llu %10llu\n", label,
           (unsigned long long)stat_avg(s),
           (unsigned long long)s->min, (unsigned long long)s->max);
}
static void csv(const char *tag, const char *lvl, const char *op, const stat_t *s)
{
    printf("CSV,%s,%s,%s,%lu,%llu,%llu,%llu\n", tag, lvl, op,
           (unsigned long)s->n, (unsigned long long)stat_avg(s),
           (unsigned long long)s->min, (unsigned long long)s->max);
}

static void print_results(void)
{
    printf("\n--- Latency over %d rounds (microseconds) ---\n", ROUNDS);
    printf("  %-28s %10s %10s %10s\n", "operation", "avg", "min", "max");

    row("X25519 keygen", &x_keygen);
    row("X25519 shared secret", &x_dh);

    for (unsigned k = 0; k < N_KEMS; k++) {
        char lbl[48];
        printf("  --- %s (%s) ---\n", KEMS[k].name, KEMS[k].level);
        snprintf(lbl, sizeof lbl, "%s keygen", KEMS[k].name); row(lbl, &kem_keygen[k]);
        snprintf(lbl, sizeof lbl, "%s encaps", KEMS[k].name); row(lbl, &kem_encaps[k]);
        snprintf(lbl, sizeof lbl, "%s decaps", KEMS[k].name); row(lbl, &kem_decaps[k]);
        snprintf(lbl, sizeof lbl, "Hybrid client keygen");    row(lbl, &hyb_ckeygen[k]);
        snprintf(lbl, sizeof lbl, "Hybrid server encaps");    row(lbl, &hyb_sencaps[k]);
        snprintf(lbl, sizeof lbl, "Hybrid client decaps");    row(lbl, &hyb_cdecaps[k]);
    }

    /* Machine-readable block. tag=latency_us, then level, operation, n, avg, min, max */
    csv("latency_us", "--", "X25519 keygen", &x_keygen);
    csv("latency_us", "--", "X25519 shared secret", &x_dh);
    for (unsigned k = 0; k < N_KEMS; k++) {
        const char *L = KEMS[k].level;
        csv("latency_us", L, "kem_keygen",   &kem_keygen[k]);
        csv("latency_us", L, "kem_encaps",   &kem_encaps[k]);
        csv("latency_us", L, "kem_decaps",   &kem_decaps[k]);
        csv("latency_us", L, "hybrid_client_keygen", &hyb_ckeygen[k]);
        csv("latency_us", L, "hybrid_server_encaps", &hyb_sencaps[k]);
        csv("latency_us", L, "hybrid_client_decaps", &hyb_cdecaps[k]);
    }
}

/* Stack measurement (stack painting on core 1) */
static __attribute__((noinline)) uint32_t *stack_ref(void)
{
    return (uint32_t *)((uintptr_t)__builtin_frame_address(0) & ~(uintptr_t)3);
}
static __attribute__((noinline)) void stack_paint(uint32_t *ref)
{
    for (uint32_t *p = core1_stack; p < ref - 128; p++)   /* stay 512 B below live frames */
        *p = PAINT;
}
static uint32_t stack_depth(uint32_t *ref)
{
    uint32_t *p = core1_stack;
    while (p < ref && *p == PAINT) p++;
    return (uint32_t)((ref - p) * 4);
}

#define STACK_OP(lvl, label, call) do {                                         \
    uint32_t *ref_ = stack_ref();                                               \
    stack_paint(ref_);                                                          \
    int r_ = (call);                                                            \
    uint32_t d_ = stack_depth(ref_);                                            \
    bool full_ = (d_ >= (uint32_t)((ref_ - core1_stack) * 4));                  \
    printf("  %-28s %6" PRIu32 " B%s%s\n", label, d_,                           \
           r_ ? "  (ERROR)" : "", full_ ? "  (STACK EXHAUSTED)" : "");          \
    printf("CSV,stack_bytes,%s,%s,%" PRIu32 "\n", lvl, label, d_);              \
} while (0)

static void memory_pass(WC_RNG *rng)
{
    word32 len = sizeof(xss_client);

    printf("\n--- Peak stack per operation ---\n");

    wc_curve25519_init(&x_client);
    wc_curve25519_init(&x_server);
    STACK_OP("--", "X25519 keygen",
             wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &x_client));
    wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &x_server);
    STACK_OP("--", "X25519 shared secret",
             wc_curve25519_shared_secret(&x_client, &x_server, xss_client, &len));
    wc_curve25519_free(&x_client);
    wc_curve25519_free(&x_server);

    for (unsigned k = 0; k < N_KEMS; k++) {
        char lbl[48];
        word32 ct_len = 0;
        if (wc_MlKemKey_Init(&kem, KEMS[k].type, NULL, INVALID_DEVID) != 0) {
            printf("  %s init failed\n", KEMS[k].name);
            continue;
        }
        snprintf(lbl, sizeof lbl, "%s keygen", KEMS[k].name);
        STACK_OP(KEMS[k].level, lbl, wc_MlKemKey_MakeKey(&kem, rng));
        snprintf(lbl, sizeof lbl, "%s encaps", KEMS[k].name);
        STACK_OP(KEMS[k].level, lbl, wc_MlKemKey_Encapsulate(&kem, ct, ss_enc, rng));
        wc_MlKemKey_CipherTextSize(&kem, &ct_len);
        snprintf(lbl, sizeof lbl, "%s decaps", KEMS[k].name);
        STACK_OP(KEMS[k].level, lbl, wc_MlKemKey_Decapsulate(&kem, ss_dec, ct, ct_len));
        wc_MlKemKey_Free(&kem);
    }
}

/* Core 1: benchmark */
static void core1_entry(void)
{
    WC_RNG rng;
    int ret;

    printf("wolfSSL %s | clk_sys %" PRIu32 " Hz | %d rounds + %d warm-up | levels: L1/L3/L5\n",
           LIBWOLFSSL_VERSION_STRING, clock_get_hz(clk_sys), ROUNDS, WARMUP_ROUNDS);
    printf("sizeof(MlKemKey) = %u B, sizeof(curve25519_key) = %u B\n",
           (unsigned)sizeof(MlKemKey), (unsigned)sizeof(curve25519_key));

    ret = wolfCrypt_Init();
    if (ret == 0) ret = wc_InitRng(&rng);
    if (ret != 0) { printf("ERROR: wolfCrypt/RNG init failed (%d)\n", ret); goto halt; }

    stat_init(&x_keygen); stat_init(&x_dh);
    for (unsigned k = 0; k < N_KEMS; k++) {
        stat_init(&kem_keygen[k]); stat_init(&kem_encaps[k]); stat_init(&kem_decaps[k]);
        stat_init(&hyb_ckeygen[k]); stat_init(&hyb_sencaps[k]); stat_init(&hyb_cdecaps[k]);
    }

    for (unsigned k = 0; k < N_KEMS; k++) {
        printf("\n[%s / %s]\n", KEMS[k].name, KEMS[k].level);

        for (int i = 0; i < WARMUP_ROUNDS; i++) {
            ret = run_round(k, &rng, false);
            if (ret) { printf("ERROR: %s warm-up failed: %d\n", KEMS[k].name, ret); goto halt; }
        }
        for (int i = 1; i <= ROUNDS; i++) {
            ret = run_round(k, &rng, true);
            if (ret) {
                printf("ERROR: %s round %d: %d%s\n", KEMS[k].name, i, ret,
                       ret == -9999 ? " (shared secrets do not match)" : "");
                goto halt;
            }
        }
        printf("  %s: %d rounds ok\n", KEMS[k].name, ROUNDS);
    }

    print_results();
    memory_pass(&rng);

    struct mallinfo mi = mallinfo();
    printf("\n--- Heap ---\n");
    printf("  arena high-water (upper bound on peak heap): %u B\n", (unsigned)mi.arena);
    printf("CSV,heap_arena_bytes,all,%u\n", (unsigned)mi.arena);

    wc_FreeRng(&rng);
    printf("\n=== PQC benchmark done ===\n");
halt:
    while (true) tight_loop_contents();
}

/* Core 0: USB serial */
int main(void)
{
    stdio_init_all();
    while (!stdio_usb_connected()) {
        sleep_ms(100);
    }
    sleep_ms(1000);
    printf("\n=== PQC benchmark start (X25519 + ML-KEM L1/L3/L5, wolfCrypt) ===\n");

    multicore_launch_core1_with_stack(core1_entry, core1_stack, sizeof(core1_stack));

    while (true) {
        sleep_ms(1000);
    }
}
