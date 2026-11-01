/*
 * ML-DSA signing-time distribution on the RP2040 (Reviewer 4 point 1,
 * Reviewer 2 point 4). For each of ML-DSA-44/65/87:
 *   - BENCH_MLDSA_SAMPLES signatures (default 10,000; named so it cannot clash
 *     with wolfCrypt's MLDSA_N, the polynomial degree 256), each on a fresh random 32-byte
 *     message with hedged (randomised) signing;
 *   - a new key pair every MLDSA_KEY_EVERY signatures (default 100), so the
 *     distribution covers many keys;
 *   - every signature is verified (correctness) and its verification timed;
 *   - Ed25519 signs and verifies the same message in the same iteration, so
 *     the hybrid signing distribution is measured, not reconstructed.
 * Every sample is printed as a RAW line; analysis computes the median, p95,
 * p99, p99.9, observed maximum and bootstrap confidence intervals.
 *
 * Runtime at the submitted means (sign + verify + paired Ed25519 per sample):
 * about 1.4 h (L2), 2.5 h (L3) and 2.3 h (L5), roughly 6 h in total.
 * Target pqc_mldsa_dist_speed builds the speed-oriented (non-low-memory)
 * configuration with 1,000 samples per level (enough to compare medians with
 * the low-memory build); ML-DSA-87 is expected to run out of memory there,
 * which is logged.
 */
#define FW_NAME            "mldsa_dist"
#define CORE1_STACK_WORDS  (40 * 1024 / 4)
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

#ifndef BENCH_MLDSA_SAMPLES
#define BENCH_MLDSA_SAMPLES           10000
#endif
#ifndef MLDSA_KEY_EVERY
#define MLDSA_KEY_EVERY   100
#endif
#define MSG_LEN           32
#define SIG_MAX           4627    /* ML-DSA-87 */

static const struct { const char *name, *lvl; byte level; } MLDSA[] = {
    { "ML-DSA-44", "L2", WC_ML_DSA_44 },
    { "ML-DSA-65", "L3", WC_ML_DSA_65 },
    { "ML-DSA-87", "L5", WC_ML_DSA_87 },
};

static wc_MlDsaKey key;
static ed25519_key ek;
static uint8_t msg[MSG_LEN], sig[SIG_MAX], esig[ED25519_SIG_SIZE];

static int run_level(unsigned m, WC_RNG *rng)
{
    int ret = 0, res;
    uint32_t keyno = 0;
    char hyb[32]; snprintf(hyb, sizeof hyb, "Ed25519+%s", MLDSA[m].name);
    printf("\n[%s] %d signatures, new key every %d\n", MLDSA[m].name, BENCH_MLDSA_SAMPLES, MLDSA_KEY_EVERY);

    for (int32_t i = -1; i < BENCH_MLDSA_SAMPLES; i++) {          /* i = -1: warm-up */
        uint64_t t_sg, t_vf, t_esg, t_evf, t_kg, t_ekg;
        word32 sl = SIG_MAX, esl = ED25519_SIG_SIZE;

        if (i < 0 || (i % MLDSA_KEY_EVERY) == 0) {
            if (i > 0) { wc_MlDsaKey_Free(&key); wc_ed25519_free(&ek); }
            if ((ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID)) != 0) return ret;
            if ((ret = wc_MlDsaKey_SetParams(&key, MLDSA[m].level)) != 0) return ret;
            wc_ed25519_init(&ek);
            /* Ed25519 first: its small allocations then sit below the ML-DSA keygen
             * scratch, which is freed at the top of the heap and can be reused by the
             * large signing allocation (the speed build signs with one ~121 KB block). */
            TIMED(t_ekg, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek)); if (ret) return ret;
            TIMED(t_kg, wc_MlDsaKey_MakeKey(&key, rng));
            if (ret) { printf("CSV,mldsa_dist_error,%s,keygen,%ld,%d\n", MLDSA[m].name, (long)i, ret); return ret; }
            if (i >= 0) {
                raw(MLDSA[m].name, MLDSA[m].lvl, "keygen", keyno, t_kg);
                raw(hyb, MLDSA[m].lvl, "keygen", keyno, t_kg + t_ekg);
                keyno++;
            }
        }
        wc_RNG_GenerateBlock(rng, msg, MSG_LEN);

        TIMED(t_esg, wc_ed25519_sign_msg(msg, MSG_LEN, esig, &esl, &ek));               if (ret) return ret;
        TIMED(t_sg,  wc_MlDsaKey_SignCtx(&key, NULL, 0, sig, &sl, msg, MSG_LEN, rng));
        if (ret) { printf("CSV,mldsa_dist_error,%s,sign,%ld,%d\n", MLDSA[m].name, (long)i, ret); return ret; }
        res = 0;
        TIMED(t_evf, wc_ed25519_verify_msg(esig, esl, msg, MSG_LEN, &res, &ek));        if (ret || !res) return -9003;
        res = 0;
        TIMED(t_vf,  wc_MlDsaKey_VerifyCtx(&key, sig, sl, NULL, 0, msg, MSG_LEN, &res)); if (ret || !res) return -9002;

        if (i < 0) continue;
        raw(MLDSA[m].name, MLDSA[m].lvl, "sign", i, t_sg);
        raw(MLDSA[m].name, MLDSA[m].lvl, "verify", i, t_vf);
        raw(hyb, MLDSA[m].lvl, "sign", i, t_sg + t_esg);
        raw(hyb, MLDSA[m].lvl, "verify", i, t_vf + t_evf);
        raw(hyb, MLDSA[m].lvl, "ed_sign", i, t_esg);
        raw(hyb, MLDSA[m].lvl, "ed_verify", i, t_evf);
    }
    wc_MlDsaKey_Free(&key); wc_ed25519_free(&ek);
    printf("CSV,mldsa_dist_done,%s,%d,%d\n", MLDSA[m].name, BENCH_MLDSA_SAMPLES, ret);
    return 0;
}

static void core1_entry(void)
{
    WC_RNG rng; int ret;
    char cfg[96];
    snprintf(cfg, sizeof cfg, "n=%d key_every=%d mldsa_build=%s", BENCH_MLDSA_SAMPLES, MLDSA_KEY_EVERY,
#ifdef MLDSA_SPEED
             "speed"
#else
             "small_mem"
#endif
    );
    meta_print(cfg);
    if ((ret = heaptrk_install()) != 0 || (ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) {
        printf("ERROR: init failed (%d)\n", ret); goto halt;
    }
    for (unsigned m = 0; m < sizeof MLDSA / sizeof MLDSA[0]; m++) {
        heaptrk_reset_peak();
        size_t base = ht.cur;
        ret = run_level(m, &rng);
        if (ret) { wc_MlDsaKey_Free(&key); wc_ed25519_free(&ek); }
        printf("CSV,mldsa_dist_heap,%s,%u,%" PRIu32 ",%u,%d\n", MLDSA[m].name,
               (unsigned)(ht.peak - base), ht.fails, (unsigned)ht.largest_fail, ret);
        if (ret) printf("  %s stopped with error %d\n", MLDSA[m].name, ret);
    }
    wc_FreeRng(&rng);
    printf("\n=== ML-DSA distribution done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "ML-DSA signing-time distribution (paired Ed25519)");
}
