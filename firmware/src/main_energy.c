/*
 * Energy calibration (Reviewer 1 point 5, Reviewer 2 point 5, Reviewer 3
 * point 2). Runs a fixed list of operations, ENERGY_REPS times each, with the
 * trigger GPIO held high only while the operation executes, ENERGY_GAP_MS of
 * idle between repetitions and 1 s between operations. An external meter
 * (e.g. Nordic PPK2 in source mode with its logic input on the trigger pin)
 * records current; analysis/energy_from_trace.py integrates the current over
 * each high pulse and maps pulses to the ENERGY lines below by order.
 * The idle gaps give the baseline current, and the per-operation results are
 * compared with the constant-power datasheet model used in Table 6.
 *
 * Output: ENERGY,<seq>,<op>,<rep>,<us>   (seq = global pulse index from 0)
 * Requires -DTRIG_GPIO=<pin> (target pqc_energy defaults to GPIO 15).
 */
#define FW_NAME            "energy"
#define CORE1_STACK_WORDS  (40 * 1024 / 4)
#ifndef TRIG_GPIO
#define TRIG_GPIO 15
#endif
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include "falcon_ext_keys.h"

#ifndef ENERGY_REPS
#define ENERGY_REPS   20
#endif
#ifndef ENERGY_GAP_MS
#define ENERGY_GAP_MS 50
#endif

static WC_RNG rng;
static curve25519_key xa, xb;
static ed25519_key ek;
static MlKemKey kem;
static wc_MlDsaKey dk;
static falcon_key fk;
static SlhDsaKey sk;
static uint8_t m[32], sig[17088], ct[1568], ss[32], xs[32];
static word32 sl, ctl;
static uint32_t seq;

typedef int (*efn)(void);
static int e_x_kg(void)  { return wc_curve25519_make_key(&rng, 32, &xa); }
static int e_x_dh(void)  { word32 l = 32; return wc_curve25519_shared_secret(&xa, &xb, xs, &l); }
static int e_k_kg(void)  { return wc_MlKemKey_MakeKey(&kem, &rng); }
static int e_k_enc(void) { return wc_MlKemKey_Encapsulate(&kem, ct, ss, &rng); }
static int e_k_dec(void) { return wc_MlKemKey_Decapsulate(&kem, ss, ct, ctl); }
static int e_ed_kg(void) { return wc_ed25519_make_key(&rng, 32, &ek); }
static int e_ed_sg(void) { sl = 64; return wc_ed25519_sign_msg(m, 32, sig, &sl, &ek); }
static int e_ed_vf(void) { int r = 0; int ret = wc_ed25519_verify_msg(sig, 64, m, 32, &r, &ek); return ret ? ret : !r; }
static int e_d_kg(void)  { return wc_MlDsaKey_MakeKey(&dk, &rng); }
static int e_d_sg(void)  { sl = sizeof sig; return wc_MlDsaKey_SignCtx(&dk, NULL, 0, sig, &sl, m, 32, &rng); }
static int e_d_vf(void)  { int r = 0; int ret = wc_MlDsaKey_VerifyCtx(&dk, sig, sl, NULL, 0, m, 32, &r); return ret ? ret : !r; }
static int e_f_sg(void)  { sl = sizeof sig; return wc_falcon_sign_msg(m, 32, sig, &sl, &fk, &rng); }
static int e_f_vf(void)  { int r = 0; int ret = wc_falcon_verify_msg(sig, sl, m, 32, &r, &fk); return ret ? ret : !r; }
static int e_s_sg(void)  { sl = sizeof sig; return wc_SlhDsaKey_Sign(&sk, NULL, 0, m, 32, sig, &sl, &rng); }
static int e_s_vf(void)  { return wc_SlhDsaKey_Verify(&sk, NULL, 0, m, 32, sig, sl); }

/* Run one op ENERGY_REPS times (plus one untriggered warm-up). */
static void run(const char *name, efn f, int reps)
{
    int ret = f();   /* warm-up, no pulse */
    if (ret) { printf("CSV,energy_error,%s,%d\n", name, ret); return; }
    sleep_ms(1000);
    for (int i = 0; i < reps; i++) {
        uint64_t us;
        TIMED(us, f());
        if (ret) { printf("CSV,energy_error,%s,%d\n", name, ret); return; }
        printf("ENERGY,%" PRIu32 ",%s,%d,%llu\n", seq++, name, i, (unsigned long long)us);
        sleep_ms(ENERGY_GAP_MS);
    }
}

static void core1_entry(void)
{
    int ret;
    char cfg[64]; snprintf(cfg, sizeof cfg, "reps=%d gap_ms=%d", ENERGY_REPS, ENERGY_GAP_MS);
    meta_print(cfg);
    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) { printf("ERROR init %d\n", ret); goto halt; }
    for (int i = 0; i < 32; i++) m[i] = (uint8_t)i;
    printf("CSV,energy_idle_start\n");
    sleep_ms(5000);                       /* 5 s idle reference at the start */
    printf("CSV,energy_idle_end\n");

    wc_curve25519_init(&xa); wc_curve25519_init(&xb);
    wc_curve25519_make_key(&rng, 32, &xb);
    run("X25519 keygen", e_x_kg, ENERGY_REPS);
    run("X25519 shared", e_x_dh, ENERGY_REPS);

    static const struct { const char *n; int t; } K[] = {
        { "ML-KEM-512", WC_ML_KEM_512 }, { "ML-KEM-768", WC_ML_KEM_768 }, { "ML-KEM-1024", WC_ML_KEM_1024 } };
    for (unsigned k = 0; k < 3; k++) {
        char nm[48];
        wc_MlKemKey_Init(&kem, K[k].t, NULL, INVALID_DEVID);
        wc_MlKemKey_CipherTextSize(&kem, &ctl);
        snprintf(nm, sizeof nm, "%s keygen", K[k].n); run(nm, e_k_kg, ENERGY_REPS);
        snprintf(nm, sizeof nm, "%s encaps", K[k].n); run(nm, e_k_enc, ENERGY_REPS);
        snprintf(nm, sizeof nm, "%s decaps", K[k].n); run(nm, e_k_dec, ENERGY_REPS);
        wc_MlKemKey_Free(&kem);
    }

    wc_ed25519_init(&ek);
    run("Ed25519 keygen", e_ed_kg, ENERGY_REPS);
    run("Ed25519 sign", e_ed_sg, ENERGY_REPS);
    run("Ed25519 verify", e_ed_vf, ENERGY_REPS);

    static const struct { const char *n; byte l; } D[] = {
        { "ML-DSA-44", WC_ML_DSA_44 }, { "ML-DSA-65", WC_ML_DSA_65 }, { "ML-DSA-87", WC_ML_DSA_87 } };
    for (unsigned d = 0; d < 3; d++) {
        char nm[48];
        wc_MlDsaKey_Init(&dk, NULL, INVALID_DEVID); wc_MlDsaKey_SetParams(&dk, D[d].l);
        snprintf(nm, sizeof nm, "%s keygen", D[d].n); run(nm, e_d_kg, ENERGY_REPS);
        snprintf(nm, sizeof nm, "%s sign", D[d].n);   run(nm, e_d_sg, ENERGY_REPS);
        snprintf(nm, sizeof nm, "%s verify", D[d].n); run(nm, e_d_vf, ENERGY_REPS);
        wc_MlDsaKey_Free(&dk);
    }

    wc_falcon_init(&fk); wc_falcon_set_level(&fk, FALCON_LEVEL1);
    wc_falcon_import_private_key(FALCON512_PRIV, sizeof FALCON512_PRIV, FALCON512_PUB, sizeof FALCON512_PUB, &fk);
    run("Falcon-512 sign", e_f_sg, ENERGY_REPS);
    run("Falcon-512 verify", e_f_vf, ENERGY_REPS);
    wc_falcon_free(&fk);

    wc_SlhDsaKey_Init(&sk, SLHDSA_SHA2_128F, NULL, INVALID_DEVID);
    wc_SlhDsaKey_MakeKey(&sk, &rng);
    run("SLH-DSA-SHA2-128f sign", e_s_sg, 5);
    run("SLH-DSA-SHA2-128f verify", e_s_vf, ENERGY_REPS);
    wc_SlhDsaKey_Free(&sk);

    printf("CSV,energy_pulses,%" PRIu32 "\n", seq);
    printf("\n=== energy calibration done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "Energy calibration (trigger on GPIO)");
}
