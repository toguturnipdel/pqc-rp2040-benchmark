/*
 * Classical-component sensitivity (Reviewer 1 point 1, Reviewer 2 point 2,
 * Reviewer 4 point 3): how much of the hybrid key-exchange cost is due to the
 * X25519 implementation?
 *
 * Measures, on the same board and clock:
 *   A. wolfCrypt X25519 (the library's portable C, as in the main benchmark;
 *      build target pqc_x25519_alt_small uses wolfCrypt's CURVED25519_SMALL
 *      implementation instead)
 *   B. x25519-cm0 (Pornin, ARMv6-M assembly) executing in place from flash
 *   C. x25519-cm0 executing from SRAM
 * Correctness: RFC 7748 section 5.2 test vector for x25519-cm0, and a
 * cross-implementation Diffie-Hellman agreement check (cm0 <-> wolfCrypt).
 * Then a full hybrid exchange at L1/L3/L5 with X25519 from (C) and ML-KEM
 * from wolfCrypt, timed per role.
 */
#define FW_NAME            "x25519_alt"
#define CORE1_STACK_WORDS  (32 * 1024 / 4)
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#ifndef X_ROUNDS
#define X_ROUNDS 100
#endif

/* Generated from third_party/x25519-cm0/x25519-cm0.S by CMake */
void x25519_cm0_flash(void *dst, const void *src, const void *scalar);
void x25519_cm0_ram(void *dst, const void *src, const void *scalar);

#ifdef CURVE_SMALL
#define WOLF_IMPL "wolfCrypt-CURVED25519_SMALL(fe_low_mem.c)"
#else
#define WOLF_IMPL "wolfCrypt-default(fe_operations.c)"
#endif

static const uint8_t BASE[32] = { 9 };

/* RFC 7748 section 5.2, first test vector */
static const uint8_t TV_K[32] = {
    0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,0x82,0x46,0x5e,0xdd,
    0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4 };
static const uint8_t TV_U[32] = {
    0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,0x24,0xb1,0x5f,0x7c,
    0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c };
static const uint8_t TV_OUT[32] = {
    0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,0xf2,0x8d,0x08,0x4f,
    0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52 };

static curve25519_key wk, wpeer;
static MlKemKey kem_c, kem_s;
static uint8_t ct[1568], ssc[32], sss[32];

static int self_test(WC_RNG *rng)
{
    uint8_t out[32], a[32], A[32], B[32], s1[32], s2[32];
    word32 l = 32;
    int ret;
    x25519_cm0_flash(out, TV_U, TV_K);
    if (memcmp(out, TV_OUT, 32)) { printf("cm0 flash: RFC 7748 vector FAILED\n"); return -1; }
    x25519_cm0_ram(out, TV_U, TV_K);
    if (memcmp(out, TV_OUT, 32)) { printf("cm0 ram: RFC 7748 vector FAILED\n"); return -1; }

    /* DH agreement: cm0 party a, wolfCrypt party b */
    wc_RNG_GenerateBlock(rng, a, 32);
    x25519_cm0_ram(A, BASE, a);
    wc_curve25519_init(&wk); wc_curve25519_init(&wpeer);
    if ((ret = wc_curve25519_make_key(rng, 32, &wk)) != 0) return ret;
    l = 32; wc_curve25519_export_public_ex(&wk, B, &l, EC25519_LITTLE_ENDIAN);
    x25519_cm0_ram(s1, B, a);
    wc_curve25519_import_public_ex(A, 32, &wpeer, EC25519_LITTLE_ENDIAN);
    l = 32;
    if ((ret = wc_curve25519_shared_secret_ex(&wk, &wpeer, s2, &l, EC25519_LITTLE_ENDIAN)) != 0) return ret;
    wc_curve25519_free(&wk); wc_curve25519_free(&wpeer);
    if (memcmp(s1, s2, 32)) { printf("cm0 <-> wolfCrypt DH agreement FAILED\n"); return -2; }
    printf("  self-test ok (RFC 7748 vector, cm0 <-> wolfCrypt agreement)\n");
    printf("CSV,x25519_selftest,ok\n");
    return 0;
}

static void bench_scalar_mults(WC_RNG *rng)
{
    int ret;
    uint8_t s[32], p[32], out[32], pub[32];
    stat_t a, b, c, d; st_init(&a); st_init(&b); st_init(&c); st_init(&d);
    for (int i = -1; i < X_ROUNDS; i++) {
        uint64_t t1, t2, t3, t4; word32 l = 32;
        wc_RNG_GenerateBlock(rng, s, 32);
        wc_curve25519_init(&wk); wc_curve25519_init(&wpeer);
        TIMED(t1, wc_curve25519_make_key(rng, 32, &wk));                                    if (ret) return;
        l = 32; wc_curve25519_export_public_ex(&wk, pub, &l, EC25519_LITTLE_ENDIAN);
        x25519_cm0_ram(p, BASE, s);
        wc_curve25519_import_public_ex(p, 32, &wpeer, EC25519_LITTLE_ENDIAN);
        l = 32;
        TIMED(t2, wc_curve25519_shared_secret_ex(&wk, &wpeer, out, &l, EC25519_LITTLE_ENDIAN)); if (ret) return;
        wc_curve25519_free(&wk); wc_curve25519_free(&wpeer);
        trig_on(); { uint64_t t0 = time_us_64(); x25519_cm0_flash(out, pub, s); t3 = time_us_64() - t0; } trig_off();
        trig_on(); { uint64_t t0 = time_us_64(); x25519_cm0_ram(out, pub, s);   t4 = time_us_64() - t0; } trig_off();
        if (i < 0) continue;
        st_add(&a, t1); st_add(&b, t2); st_add(&c, t3); st_add(&d, t4);
        raw(WOLF_IMPL, "--", "keygen", i, t1);
        raw(WOLF_IMPL, "--", "shared", i, t2);
        raw("x25519-cm0-flash", "--", "scalarmult", i, t3);
        raw("x25519-cm0-sram",  "--", "scalarmult", i, t4);
    }
    printf("  %-44s mean %8llu us\n", WOLF_IMPL " keygen", (unsigned long long)st_avg(&a));
    printf("  %-44s mean %8llu us\n", WOLF_IMPL " shared", (unsigned long long)st_avg(&b));
    printf("  %-44s mean %8llu us\n", "x25519-cm0 (flash/XIP)", (unsigned long long)st_avg(&c));
    printf("  %-44s mean %8llu us\n", "x25519-cm0 (SRAM)", (unsigned long long)st_avg(&d));
}

/* Full hybrid exchange with x25519-cm0 (SRAM) + wolfCrypt ML-KEM */
static const struct { const char *name, *lvl; int type; } KEMS[] = {
    { "X25519cm0+ML-KEM-512", "L1", WC_ML_KEM_512 },
    { "X25519cm0+ML-KEM-768", "L3", WC_ML_KEM_768 },
    { "X25519cm0+ML-KEM-1024", "L5", WC_ML_KEM_1024 },
};
static void bench_hybrid_cm0(WC_RNG *rng)
{
    int ret;
    for (unsigned k = 0; k < 3; k++) {
        for (int i = -1; i < X_ROUNDS; i++) {
            uint8_t a[32], b[32], A[32], B[32], sa[32], sb[32];
            uint64_t t_axkg, t_kkg, t_bxkg, t_bxdh, t_enc, t_axdh, t_dec;
            word32 ctl = 0;
            wc_RNG_GenerateBlock(rng, a, 32); wc_RNG_GenerateBlock(rng, b, 32);
            wc_MlKemKey_Init(&kem_c, KEMS[k].type, NULL, INVALID_DEVID);
            wc_MlKemKey_Init(&kem_s, KEMS[k].type, NULL, INVALID_DEVID);
            wc_MlKemKey_CipherTextSize(&kem_c, &ctl);
            uint8_t ek[1568]; word32 ekl = 0; wc_MlKemKey_PublicKeySize(&kem_c, &ekl);

            trig_on(); { uint64_t t0 = time_us_64(); x25519_cm0_ram(A, BASE, a); t_axkg = time_us_64() - t0; } trig_off();
            TIMED(t_kkg, wc_MlKemKey_MakeKey(&kem_c, rng));                        if (ret) goto e;
            wc_MlKemKey_EncodePublicKey(&kem_c, ek, ekl);
            wc_MlKemKey_DecodePublicKey(&kem_s, ek, ekl);
            trig_on(); { uint64_t t0 = time_us_64(); x25519_cm0_ram(B, BASE, b); t_bxkg = time_us_64() - t0; } trig_off();
            trig_on(); { uint64_t t0 = time_us_64(); x25519_cm0_ram(sb, A, b);   t_bxdh = time_us_64() - t0; } trig_off();
            TIMED(t_enc, wc_MlKemKey_Encapsulate(&kem_s, ct, sss, rng));            if (ret) goto e;
            trig_on(); { uint64_t t0 = time_us_64(); x25519_cm0_ram(sa, B, a);   t_axdh = time_us_64() - t0; } trig_off();
            TIMED(t_dec, wc_MlKemKey_Decapsulate(&kem_c, ssc, ct, ctl));            if (ret) goto e;
            if (memcmp(sa, sb, 32) || memcmp(ssc, sss, 32)) { ret = -9999; goto e; }
            wc_MlKemKey_Free(&kem_c); wc_MlKemKey_Free(&kem_s);
            if (i < 0) continue;
            raw(KEMS[k].name, KEMS[k].lvl, "client_x25519_keygen", i, t_axkg);
            raw(KEMS[k].name, KEMS[k].lvl, "client_kem_keygen", i, t_kkg);
            raw(KEMS[k].name, KEMS[k].lvl, "server_x25519_keygen", i, t_bxkg);
            raw(KEMS[k].name, KEMS[k].lvl, "server_x25519_shared", i, t_bxdh);
            raw(KEMS[k].name, KEMS[k].lvl, "server_kem_encaps", i, t_enc);
            raw(KEMS[k].name, KEMS[k].lvl, "client_x25519_shared", i, t_axdh);
            raw(KEMS[k].name, KEMS[k].lvl, "client_kem_decaps", i, t_dec);
            continue;
e:          wc_MlKemKey_Free(&kem_c); wc_MlKemKey_Free(&kem_s);
            printf("  %s round %d error %d\n", KEMS[k].name, i, ret);
            return;
        }
        printf("  %s: %d rounds ok\n", KEMS[k].name, X_ROUNDS);
    }
}

static void core1_entry(void)
{
    WC_RNG rng; int ret;
    char cfg[96];
    snprintf(cfg, sizeof cfg, "rounds=%d wolf_x25519=%s", X_ROUNDS, WOLF_IMPL);
    meta_print(cfg);
    if ((ret = heaptrk_install()) != 0 || (ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) {
        printf("ERROR: init failed (%d)\n", ret); goto halt;
    }
    printf("CSV,meta,x25519_cm0_ram_addr,0x%08lx\n", (unsigned long)(uintptr_t)&x25519_cm0_ram);
    printf("CSV,meta,x25519_cm0_flash_addr,0x%08lx\n", (unsigned long)(uintptr_t)&x25519_cm0_flash);
    if (self_test(&rng) != 0) {
        printf("CSV,x25519_selftest,FAILED\n");
        printf("\n=== X25519 self-test failed, done ===\n");
        goto halt;
    }
    bench_scalar_mults(&rng);
    bench_hybrid_cm0(&rng);
    wc_FreeRng(&rng);
    printf("\n=== X25519 implementation comparison done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "X25519 implementation comparison (wolfCrypt vs x25519-cm0 flash/SRAM)");
}
