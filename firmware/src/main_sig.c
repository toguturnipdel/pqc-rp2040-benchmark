/*
 * Digital-signature benchmark for the Raspberry Pi Pico (RP2040), wolfCrypt.
 *   Classical baseline: Ed25519
 *   Post-quantum:       ML-DSA-44/65/87 and Falcon-512/1024 (MLDSA_ROUNDS rounds),
 *                       SLH-DSA, all twelve parameter sets (SLHDSA_ROUNDS rounds)
 *   Hybrid:             Ed25519 + each post-quantum scheme (sign both, verify both)
 *
 * Build options:
 *   default                                 all twelve SLH-DSA sets, 3 rounds
 *   -DSLHDSA_ROUNDS=1 -DSLHDSA_FAST_ONLY    six fast (f) SLH-DSA sets, 1 round
 *
 * Core 0 services USB serial. Core 1 runs the benchmark on a dedicated stack.
 * The SLH-DSA small-signature (s) sets need several minutes per signature at 125 MHz.
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
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/falcon.h>

#define MLDSA_ROUNDS       20
#ifndef SLHDSA_ROUNDS
#define SLHDSA_ROUNDS      3
#endif
#define CORE1_STACK_WORDS  (40 * 1024 / 4)   /* 40 KB, leaving RAM for the 50 KB signature buffer */
#define MSG_LEN            32                 /* fixed 32-byte message */
#define ED_SIG_MAX         ED25519_SIG_SIZE   /* 64 */
#define PQ_SIG_MAX         49856              /* largest signature: SLH-DSA-256f */

static uint32_t core1_stack[CORE1_STACK_WORDS];
static uint8_t  msg[MSG_LEN];

/* Entropy hook for wolfCrypt */
int pico_rng_seed(unsigned char *out, unsigned int sz)
{
    while (sz > 0) {
        uint32_t r = get_rand_32();
        unsigned int n = (sz < 4) ? sz : 4;
        memcpy(out, &r, n);
        out += n; sz -= n;
    }
    return 0;
}

/* Statistics */
typedef struct { uint64_t sum, min, max; uint32_t n; } stat_t;
static void st_init(stat_t *s){ s->sum=0; s->min=UINT64_MAX; s->max=0; s->n=0; }
static void st_add(stat_t *s, uint64_t v){ s->sum+=v; if(v<s->min)s->min=v; if(v>s->max)s->max=v; s->n++; }
static uint64_t st_avg(const stat_t *s){ return s->n ? s->sum/s->n : 0; }

#define TIMED(dst, call) do { uint64_t t0_=time_us_64(); ret=(call); (dst)=time_us_64()-t0_; } while(0)

static void row(const char *label, const stat_t *s, uint32_t sig_bytes)
{
    printf("  %-26s %10llu %10llu %10llu  %8" PRIu32 "\n", label,
           (unsigned long long)st_avg(s), (unsigned long long)s->min,
           (unsigned long long)s->max, sig_bytes);
}
static void csv(const char *scheme, const char *lvl, const char *op,
                const stat_t *s, uint32_t sig_bytes)
{
    printf("CSV,sig_us,%s,%s,%s,%lu,%llu,%llu,%llu,%" PRIu32 "\n",
           scheme, lvl, op, (unsigned long)s->n, (unsigned long long)st_avg(s),
           (unsigned long long)s->min, (unsigned long long)s->max, sig_bytes);
}

/* Shared buffers (static: not counted toward stack) */
static uint8_t ed_sig[ED_SIG_MAX];
static uint8_t pq_sig[PQ_SIG_MAX];

/* Ed25519 baseline */
static int bench_ed25519(WC_RNG *rng)
{
    int ret, res = 0;
    stat_t kg, sg, vf; st_init(&kg); st_init(&sg); st_init(&vf);
    uint64_t dt;
    ed25519_key k;

    for (int i = 0; i < MLDSA_ROUNDS; i++) {
        word32 sl = ED_SIG_MAX;
        wc_ed25519_init(&k);
        TIMED(dt, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &k)); if (ret) goto e;
        st_add(&kg, dt);
        TIMED(dt, wc_ed25519_sign_msg(msg, MSG_LEN, ed_sig, &sl, &k)); if (ret) goto e;
        st_add(&sg, dt);
        TIMED(dt, wc_ed25519_verify_msg(ed_sig, sl, msg, MSG_LEN, &res, &k));
        if (ret || !res) { if(!ret) ret=-9001; goto e; }
        st_add(&vf, dt);
        wc_ed25519_free(&k);
        continue;
e:      wc_ed25519_free(&k); return ret;
    }
    printf("  --- Ed25519 (classical) ---\n");
    row("Ed25519 keygen", &kg, 0);
    row("Ed25519 sign",   &sg, ED_SIG_MAX);
    row("Ed25519 verify", &vf, 0);
    csv("Ed25519","--","keygen",&kg,0);
    csv("Ed25519","--","sign",&sg,ED_SIG_MAX);
    csv("Ed25519","--","verify",&vf,0);
    return 0;
}

/* ML-DSA (3 levels) */
static const struct { const char *name, *lvl; byte level; } MLDSA[] = {
    { "ML-DSA-44", "L2", WC_ML_DSA_44 },
    { "ML-DSA-65", "L3", WC_ML_DSA_65 },
    { "ML-DSA-87", "L5", WC_ML_DSA_87 },
};

static int bench_mldsa(WC_RNG *rng, int hybrid)
{
    int ret, res = 0;
    for (unsigned m = 0; m < sizeof(MLDSA)/sizeof(MLDSA[0]); m++) {
        stat_t kg, sg, vf; st_init(&kg); st_init(&sg); st_init(&vf);
        uint64_t dt, edkg=0, edsg=0, edvf=0;
        wc_MlDsaKey key; ed25519_key ek;
        int sigsz = 0;

        for (int i = 0; i < MLDSA_ROUNDS; i++) {
            word32 sl = PQ_SIG_MAX, esl = ED_SIG_MAX;
            wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
            if ((ret = wc_MlDsaKey_SetParams(&key, MLDSA[m].level)) != 0) goto e;
            if (hybrid) wc_ed25519_init(&ek);

            TIMED(dt, wc_MlDsaKey_MakeKey(&key, rng)); if (ret) goto e; st_add(&kg, dt);
            if (hybrid) { TIMED(edkg, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek)); if (ret) goto e; }

            TIMED(dt, wc_MlDsaKey_SignCtx(&key, NULL, 0, pq_sig, &sl, msg, MSG_LEN, rng)); if (ret) goto e;
            st_add(&sg, dt); sigsz = (int)sl;
            if (hybrid) { TIMED(edsg, wc_ed25519_sign_msg(msg, MSG_LEN, ed_sig, &esl, &ek)); if (ret) goto e; }

            TIMED(dt, wc_MlDsaKey_VerifyCtx(&key, pq_sig, sl, NULL, 0, msg, MSG_LEN, &res));
            if (ret || !res) { if(!ret) ret=-9002; goto e; }
            st_add(&vf, dt);
            if (hybrid) {
                int er=0; TIMED(edvf, wc_ed25519_verify_msg(ed_sig, esl, msg, MSG_LEN, &er, &ek));
                if (ret || !er) { if(!ret) ret=-9003; goto e; }
            }

            wc_MlDsaKey_Free(&key);
            if (hybrid) wc_ed25519_free(&ek);
            continue;
e:          wc_MlDsaKey_Free(&key); if (hybrid) wc_ed25519_free(&ek);
            printf("  %s error: %d\n", MLDSA[m].name, ret); continue;
        }

        if (!hybrid) {
            printf("  --- %s (%s) ---\n", MLDSA[m].name, MLDSA[m].lvl);
            row("keygen", &kg, 0);
            row("sign",   &sg, (uint32_t)sigsz);
            row("verify", &vf, 0);
            csv(MLDSA[m].name, MLDSA[m].lvl, "keygen", &kg, 0);
            csv(MLDSA[m].name, MLDSA[m].lvl, "sign",   &sg, (uint32_t)sigsz);
            csv(MLDSA[m].name, MLDSA[m].lvl, "verify", &vf, 0);
        } else {
            /* Hybrid cost per operation: post-quantum statistics plus the Ed25519
             * time of the same operation from the last round (Ed25519 timing is
             * nearly constant between rounds). */
            char nm[32]; snprintf(nm, sizeof nm, "Ed25519+%s", MLDSA[m].name);
            stat_t hkg=kg, hsg=sg, hvf=vf;
            hkg.sum += edkg*hkg.n; hkg.min+=edkg; hkg.max+=edkg;
            hsg.sum += edsg*hsg.n; hsg.min+=edsg; hsg.max+=edsg;
            hvf.sum += edvf*hvf.n; hvf.min+=edvf; hvf.max+=edvf;
            printf("  --- %s (%s) ---\n", nm, MLDSA[m].lvl);
            row("keygen", &hkg, 0);
            row("sign",   &hsg, (uint32_t)sigsz + ED_SIG_MAX);
            row("verify", &hvf, 0);
            csv(nm, MLDSA[m].lvl, "keygen", &hkg, 0);
            csv(nm, MLDSA[m].lvl, "sign",   &hsg, (uint32_t)sigsz + ED_SIG_MAX);
            csv(nm, MLDSA[m].lvl, "verify", &hvf, 0);
        }
    }
    return 0;
}


/* Falcon / FN-DSA (2 levels) */
static const struct { const char *name, *lvl; byte level; } FALCONS[] = {
    { "Falcon-512",  "L1", FALCON_LEVEL1 },
    { "Falcon-1024", "L5", FALCON_LEVEL5 },
};

static int bench_falcon(WC_RNG *rng, int hybrid)
{
    int ret, res = 0;
    for (unsigned f = 0; f < sizeof(FALCONS)/sizeof(FALCONS[0]); f++) {
        stat_t kg, sg, vf; st_init(&kg); st_init(&sg); st_init(&vf);
        uint64_t dt, edkg=0, edsg=0, edvf=0;
        falcon_key key; ed25519_key ek;
        int sigsz = 0;

        for (int i = 0; i < MLDSA_ROUNDS; i++) {
            word32 sl = PQ_SIG_MAX, esl = ED_SIG_MAX;
            wc_falcon_init(&key);
            if ((ret = wc_falcon_set_level(&key, FALCONS[f].level)) != 0) goto e;
            if (hybrid) wc_ed25519_init(&ek);

            TIMED(dt, wc_falcon_make_key(&key, rng)); if (ret) goto e; st_add(&kg, dt);
            if (hybrid) { TIMED(edkg, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek)); if (ret) goto e; }

            TIMED(dt, wc_falcon_sign_msg(msg, MSG_LEN, pq_sig, &sl, &key, rng)); if (ret) goto e;
            st_add(&sg, dt); sigsz = (int)sl;
            if (hybrid) { TIMED(edsg, wc_ed25519_sign_msg(msg, MSG_LEN, ed_sig, &esl, &ek)); if (ret) goto e; }

            TIMED(dt, wc_falcon_verify_msg(pq_sig, sl, msg, MSG_LEN, &res, &key));
            if (ret || !res) { if(!ret) ret=-9005; goto e; }
            st_add(&vf, dt);
            if (hybrid) {
                int er=0; TIMED(edvf, wc_ed25519_verify_msg(ed_sig, esl, msg, MSG_LEN, &er, &ek));
                if (ret || !er) { if(!ret) ret=-9006; goto e; }
            }

            wc_falcon_free(&key); if (hybrid) wc_ed25519_free(&ek);
            continue;
e:          wc_falcon_free(&key); if (hybrid) wc_ed25519_free(&ek);
            printf("  %s error: %d\n", FALCONS[f].name, ret); continue;
        }

        if (!hybrid) {
            printf("  --- %s (%s) ---\n", FALCONS[f].name, FALCONS[f].lvl);
            row("keygen", &kg, 0);
            row("sign",   &sg, (uint32_t)sigsz);
            row("verify", &vf, 0);
            csv(FALCONS[f].name, FALCONS[f].lvl, "keygen", &kg, 0);
            csv(FALCONS[f].name, FALCONS[f].lvl, "sign",   &sg, (uint32_t)sigsz);
            csv(FALCONS[f].name, FALCONS[f].lvl, "verify", &vf, 0);
        } else {
            char nm[32]; snprintf(nm, sizeof nm, "Ed25519+%s", FALCONS[f].name);
            stat_t hkg=kg, hsg=sg, hvf=vf;
            hkg.sum+=edkg*hkg.n; hkg.min+=edkg; hkg.max+=edkg;
            hsg.sum+=edsg*hsg.n; hsg.min+=edsg; hsg.max+=edsg;
            hvf.sum+=edvf*hvf.n; hvf.min+=edvf; hvf.max+=edvf;
            printf("  --- %s (%s) ---\n", nm, FALCONS[f].lvl);
            row("keygen", &hkg, 0);
            row("sign",   &hsg, (uint32_t)sigsz + ED_SIG_MAX);
            row("verify", &hvf, 0);
            csv(nm, FALCONS[f].lvl, "keygen", &hkg, 0);
            csv(nm, FALCONS[f].lvl, "sign",   &hsg, (uint32_t)sigsz + ED_SIG_MAX);
            csv(nm, FALCONS[f].lvl, "verify", &hvf, 0);
        }
    }
    return 0;
}

/* SLH-DSA */
static const struct { const char *name, *lvl; enum SlhDsaParam p; } SLH[] = {
#ifndef SLHDSA_FAST_ONLY
    { "SLH-DSA-SHAKE-128s","L1", SLHDSA_SHAKE128S },
#endif
    { "SLH-DSA-SHAKE-128f","L1", SLHDSA_SHAKE128F },
#ifndef SLHDSA_FAST_ONLY
    { "SLH-DSA-SHAKE-192s","L3", SLHDSA_SHAKE192S },
#endif
    { "SLH-DSA-SHAKE-192f","L3", SLHDSA_SHAKE192F },
#ifndef SLHDSA_FAST_ONLY
    { "SLH-DSA-SHAKE-256s","L5", SLHDSA_SHAKE256S },
#endif
    { "SLH-DSA-SHAKE-256f","L5", SLHDSA_SHAKE256F },
#ifndef SLHDSA_FAST_ONLY
    { "SLH-DSA-SHA2-128s","L1",  SLHDSA_SHA2_128S },
#endif
    { "SLH-DSA-SHA2-128f","L1",  SLHDSA_SHA2_128F },
#ifndef SLHDSA_FAST_ONLY
    { "SLH-DSA-SHA2-192s","L3",  SLHDSA_SHA2_192S },
#endif
    { "SLH-DSA-SHA2-192f","L3",  SLHDSA_SHA2_192F },
#ifndef SLHDSA_FAST_ONLY
    { "SLH-DSA-SHA2-256s","L5",  SLHDSA_SHA2_256S },
#endif
    { "SLH-DSA-SHA2-256f","L5",  SLHDSA_SHA2_256F },
};

static int bench_slhdsa(WC_RNG *rng, int hybrid)
{
    int ret, res = 0;
    printf("\n  (SLH-DSA: %d round each, this is the slow part)\n", SLHDSA_ROUNDS);
    for (unsigned s = 0; s < sizeof(SLH)/sizeof(SLH[0]); s++) {
        int need = wc_SlhDsaKey_SigSizeFromParam(SLH[s].p);
        if (need <= 0 || need > PQ_SIG_MAX) {
            printf("  %-26s SKIPPED (sig %d B > buffer)\n", SLH[s].name, need);
            continue;
        }
        stat_t kg, sg, vf; st_init(&kg); st_init(&sg); st_init(&vf);
        uint64_t dt, edkg=0, edsg=0, edvf=0;
        SlhDsaKey key; ed25519_key ek;
        int sigsz = need;

        printf("  running %s ...\n", SLH[s].name);
        for (int i = 0; i < SLHDSA_ROUNDS; i++) {
            word32 sl = PQ_SIG_MAX, esl = ED_SIG_MAX;
            if ((ret = wc_SlhDsaKey_Init(&key, SLH[s].p, NULL, INVALID_DEVID)) != 0) {
                printf("  %s init failed: %d\n", SLH[s].name, ret); goto next;
            }
            if (hybrid) wc_ed25519_init(&ek);

            TIMED(dt, wc_SlhDsaKey_MakeKey(&key, rng)); if (ret) goto e; st_add(&kg, dt);
            if (hybrid) { TIMED(edkg, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek)); if (ret) goto e; }

            TIMED(dt, wc_SlhDsaKey_Sign(&key, NULL, 0, msg, MSG_LEN, pq_sig, &sl, rng));
            if (ret) goto e; st_add(&sg, dt); sigsz = (int)sl;
            if (hybrid) { TIMED(edsg, wc_ed25519_sign_msg(msg, MSG_LEN, ed_sig, &esl, &ek)); if (ret) goto e; }

            TIMED(dt, wc_SlhDsaKey_Verify(&key, NULL, 0, msg, MSG_LEN, pq_sig, sl));
            if (ret) { goto e; } st_add(&vf, dt);
            if (hybrid) {
                int er=0; TIMED(edvf, wc_ed25519_verify_msg(ed_sig, esl, msg, MSG_LEN, &er, &ek));
                if (ret || !er) { if(!ret) ret=-9004; goto e; }
            }

            wc_SlhDsaKey_Free(&key); if (hybrid) wc_ed25519_free(&ek);
            continue;
e:          wc_SlhDsaKey_Free(&key); if (hybrid) wc_ed25519_free(&ek);
            printf("  %s error: %d\n", SLH[s].name, ret); goto next;
        }

        if (!hybrid) {
            row(SLH[s].name, &sg, (uint32_t)sigsz);
            csv(SLH[s].name, SLH[s].lvl, "keygen", &kg, 0);
            csv(SLH[s].name, SLH[s].lvl, "sign",   &sg, (uint32_t)sigsz);
            csv(SLH[s].name, SLH[s].lvl, "verify", &vf, 0);
        } else {
            char nm[40]; snprintf(nm, sizeof nm, "Ed25519+%s", SLH[s].name);
            stat_t hkg=kg, hsg=sg, hvf=vf;
            hkg.sum+=edkg*hkg.n; hkg.min+=edkg; hkg.max+=edkg;
            hsg.sum+=edsg*hsg.n; hsg.min+=edsg; hsg.max+=edsg;
            hvf.sum+=edvf*hvf.n; hvf.min+=edvf; hvf.max+=edvf;
            csv(nm, SLH[s].lvl, "keygen", &hkg, 0);
            csv(nm, SLH[s].lvl, "sign",   &hsg, (uint32_t)sigsz + ED_SIG_MAX);
            csv(nm, SLH[s].lvl, "verify", &hvf, 0);
        }
next:   ;
    }
    return 0;
}

/* Core 1 */
static void core1_entry(void)
{
    WC_RNG rng; int ret;

    printf("wolfSSL %s | clk_sys %" PRIu32 " Hz\n", LIBWOLFSSL_VERSION_STRING, clock_get_hz(clk_sys));
    printf("ML-DSA/Falcon: %d rounds | SLH-DSA: %d round (all 12 sets)\n", MLDSA_ROUNDS, SLHDSA_ROUNDS);

    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) {
        printf("ERROR: init failed (%d)\n", ret); goto halt;
    }
    for (unsigned i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;

    printf("\ncols: operation  avg_us  min_us  max_us  sig_bytes\n");

    printf("\n===== STANDALONE =====\n");
    bench_ed25519(&rng);
    bench_mldsa(&rng, 0);
    bench_falcon(&rng, 0);
    bench_slhdsa(&rng, 0);

    printf("\n===== HYBRID (Ed25519 + PQC) =====\n");
    bench_mldsa(&rng, 1);
    bench_falcon(&rng, 1);
    bench_slhdsa(&rng, 1);

done: {
    struct mallinfo mi = mallinfo();
    printf("\n--- Heap ---\n  arena high-water: %u B\n", (unsigned)mi.arena);
    printf("CSV,heap_arena_bytes,all,%u\n", (unsigned)mi.arena);
    wc_FreeRng(&rng);
    printf("\n=== signature benchmark done ===\n");
}
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    stdio_init_all();
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(1000);
    printf("\n=== PQC signature benchmark start (Ed25519 + ML-DSA + Falcon + SLH-DSA) ===\n");
    multicore_launch_core1_with_stack(core1_entry, core1_stack, sizeof(core1_stack));
    while (true) sleep_ms(1000);
}
