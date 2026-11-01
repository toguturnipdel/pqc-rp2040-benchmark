/*
 * Code-location sensitivity of SLH-DSA (Reviewer 2 point 7): the same
 * SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f sign/verify loop, built twice:
 *   pqc_slh_xip   code executes in place from QSPI flash (as in the paper)
 *   pqc_slh_sram  whole binary copied to SRAM at boot (pico copy_to_ram)
 * Comparing the two isolates the contribution of XIP cache behaviour and code
 * layout to the build-to-build differences reported in Section 5.3.
 */
#define FW_NAME            "slh_codeloc"
#define CORE1_STACK_WORDS  (32 * 1024 / 4)
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>

#ifndef SLH_ROUNDS
#define SLH_ROUNDS 20
#endif
#define MSG_LEN    32
#define SIG_MAX    17088   /* 128f */

static SlhDsaKey key;
static uint8_t msg[MSG_LEN], sig[SIG_MAX];
static const struct { const char *name; enum SlhDsaParam p; } SETS[] = {
    { "SLH-DSA-SHA2-128f",  SLHDSA_SHA2_128F },
    { "SLH-DSA-SHAKE-128f", SLHDSA_SHAKE128F },
};

static void core1_entry(void)
{
    WC_RNG rng; int ret;
    char cfg[64]; snprintf(cfg, sizeof cfg, "rounds=%d", SLH_ROUNDS);
    meta_print(cfg);
    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) { printf("ERROR init %d\n", ret); goto halt; }
    for (unsigned s = 0; s < 2; s++) {
        for (int i = -1; i < SLH_ROUNDS; i++) {
            uint64_t kg, sg, vf; word32 sl = SIG_MAX;
            wc_RNG_GenerateBlock(&rng, msg, MSG_LEN);
            if ((ret = wc_SlhDsaKey_Init(&key, SETS[s].p, NULL, INVALID_DEVID)) != 0) goto e;
            TIMED(kg, wc_SlhDsaKey_MakeKey(&key, &rng));                                 if (ret) goto e;
            TIMED(sg, wc_SlhDsaKey_Sign(&key, NULL, 0, msg, MSG_LEN, sig, &sl, &rng));   if (ret) goto e;
            TIMED(vf, wc_SlhDsaKey_Verify(&key, NULL, 0, msg, MSG_LEN, sig, sl));        if (ret) goto e;
            wc_SlhDsaKey_Free(&key);
            if (i < 0) continue;
            raw(SETS[s].name, "L1", "keygen", i, kg);
            raw(SETS[s].name, "L1", "sign", i, sg);
            raw(SETS[s].name, "L1", "verify", i, vf);
            continue;
e:          wc_SlhDsaKey_Free(&key);
            printf("  %s error %d\n", SETS[s].name, ret);
            break;
        }
        printf("  %s done\n", SETS[s].name);
    }
    wc_FreeRng(&rng);
    printf("\n=== SLH-DSA code-location run done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "SLH-DSA code-location run (128f, SHA2 and SHAKE)");
}
