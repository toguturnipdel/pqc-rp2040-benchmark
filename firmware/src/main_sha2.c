/*
 * SLH-DSA SHA2-192s, SHA2-192f, SHA2-256s and SHA2-256f benchmark
 * (key generation, signing, verification), 3 rounds per set.
 * Output uses the same CSV format as main_sig.c.
 *
 * The small-signature (s) sets need several minutes per signature; a full run
 * takes about one hour, so keep the host awake during serial capture.
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
#include <wolfssl/wolfcrypt/wc_slhdsa.h>

#define ROUNDS             3
#define CORE1_STACK_WORDS  (40 * 1024 / 4)
#define MSG_LEN            32
#define PQ_SIG_MAX         49856   /* largest signature: SLH-DSA-256f */

static uint32_t core1_stack[CORE1_STACK_WORDS];
static uint8_t  msg[MSG_LEN];
static uint8_t  pq_sig[PQ_SIG_MAX];

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

typedef struct { uint64_t sum, min, max; uint32_t n; } stat_t;
static void st_init(stat_t *s){ s->sum=0; s->min=UINT64_MAX; s->max=0; s->n=0; }
static void st_add(stat_t *s, uint64_t v){ s->sum+=v; if(v<s->min)s->min=v; if(v>s->max)s->max=v; s->n++; }
static uint64_t st_avg(const stat_t *s){ return s->n ? s->sum/s->n : 0; }

#define TIMED(dst, call) do { uint64_t t0_=time_us_64(); ret=(call); (dst)=time_us_64()-t0_; } while(0)

static void csv(const char *scheme, const char *lvl, const char *op,
                const stat_t *s, uint32_t sig_bytes)
{
    printf("CSV,sig_us,%s,%s,%s,%lu,%llu,%llu,%llu,%" PRIu32 "\n",
           scheme, lvl, op, (unsigned long)s->n, (unsigned long long)st_avg(s),
           (unsigned long long)s->min, (unsigned long long)s->max, sig_bytes);
}

static const struct { const char *name, *lvl; enum SlhDsaParam p; } SETS[] = {
    { "SLH-DSA-SHA2-192s","L3", SLHDSA_SHA2_192S },
    { "SLH-DSA-SHA2-192f","L3", SLHDSA_SHA2_192F },
    { "SLH-DSA-SHA2-256s","L5", SLHDSA_SHA2_256S },
    { "SLH-DSA-SHA2-256f","L5", SLHDSA_SHA2_256F },
};

static void core1_entry(void)
{
    WC_RNG rng; int ret, res;

    printf("wolfSSL %s | clk_sys %" PRIu32 " Hz\n", LIBWOLFSSL_VERSION_STRING, clock_get_hz(clk_sys));
    printf("Completion run: 4 SHA2 SLH-DSA sets, %d rounds each\n", ROUNDS);

    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) {
        printf("ERROR: init failed (%d)\n", ret); goto halt;
    }
    for (unsigned i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;

    printf("\ncols: operation  avg_us  min_us  max_us  sig_bytes\n");

    for (unsigned s = 0; s < sizeof(SETS)/sizeof(SETS[0]); s++) {
        int need = wc_SlhDsaKey_SigSizeFromParam(SETS[s].p);
        if (need <= 0 || need > PQ_SIG_MAX) {
            printf("  %-22s SKIPPED (sig %d B)\n", SETS[s].name, need); continue;
        }
        stat_t kg, sg, vf; st_init(&kg); st_init(&sg); st_init(&vf);
        int sigsz = need;
        SlhDsaKey key;

        printf("  running %s ...\n", SETS[s].name);
        for (int i = 0; i < ROUNDS; i++) {
            uint64_t dt; word32 sl = PQ_SIG_MAX;
            if ((ret = wc_SlhDsaKey_Init(&key, SETS[s].p, NULL, INVALID_DEVID)) != 0) {
                printf("  %s init failed: %d\n", SETS[s].name, ret); goto next;
            }
            TIMED(dt, wc_SlhDsaKey_MakeKey(&key, &rng)); if (ret) goto e; st_add(&kg, dt);
            TIMED(dt, wc_SlhDsaKey_Sign(&key, NULL, 0, msg, MSG_LEN, pq_sig, &sl, &rng));
            if (ret) goto e; st_add(&sg, dt); sigsz = (int)sl;
            TIMED(dt, wc_SlhDsaKey_Verify(&key, NULL, 0, msg, MSG_LEN, pq_sig, sl));
            if (ret) goto e; st_add(&vf, dt);
            wc_SlhDsaKey_Free(&key);
            continue;
e:          wc_SlhDsaKey_Free(&key);
            printf("  %s error: %d\n", SETS[s].name, ret); goto next;
        }
        printf("  %-22s sign avg %llu us  sig %d B\n", SETS[s].name,
               (unsigned long long)st_avg(&sg), sigsz);
        csv(SETS[s].name, SETS[s].lvl, "keygen", &kg, 0);
        csv(SETS[s].name, SETS[s].lvl, "sign",   &sg, (uint32_t)sigsz);
        csv(SETS[s].name, SETS[s].lvl, "verify", &vf, 0);
next:   ;
    }

    wc_FreeRng(&rng);
    printf("\n=== SHA2 completion run done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    stdio_init_all();
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(1000);
    printf("\n=== SLH-DSA SHA2 completion benchmark (192s/192f/256s/256f) ===\n");
    multicore_launch_core1_with_stack(core1_entry, core1_stack, sizeof(core1_stack));
    while (true) sleep_ms(1000);
}
