/*
 * Digital-signature benchmark for the Raspberry Pi Pico (RP2040), wolfCrypt.
 *   Classical: Ed25519
 *   Post-quantum: ML-DSA-44/65/87, Falcon-512/1024, SLH-DSA (all twelve sets)
 *   Hybrid: Ed25519 + each post-quantum scheme
 *
 * Paired measurement. In every round the Ed25519 and the post-quantum
 * operations run back to back on the same message, so standalone and hybrid
 * figures come from the same samples. The hybrid is a composite-style dual
 * signature: both components sign the domain-separated message
 *     M' = Prefix || Label || 0x00 || SHA-512(M)
 * (Prefix = "CompositeAlgorithmSignatures2025", Label names the pair; empty
 * context). This binds each component to the pair, so a component signature
 * cannot be stripped and presented as a standalone signature over M. It
 * follows the structure of the IETF LAMPS composite-signature drafts but is
 * not claimed to conform to any specific draft version. The binding step is
 * timed separately (op "bind"), on both the signing and verifying side.
 *
 * Falcon: Falcon-512 key generation is measured on-device; Falcon-512 and
 * Falcon-1024 signing and verification use key pairs provisioned off-device
 * (tools/falcon_keygen -> falcon_ext_keys.h). One on-device Falcon-1024 key
 * generation attempt is made and the largest failed allocation is logged.
 *
 * Build modes:
 *   default            timing (RAW per-sample lines + summary lines)
 *   -DBENCH_MODE_MEM   per-operation peak stack/heap and RFC 7228 RAM budgets
 *   -DSIG_PART=n       1 lattice only, 2 SLH-DSA f sets only, 3 SLH-DSA s sets only,
 *                      4 Falcon only (use with -DFALCON_SIGN_SMALL)
 *   -DFALCON_SIGN_SMALL wolfCrypt small-memory Falcon signer (WOLFSSL_FALCON_SIGN_SMALL_MEM);
 *                      Falcon scheme names get the suffix "-smallmem" so the runs stay distinct
 *                      (0 or undefined: everything)
 *
 * Core 0 services USB serial; core 1 runs the benchmark on a dedicated stack.
 */
#ifdef BENCH_MODE_MEM
#define FW_NAME            "sig_mem"
#else
#define FW_NAME            "sig"
#endif
#define CORE1_STACK_WORDS  (40 * 1024 / 4)
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include "falcon_ext_keys.h"

#ifndef SIG_PART
#define SIG_PART 0
#endif
#define DO_LATTICE (SIG_PART == 0 || SIG_PART == 1 || SIG_PART == 4)
#define FALCON_ONLY (SIG_PART == 4)
#ifdef FALCON_SIGN_SMALL
#define FSUF "-smallmem"
#else
#define FSUF ""
#endif
#define DO_SLH_F   (SIG_PART == 0 || SIG_PART == 2)
#define DO_SLH_S   (SIG_PART == 0 || SIG_PART == 3)

#ifndef LATTICE_ROUNDS
#define LATTICE_ROUNDS     100   /* ML-DSA, Falcon sign/verify, Ed25519 */
#endif
#ifndef FALCON_KG_ROUNDS
#define FALCON_KG_ROUNDS   20    /* Falcon-512 on-device key generation */
#endif
#ifndef SLH_F_ROUNDS
#define SLH_F_ROUNDS       20
#endif
#ifndef SLH_S_ROUNDS
#define SLH_S_ROUNDS       3
#endif
#ifndef SLH_SHA2_128S_ROUNDS
#define SLH_SHA2_128S_ROUNDS 5
#endif
#define MSG_LEN            32
#define ED_SIG_MAX         ED25519_SIG_SIZE   /* 64 */
/* Signature buffer: SLH-DSA-256f needs 49,856 B, but the lattice and Falcon-only
 * parts never do, and a static 50 KB buffer would take that much RAM away from
 * the heap (Falcon-1024 signing needs one contiguous ~90 KB block). */
#if SIG_PART == 1 || SIG_PART == 4
#define PQ_SIG_MAX         4864               /* ML-DSA-87: 4,627 B; Falcon-1024: <= 1,280 B */
#else
#define PQ_SIG_MAX         49856              /* SLH-DSA-256f */
#endif

static uint8_t msg[MSG_LEN];
static uint8_t ed_sig[ED_SIG_MAX];
static uint8_t pq_sig[PQ_SIG_MAX];

/* ------------------------------------------------------------------------ */
/* Composite-style binding                                                   */
/* ------------------------------------------------------------------------ */
static const char PREFIX[] = "CompositeAlgorithmSignatures2025";   /* 32 bytes */
#define LABEL_MAX 48
static uint8_t mprime[32 + LABEL_MAX + 1 + WC_SHA512_DIGEST_SIZE];
static word32  mprime_len;

static int bind_msg(const char *label, const uint8_t *m, word32 ml)
{
    size_t ll = strlen(label);
    if (ll > LABEL_MAX) return -1;
    memcpy(mprime, PREFIX, 32);
    memcpy(mprime + 32, label, ll);
    mprime[32 + ll] = 0x00;                              /* empty context */
    mprime_len = (word32)(32 + ll + 1 + WC_SHA512_DIGEST_SIZE);
    return wc_Sha512Hash(m, ml, mprime + 32 + ll + 1);
}

/* ------------------------------------------------------------------------ */
/* Post-quantum scheme adapters                                              */
/* ------------------------------------------------------------------------ */
typedef enum { F_MLDSA, F_FALCON, F_SLH } fam_t;
typedef struct {
    const char *name, *lvl, *label;
    fam_t fam;
    int   param;
    int   rounds;
    bool  ext_key;          /* Falcon: import provisioned key instead of keygen */
    const uint8_t *priv, *pub; word32 privSz, pubSz;
} scheme_t;

static union { wc_MlDsaKey d; falcon_key f; SlhDsaKey s; } pk;
static ed25519_key ek;

static int pq_init(const scheme_t *s)
{
    int ret;
    switch (s->fam) {
    case F_MLDSA:
        if ((ret = wc_MlDsaKey_Init(&pk.d, NULL, INVALID_DEVID)) != 0) return ret;
        return wc_MlDsaKey_SetParams(&pk.d, (byte)s->param);
    case F_FALCON:
        if ((ret = wc_falcon_init(&pk.f)) != 0) return ret;
        return wc_falcon_set_level(&pk.f, (byte)s->param);
    default:
        return wc_SlhDsaKey_Init(&pk.s, (enum SlhDsaParam)s->param, NULL, INVALID_DEVID);
    }
}
static void pq_free(const scheme_t *s)
{
    switch (s->fam) {
    case F_MLDSA:  wc_MlDsaKey_Free(&pk.d); break;
    case F_FALCON: wc_falcon_free(&pk.f); break;
    default:       wc_SlhDsaKey_Free(&pk.s); break;
    }
}
static int pq_keygen(const scheme_t *s, WC_RNG *rng)
{
    switch (s->fam) {
    case F_MLDSA:  return wc_MlDsaKey_MakeKey(&pk.d, rng);
    case F_FALCON: return wc_falcon_make_key(&pk.f, rng);
    default:       return wc_SlhDsaKey_MakeKey(&pk.s, rng);
    }
}
static int pq_import(const scheme_t *s)
{
    return wc_falcon_import_private_key(s->priv, s->privSz, s->pub, s->pubSz, &pk.f);
}
static int pq_sign(const scheme_t *s, const uint8_t *m, word32 ml, word32 *sl, WC_RNG *rng)
{
    *sl = PQ_SIG_MAX;
    switch (s->fam) {
    case F_MLDSA:  return wc_MlDsaKey_SignCtx(&pk.d, NULL, 0, pq_sig, sl, m, ml, rng);
    case F_FALCON: return wc_falcon_sign_msg(m, ml, pq_sig, sl, &pk.f, rng);
    default:       return wc_SlhDsaKey_Sign(&pk.s, NULL, 0, m, ml, pq_sig, sl, rng);
    }
}
static int pq_verify(const scheme_t *s, const uint8_t *m, word32 ml, word32 sl)
{
    int ret, res = 0;
    switch (s->fam) {
    case F_MLDSA:  ret = wc_MlDsaKey_VerifyCtx(&pk.d, pq_sig, sl, NULL, 0, m, ml, &res); break;
    case F_FALCON: ret = wc_falcon_verify_msg(pq_sig, sl, m, ml, &res, &pk.f); break;
    default:       ret = wc_SlhDsaKey_Verify(&pk.s, NULL, 0, m, ml, pq_sig, sl); res = (ret == 0); break;
    }
    return ret ? ret : (res ? 0 : -9002);
}
static size_t pq_key_bytes(const scheme_t *s)
{
    switch (s->fam) {
    case F_MLDSA:  return sizeof(wc_MlDsaKey);
    case F_FALCON: return sizeof(falcon_key);
    default:       return sizeof(SlhDsaKey);
    }
}

static const scheme_t SCHEMES[] = {
    { "ML-DSA-44", "L2", "RP2040-Ed25519-MLDSA44", F_MLDSA, WC_ML_DSA_44, LATTICE_ROUNDS, false },
    { "ML-DSA-65", "L3", "RP2040-Ed25519-MLDSA65", F_MLDSA, WC_ML_DSA_65, LATTICE_ROUNDS, false },
    { "ML-DSA-87", "L5", "RP2040-Ed25519-MLDSA87", F_MLDSA, WC_ML_DSA_87, LATTICE_ROUNDS, false },
    { "Falcon-512" FSUF, "L1", "RP2040-Ed25519-Falcon512", F_FALCON, FALCON_LEVEL1, LATTICE_ROUNDS, true,
      FALCON512_PRIV, FALCON512_PUB, sizeof FALCON512_PRIV, sizeof FALCON512_PUB },
    { "Falcon-1024" FSUF, "L5", "RP2040-Ed25519-Falcon1024", F_FALCON, FALCON_LEVEL5, LATTICE_ROUNDS, true,
      FALCON1024_PRIV, FALCON1024_PUB, sizeof FALCON1024_PRIV, sizeof FALCON1024_PUB },
};
#define N_LATTICE (sizeof(SCHEMES) / sizeof(SCHEMES[0]))

#define SLH(n, l, p, r) { n, l, "RP2040-Ed25519-" n, F_SLH, p, r, false }
static const scheme_t SLH_F[] = {
    SLH("SLH-DSA-SHA2-128f",  "L1", SLHDSA_SHA2_128F, SLH_F_ROUNDS),
    SLH("SLH-DSA-SHAKE-128f", "L1", SLHDSA_SHAKE128F, SLH_F_ROUNDS),
    SLH("SLH-DSA-SHA2-192f",  "L3", SLHDSA_SHA2_192F, SLH_F_ROUNDS),
    SLH("SLH-DSA-SHAKE-192f", "L3", SLHDSA_SHAKE192F, SLH_F_ROUNDS),
    SLH("SLH-DSA-SHA2-256f",  "L5", SLHDSA_SHA2_256F, SLH_F_ROUNDS),
    SLH("SLH-DSA-SHAKE-256f", "L5", SLHDSA_SHAKE256F, SLH_F_ROUNDS),
};
static const scheme_t SLH_S[] = {
    SLH("SLH-DSA-SHA2-128s",  "L1", SLHDSA_SHA2_128S, SLH_SHA2_128S_ROUNDS),
    SLH("SLH-DSA-SHAKE-128s", "L1", SLHDSA_SHAKE128S, SLH_S_ROUNDS),
    SLH("SLH-DSA-SHA2-192s",  "L3", SLHDSA_SHA2_192S, SLH_S_ROUNDS),
    SLH("SLH-DSA-SHAKE-192s", "L3", SLHDSA_SHAKE192S, SLH_S_ROUNDS),
    SLH("SLH-DSA-SHA2-256s",  "L5", SLHDSA_SHA2_256S, SLH_S_ROUNDS),
    SLH("SLH-DSA-SHAKE-256s", "L5", SLHDSA_SHAKE256S, SLH_S_ROUNDS),
};

/* ------------------------------------------------------------------------ */
/* Summary lines (CSV,sig_us,...) kept compatible with the original format   */
/* ------------------------------------------------------------------------ */
static void csv(const char *scheme, const char *lvl, const char *op, const stat_t *s, uint32_t sig_bytes)
{
    printf("CSV,sig_us,%s,%s,%s,%lu,%llu,%llu,%llu,%" PRIu32 "\n", scheme, lvl, op,
           (unsigned long)s->n, (unsigned long long)st_avg(s), (unsigned long long)s->min,
           (unsigned long long)s->max, sig_bytes);
}

#ifndef BENCH_MODE_MEM
/* ======================================================================== */
/* Timing mode                                                              */
/* ======================================================================== */
static void new_message(WC_RNG *rng) { wc_RNG_GenerateBlock(rng, msg, MSG_LEN); }

/* Ed25519 alone (signs M directly, as a classical baseline) */
static void bench_ed25519(WC_RNG *rng)
{
    int ret, res;
    stat_t kg, sg, vf; st_init(&kg); st_init(&sg); st_init(&vf);
    for (int i = -1; i < LATTICE_ROUNDS; i++) {          /* i = -1: warm-up */
        uint64_t a, b, c; word32 sl = ED_SIG_MAX; res = 0;
        new_message(rng);
        wc_ed25519_init(&ek);
        TIMED(a, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek));              if (ret) goto e;
        TIMED(b, wc_ed25519_sign_msg(msg, MSG_LEN, ed_sig, &sl, &ek));          if (ret) goto e;
        TIMED(c, wc_ed25519_verify_msg(ed_sig, sl, msg, MSG_LEN, &res, &ek));   if (ret || !res) goto e;
        wc_ed25519_free(&ek);
        if (i < 0) continue;
        st_add(&kg, a); st_add(&sg, b); st_add(&vf, c);
        raw("Ed25519", "--", "keygen", i, a); raw("Ed25519", "--", "sign", i, b); raw("Ed25519", "--", "verify", i, c);
        continue;
e:      wc_ed25519_free(&ek); printf("  Ed25519 error %d res %d\n", ret, res); return;
    }
    csv("Ed25519", "--", "keygen", &kg, 0); csv("Ed25519", "--", "sign", &sg, ED_SIG_MAX);
    csv("Ed25519", "--", "verify", &vf, 0);
}

/* Paired standalone + hybrid rounds for one post-quantum scheme. */
static void bench_paired(const scheme_t *s, WC_RNG *rng)
{
    int ret = 0;
    stat_t pkg, psg, pvf, ekg, esg, evf, bnd, hkg, hsg, hvf;
    st_init(&pkg); st_init(&psg); st_init(&pvf); st_init(&ekg); st_init(&esg);
    st_init(&evf); st_init(&bnd); st_init(&hkg); st_init(&hsg); st_init(&hvf);
    char hyb[48]; snprintf(hyb, sizeof hyb, "Ed25519+%s", s->name);
    uint32_t sigsz = 0;
    int warm = (s->rounds >= 10) ? 1 : 0;

    printf("  running %s (%d rounds, %d warm-up%s) ...\n", s->name, s->rounds, warm,
           s->ext_key ? ", provisioned key" : "");
    for (int i = -warm; i < s->rounds; i++) {
        uint64_t t_kg, t_ekg, t_b1, t_esg, t_psg, t_b2, t_evf, t_pvf;
        word32 sl, esl = ED_SIG_MAX; int eres = 0;
        new_message(rng);
        if ((ret = pq_init(s)) != 0) goto e;
        wc_ed25519_init(&ek);

        if (s->ext_key) { TIMED(t_kg, pq_import(s)); } else { TIMED(t_kg, pq_keygen(s, rng)); }
        if (ret) goto e;
        TIMED(t_ekg, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek));                       if (ret) goto e;
        /* signer */
        TIMED(t_b1,  bind_msg(s->label, msg, MSG_LEN));                                      if (ret) goto e;
        TIMED(t_esg, wc_ed25519_sign_msg(mprime, mprime_len, ed_sig, &esl, &ek));             if (ret) goto e;
        TIMED(t_psg, pq_sign(s, mprime, mprime_len, &sl, rng));                              if (ret) goto e;
        /* verifier (recomputes M') */
        TIMED(t_b2,  bind_msg(s->label, msg, MSG_LEN));                                      if (ret) goto e;
        TIMED(t_evf, wc_ed25519_verify_msg(ed_sig, esl, mprime, mprime_len, &eres, &ek));     if (ret || !eres) { ret = ret ? ret : -9003; goto e; }
        TIMED(t_pvf, pq_verify(s, mprime, mprime_len, sl));                                  if (ret) goto e;
        pq_free(s); wc_ed25519_free(&ek);
        if (i < 0) continue;

        sigsz = sl;
        const char *kgop = s->ext_key ? "import" : "keygen";
        st_add(&pkg, t_kg); st_add(&psg, t_psg); st_add(&pvf, t_pvf);
        st_add(&ekg, t_ekg); st_add(&esg, t_esg); st_add(&evf, t_evf); st_add(&bnd, t_b1);
        st_add(&hkg, t_kg + t_ekg); st_add(&hsg, t_b1 + t_esg + t_psg); st_add(&hvf, t_b2 + t_evf + t_pvf);
        raw(s->name, s->lvl, kgop, i, t_kg);   raw(s->name, s->lvl, "sign", i, t_psg);  raw(s->name, s->lvl, "verify", i, t_pvf);
        raw(hyb, s->lvl, "ed_keygen", i, t_ekg); raw(hyb, s->lvl, "ed_sign", i, t_esg); raw(hyb, s->lvl, "ed_verify", i, t_evf);
        raw(hyb, s->lvl, "bind_sign", i, t_b1);  raw(hyb, s->lvl, "bind_verify", i, t_b2);
        raw(hyb, s->lvl, kgop, i, t_kg + t_ekg);
        raw(hyb, s->lvl, "sign", i, t_b1 + t_esg + t_psg);
        raw(hyb, s->lvl, "verify", i, t_b2 + t_evf + t_pvf);
        continue;
e:      pq_free(s); wc_ed25519_free(&ek);
        printf("  %s round %d error: %d\n", s->name, i, ret);
        printf("CSV,sig_error,%s,%s,%d,%d\n", s->name, s->lvl, i, ret);
        return;
    }
    const char *kgop = s->ext_key ? "import" : "keygen";
    csv(s->name, s->lvl, kgop, &pkg, 0); csv(s->name, s->lvl, "sign", &psg, sigsz); csv(s->name, s->lvl, "verify", &pvf, 0);
    csv(hyb, s->lvl, kgop, &hkg, 0); csv(hyb, s->lvl, "sign", &hsg, sigsz + ED_SIG_MAX); csv(hyb, s->lvl, "verify", &hvf, 0);
}

/* Falcon-512 on-device key generation (paired with Ed25519 key generation). */
static void bench_falcon512_keygen(WC_RNG *rng)
{
    int ret;
    stat_t kg; st_init(&kg);
    scheme_t s = SCHEMES[3];  /* Falcon-512 */
    s.ext_key = false;
    printf("  running Falcon-512 on-device keygen (%d rounds) ...\n", FALCON_KG_ROUNDS);
    for (int i = -1; i < FALCON_KG_ROUNDS; i++) {
        uint64_t a, b;
        if ((ret = pq_init(&s)) != 0) break;
        wc_ed25519_init(&ek);
        TIMED(a, pq_keygen(&s, rng));
        if (ret == 0) TIMED(b, wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &ek));
        pq_free(&s); wc_ed25519_free(&ek);
        if (ret) { printf("  Falcon-512 keygen error %d\n", ret); return; }
        if (i < 0) continue;
        st_add(&kg, a);
        raw("Falcon-512" FSUF, "L1", "keygen", i, a);
        raw("Ed25519+Falcon-512" FSUF, "L1", "ed_keygen", i, b);
        raw("Ed25519+Falcon-512" FSUF, "L1", "keygen", i, a + b);
    }
    csv("Falcon-512" FSUF, "L1", "keygen", &kg, 0);
}

/* One on-device Falcon-1024 key generation attempt; logs its heap use (and the
 * failing allocation, if any). In the submitted run key generation succeeded and
 * signing with the default signer failed. */
static void falcon1024_keygen_attempt(WC_RNG *rng)
{
    int ret; uint64_t a;
    scheme_t s = SCHEMES[4];
    s.ext_key = false;
    heaptrk_reset_peak();
    size_t base = ht.cur;
    pq_init(&s);
    TIMED(a, pq_keygen(&s, rng));
    pq_free(&s);
    printf("  Falcon-1024 on-device keygen: ret %d after %llu us, tracked heap peak %u B above baseline\n",
           ret, (unsigned long long)a, (unsigned)(ht.peak - base));
    printf("CSV,falcon1024_keygen,%d,%llu,%u,%" PRIu32 ",%u,%u\n", ret, (unsigned long long)a,
           (unsigned)(ht.peak - base), ht.fails, (unsigned)ht.largest_fail, (unsigned)ht.cur_at_fail);
    {
        struct mallinfo mi = mallinfo();
        printf("CSV,falcon1024_keygen_arena,%u,%u\n", (unsigned)mi.arena, (unsigned)mi.fordblks);
    }
}

static void run_all(WC_RNG *rng)
{
#if DO_LATTICE
    printf("\n===== Ed25519, ML-DSA, Falcon (paired standalone + hybrid) =====\n");
    if (!FALCON_ONLY) bench_ed25519(rng);
    for (unsigned k = 0; k < N_LATTICE; k++) {
        /* Falcon-only part: Falcon-1024 first, so its ~90 KB block comes from a fresh heap */
        unsigned i = FALCON_ONLY ? N_LATTICE - 1 - k : k;
        if (FALCON_ONLY && SCHEMES[i].fam != F_FALCON) continue;
        bench_paired(&SCHEMES[i], rng);
    }
    bench_falcon512_keygen(rng);
    falcon1024_keygen_attempt(rng);
#endif
#if DO_SLH_F
    printf("\n===== SLH-DSA fast (f) sets =====\n");
    for (unsigned i = 0; i < sizeof SLH_F / sizeof SLH_F[0]; i++) bench_paired(&SLH_F[i], rng);
#endif
#if DO_SLH_S
    printf("\n===== SLH-DSA small (s) sets (slow) =====\n");
    for (unsigned i = 0; i < sizeof SLH_S / sizeof SLH_S[0]; i++) bench_paired(&SLH_S[i], rng);
#endif
}

#else
/* ======================================================================== */
/* Memory mode: per-operation peak stack/heap and RAM budgets               */
/* ======================================================================== */
typedef struct { const scheme_t *s; WC_RNG *rng; word32 sl; } sctx_t;
static int op_ed_kg(void *c) { sctx_t *x = c; return wc_ed25519_make_key(x->rng, ED25519_KEY_SIZE, &ek); }
static int op_ed_sg(void *c) { (void)c; word32 l = ED_SIG_MAX; return wc_ed25519_sign_msg(mprime, mprime_len, ed_sig, &l, &ek); }
static int op_ed_vf(void *c) { (void)c; int r = 0; int ret = wc_ed25519_verify_msg(ed_sig, ED_SIG_MAX, mprime, mprime_len, &r, &ek); return ret ? ret : (r ? 0 : -1); }
static int op_bind(void *c)  { sctx_t *x = c; return bind_msg(x->s->label, msg, MSG_LEN); }
static int op_pq_kg(void *c) { sctx_t *x = c; pq_free(x->s); pq_init(x->s); return x->s->ext_key ? pq_import(x->s) : pq_keygen(x->s, x->rng); }
static int op_pq_sg(void *c) { sctx_t *x = c; return pq_sign(x->s, mprime, mprime_len, &x->sl, x->rng); }
static int op_pq_vf(void *c) { sctx_t *x = c; return pq_verify(x->s, mprime, mprime_len, x->sl); }

/* restore: re-run the op unconstrained afterwards, for ops whose output later
 * ops depend on (key generation), in case a capped run failed midway. */
static void measure(const char *scheme, const char *lvl, const char *op, op_fn fn, void *ctx,
                    size_t static_b, bool restore)
{
    mem_t m;
    mem_measure(scheme, lvl, op, fn, ctx, static_b, &m);
    mem_budget(scheme, lvl, op, fn, ctx, static_b, &m);
    if (restore) fn(ctx);
}

static void mem_scheme(const scheme_t *s, WC_RNG *rng)
{
    sctx_t c = { s, rng, 0 };
    size_t kb = pq_key_bytes(s);
    size_t sigb = (s->fam == F_SLH) ? (size_t)wc_SlhDsaKey_SigSizeFromParam((enum SlhDsaParam)s->param) :
                  (s->fam == F_FALCON) ? (s->param == FALCON_LEVEL1 ? FALCON_LEVEL1_SIG_SIZE : FALCON_LEVEL5_SIG_SIZE) :
                  (size_t)PQ_SIG_MAX;
    if (s->fam == F_MLDSA) { int n = 0; pq_init(s); wc_MlDsaKey_GetSigLen(&pk.d, &n); sigb = (size_t)n; pq_free(s); }
    printf("  memory: %s\n", s->name);
    pq_init(s);
    measure(s->name, s->lvl, s->ext_key ? "import" : "keygen", op_pq_kg, &c, kb, true);
    bind_msg(s->label, msg, MSG_LEN);
    /* Sign once unconstrained (valid signature for verify), measure verify,
     * and only then run the capped signing attempts, which may leave pq_sig
     * invalid. Each SLH-DSA s-set signature takes minutes, so no restore run. */
    mem_t ms;
    mem_measure(s->name, s->lvl, "sign", op_pq_sg, &c, kb + sigb + sizeof mprime, &ms);
    measure(s->name, s->lvl, "verify", op_pq_vf, &c, kb + sigb + sizeof mprime, false);
    mem_budget(s->name, s->lvl, "sign", op_pq_sg, &c, kb + sigb + sizeof mprime, &ms);
    pq_free(s);
    printf("CSV,meta,sig_bytes_%s,%u\n", s->name, (unsigned)sigb);
    printf("CSV,meta,sizeof_key_%s,%u\n", s->name, (unsigned)kb);
}

static void run_all(WC_RNG *rng)
{
    for (unsigned i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;
    printf("CSV,meta,sizeof_ed25519_key,%u\n", (unsigned)sizeof(ed25519_key));
#if DO_LATTICE
    sctx_t c = { &SCHEMES[0], rng, 0 };
    if (!FALCON_ONLY) {
    wc_ed25519_init(&ek);
    measure("Ed25519", "--", "keygen", op_ed_kg, &c, sizeof(ed25519_key), true);
    bind_msg(SCHEMES[0].label, msg, MSG_LEN);
    measure("Ed25519", "--", "sign",   op_ed_sg, &c, sizeof(ed25519_key) + ED_SIG_MAX + sizeof mprime, true);
    measure("Ed25519", "--", "verify", op_ed_vf, &c, sizeof(ed25519_key) + ED_SIG_MAX + sizeof mprime, false);
    measure("Composite-bind", "--", "bind", op_bind, &c, sizeof mprime, true);
    wc_ed25519_free(&ek);
    }
    for (unsigned k = 0; k < N_LATTICE; k++) {
        unsigned i = FALCON_ONLY ? N_LATTICE - 1 - k : k;
        if (FALCON_ONLY && SCHEMES[i].fam != F_FALCON) continue;
        mem_scheme(&SCHEMES[i], rng);
    }
    { scheme_t f = SCHEMES[3]; f.ext_key = false; mem_scheme(&f, rng); }   /* Falcon-512 on-device keygen */
    { /* Falcon-1024 on-device keygen: logs heap use (and any failing allocation) */
        scheme_t f = SCHEMES[4]; f.ext_key = false; sctx_t cf = { &f, rng, 0 };
        pq_init(&f);
        mem_measure(f.name, f.lvl, "keygen", op_pq_kg, &cf, sizeof(falcon_key), NULL);
        pq_free(&f);
    }
#endif
#if DO_SLH_F
    for (unsigned i = 0; i < sizeof SLH_F / sizeof SLH_F[0]; i++) mem_scheme(&SLH_F[i], rng);
#endif
#if DO_SLH_S
    for (unsigned i = 0; i < sizeof SLH_S / sizeof SLH_S[0]; i++) mem_scheme(&SLH_S[i], rng);
#endif
}
#endif /* BENCH_MODE_MEM */

/* ------------------------------------------------------------------------ */
/* Core 1                                                                    */
/* ------------------------------------------------------------------------ */
static void core1_entry(void)
{
    WC_RNG rng; int ret;
    char cfg[200];
    snprintf(cfg, sizeof cfg, "part=%d falcon_signer=%s lattice_rounds=%d falcon_kg_rounds=%d slh_f=%d slh_s=%d slh_sha2_128s=%d binding=composite-style",
             SIG_PART,
#ifdef FALCON_SIGN_SMALL
             "small_mem",
#else
             "default",
#endif
             LATTICE_ROUNDS, FALCON_KG_ROUNDS, SLH_F_ROUNDS, SLH_S_ROUNDS, SLH_SHA2_128S_ROUNDS);
    meta_print(cfg);
#ifdef MLDSA_SPEED
    printf("CSV,meta,mldsa_build,speed\n");
#else
    printf("CSV,meta,mldsa_build,small_mem\n");
#endif
    if ((ret = heaptrk_install()) != 0) { printf("ERROR: allocator hook (%d)\n", ret); goto halt; }
    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) {
        printf("ERROR: init failed (%d)\n", ret); goto halt;
    }
    run_all(&rng);
    {
        struct mallinfo mi = mallinfo();
        printf("CSV,heap_arena_bytes,all,%u\n", (unsigned)mi.arena);
        printf("CSV,heap_tracked_peak_bytes,all,%u\n", (unsigned)ht.peak);
    }
    wc_FreeRng(&rng);
    printf("\n=== signature benchmark done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "PQC signature benchmark start (Ed25519 + ML-DSA + Falcon + SLH-DSA, paired)");
}
