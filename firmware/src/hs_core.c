#include "hs_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>

const char *HS_T_NAMES[HS_N_T] = {
    "keygen", "serialise", "hex_send", "wait", "hex_recv", "parse",
    "x25519_shared", "kem_decaps", "combine", "confirm", "total", "host_compute",
};

#define XL 32
#define EK_MAX 1568
#define CT_MAX 1568
static curve25519_key xc, xs;
static MlKemKey kem;
static uint8_t c2s[XL + EK_MAX], s2c[XL + CT_MAX];
static char line[2 * (XL + CT_MAX) + 128];

static const char HEX[] = "0123456789abcdef";
static void hex_enc(char *o, const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) { o[2*i] = HEX[b[i] >> 4]; o[2*i+1] = HEX[b[i] & 15]; } o[2*n] = 0; }
static int hv(char c) { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1; }
static int hex_dec(uint8_t *o, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) { int a = hv(s[2*i]), b = hv(s[2*i+1]); if (a < 0 || b < 0) return -1; o[i] = (uint8_t)(a << 4 | b); }
    return 0;
}

int hs_client_round(const hs_io_t *io, WC_RNG *rng, int kem_type, const char *lvl,
                    uint32_t round, uint64_t t[HS_N_T])
{
    int ret = 0;
    word32 ekl = 0, ctl = 0, l;
    uint8_t ssx[XL], ssk[32], ikm[64], K[32], H[32], tag[32];
    static const byte INFO[] = "rp2040 hybrid x25519+mlkem";
    static const byte FIN[] = "client finished";
    uint64_t t0, a, start;
    memset(t, 0, sizeof(uint64_t) * HS_N_T);

    wc_curve25519_init(&xc); wc_curve25519_init(&xs);
    if ((ret = wc_MlKemKey_Init(&kem, kem_type, NULL, INVALID_DEVID)) != 0) goto out;
    wc_MlKemKey_PublicKeySize(&kem, &ekl);
    wc_MlKemKey_CipherTextSize(&kem, &ctl);

    start = io->now_us();
    /* keygen */
    t0 = io->now_us();
    if ((ret = wc_curve25519_make_key(rng, XL, &xc)) != 0) goto out;
    if ((ret = wc_MlKemKey_MakeKey(&kem, rng)) != 0) goto out;
    t[HS_T_KEYGEN] = io->now_us() - t0;
    /* binary serialisation */
    t0 = io->now_us(); l = XL;
    if ((ret = wc_curve25519_export_public_ex(&xc, c2s, &l, EC25519_LITTLE_ENDIAN)) != 0) goto out;
    if ((ret = wc_MlKemKey_EncodePublicKey(&kem, c2s + XL, ekl)) != 0) goto out;
    t[HS_T_SERIALISE] = io->now_us() - t0;
    /* hex + send */
    t0 = io->now_us();
    int n = snprintf(line, sizeof line, "HS,C2S,%s,%lu,", lvl, (unsigned long)round);
    hex_enc(line + n, c2s, XL + ekl);
    if ((ret = io->put_line(line)) != 0) goto out;
    t[HS_T_HEXOUT] = io->now_us() - t0;
    /* wait for S2C */
    t0 = io->now_us();
    if ((ret = io->get_line(line, sizeof line, 10000)) != 0) { ret = -100; goto out; }
    t[HS_T_WAIT] = io->now_us() - t0;
    if (strncmp(line, "HS,S2C,", 7) != 0) { ret = -101; goto out; }
    /* hex decode */
    t0 = io->now_us();
    if (strlen(line + 7) < 2 * (size_t)(XL + ctl) + 2 || hex_dec(s2c, line + 7, XL + ctl) != 0) { ret = -102; goto out; }
    t[HS_T_HEXIN] = io->now_us() - t0;
    t[HS_T_HOST] = strtoull(line + 7 + 2 * (XL + ctl) + 1, NULL, 10);
    /* parse */
    t0 = io->now_us();
    if ((ret = wc_curve25519_import_public_ex(s2c, XL, &xs, EC25519_LITTLE_ENDIAN)) != 0) goto out;
    t[HS_T_PARSE] = io->now_us() - t0;
    /* X25519 */
    t0 = io->now_us(); l = XL;
    if ((ret = wc_curve25519_shared_secret_ex(&xc, &xs, ssx, &l, EC25519_LITTLE_ENDIAN)) != 0) goto out;
    t[HS_T_X25519] = io->now_us() - t0;
    /* ML-KEM decaps */
    t0 = io->now_us();
    if ((ret = wc_MlKemKey_Decapsulate(&kem, ssk, s2c + XL, ctl)) != 0) goto out;
    t[HS_T_DECAPS] = io->now_us() - t0;
    /* combiner */
    t0 = io->now_us();
    memcpy(ikm, ssk, 32); memcpy(ikm + 32, ssx, 32);
    if ((ret = wc_HKDF(WC_SHA256, ikm, 64, NULL, 0, INFO, sizeof INFO - 1, K, 32)) != 0) goto out;
    t[HS_T_COMBINE] = io->now_us() - t0;
    /* key confirmation: transcript hash, HMAC, FIN, wait for OK */
    t0 = io->now_us();
    {
        wc_Sha256 sh; Hmac hm;
        if ((ret = wc_InitSha256(&sh)) != 0) goto out;
        wc_Sha256Update(&sh, c2s, XL + ekl); wc_Sha256Update(&sh, s2c, XL + ctl); wc_Sha256Final(&sh, H);
        wc_Sha256Free(&sh);
        if ((ret = wc_HmacInit(&hm, NULL, INVALID_DEVID)) != 0) goto out;
        if ((ret = wc_HmacSetKey(&hm, WC_SHA256, K, 32)) == 0) {
            wc_HmacUpdate(&hm, FIN, sizeof FIN - 1); wc_HmacUpdate(&hm, H, 32); ret = wc_HmacFinal(&hm, tag);
        }
        wc_HmacFree(&hm);
        if (ret) goto out;
    }
    strcpy(line, "HS,FIN,"); hex_enc(line + 7, tag, 32);
    if ((ret = io->put_line(line)) != 0) goto out;
    a = io->now_us();
    if ((ret = io->get_line(line, sizeof line, 10000)) != 0) { ret = -103; goto out; }
    if (strcmp(line, "HS,OK") != 0) { ret = -104; goto out; }
    t[HS_T_CONFIRM] = io->now_us() - t0;
    (void)a;
    t[HS_T_TOTAL] = io->now_us() - start;
out:
    wc_MlKemKey_Free(&kem);
    wc_curve25519_free(&xc); wc_curve25519_free(&xs);
    return ret;
}
