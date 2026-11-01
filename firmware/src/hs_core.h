/*
 * Client side of the host-to-device hybrid key exchange (Reviewer 3 point 1).
 * Portable: compiled into the RP2040 firmware (main_handshake.c) and, for
 * testing, into a Linux build that talks to host/hs_server.py over a pty.
 *
 * Protocol (one text line per message over USB CDC; payloads hex-encoded):
 *   device -> host  HS,C2S,<level>,<round>,<hex(X25519 pk || ML-KEM ek)>
 *   host -> device  HS,S2C,<hex(X25519 pk || ML-KEM ct)>,<host_compute_us>
 *   device -> host  HS,FIN,<hex(HMAC-SHA256(K, "client finished" || H))>
 *   host -> device  HS,OK   (or HS,BAD)
 * K   = HKDF-SHA256(salt = none, IKM = ss_MLKEM || ss_X25519,
 *                   info = "rp2040 hybrid x25519+mlkem"), 32 bytes
 * H   = SHA-256(C2S payload || S2C payload)  (transcript binding)
 * Hex encoding is a transport artefact of the text channel; its cost is timed
 * separately from binary serialisation.
 */
#ifndef HS_CORE_H
#define HS_CORE_H
#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

typedef struct {
    int      (*put_line)(const char *line);                       /* adds '\n' */
    int      (*get_line)(char *buf, size_t max, uint32_t timeout_ms);
    uint64_t (*now_us)(void);
} hs_io_t;

enum {
    HS_T_KEYGEN,      /* X25519 keygen + ML-KEM keygen                     */
    HS_T_SERIALISE,   /* export X25519 pk + encode ML-KEM ek (binary)      */
    HS_T_HEXOUT,      /* hex-encode + send line                            */
    HS_T_WAIT,        /* end of send -> complete S2C line received         */
    HS_T_HEXIN,       /* hex-decode S2C payload                            */
    HS_T_PARSE,       /* import server X25519 pk                           */
    HS_T_X25519,      /* client X25519 shared secret                       */
    HS_T_DECAPS,      /* ML-KEM decapsulation                              */
    HS_T_COMBINE,     /* HKDF combiner                                     */
    HS_T_CONFIRM,     /* transcript hash + HMAC + send FIN + wait for OK   */
    HS_T_TOTAL,       /* wall clock, start -> OK received                  */
    HS_T_HOST,        /* host compute time reported by the server          */
    HS_N_T
};
extern const char *HS_T_NAMES[HS_N_T];

/* Runs one complete exchange. Returns 0 on success, negative on error. */
int hs_client_round(const hs_io_t *io, WC_RNG *rng, int kem_type, const char *lvl,
                    uint32_t round, uint64_t t[HS_N_T]);
#endif
