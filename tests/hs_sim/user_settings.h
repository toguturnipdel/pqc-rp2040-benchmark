/* Host settings for the handshake simulation test (same algorithms as firmware). */
#ifndef HS_SIM_SETTINGS_H
#define HS_SIM_SETTINGS_H
#define WOLFCRYPT_ONLY
#define NO_FILESYSTEM
#define SINGLE_THREADED
#define HAVE_CURVE25519
#define HAVE_HKDF
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
extern int host_rng_seed(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED host_rng_seed
#endif
