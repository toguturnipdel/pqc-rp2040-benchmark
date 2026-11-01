/* Host (x86-64/aarch64 Linux) wolfCrypt settings for the Falcon key-provisioning
 * tool. Same Falcon implementation and integer-emulated FPR backend as the
 * RP2040 firmware (no WOLFSSL_FALCON_FPR_DOUBLE/ASM), so key generation uses
 * the identical code path. */
#ifndef HOST_USER_SETTINGS_H
#define HOST_USER_SETTINGS_H
#define WOLFCRYPT_ONLY
#define NO_FILESYSTEM
#define SINGLE_THREADED
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHA512
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_FALCON
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
/* Seed the DRBG from /dev/urandom through a hook (implemented in falcon_keygen.c);
 * the default Linux seed path fails in some sandboxed environments. */
extern int host_rng_seed(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED host_rng_seed
#endif
