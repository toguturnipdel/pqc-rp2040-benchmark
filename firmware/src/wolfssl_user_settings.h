#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Bare-metal RP2040: wolfCrypt only (no TLS layer, no sockets, no OS) */
#define WOLFCRYPT_ONLY
#define WOLFSSL_NO_SOCK
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_ASN_TIME
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK

/* Seed wolfCrypt's Hash-DRBG from the Pico SDK (implemented in main.c) */
extern int pico_rng_seed(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED pico_rng_seed

/* Classical algorithms */
#define HAVE_ECC
#define HAVE_CURVE25519
#define HAVE_HKDF
#define WOLFSSL_SHA512
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ML-KEM (FIPS 203), wolfSSL native implementation */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Unused algorithms */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_OLD_TLS


/* Signatures: Ed25519 (classical) + ML-DSA + SLH-DSA (native wolfCrypt) */
#define HAVE_ED25519
#define WOLFSSL_HAVE_MLDSA
#define HAVE_DILITHIUM
#define WOLFSSL_HAVE_SLHDSA
#define WOLFSSL_SLHDSA_SHA2        /* enable the 6 SHA2 parameter sets too */
#define WOLFSSL_EXPERIMENTAL_SETTINGS  /* required: native Falcon is experimental */
#define HAVE_FALCON                /* native Falcon/FN-DSA (no liboqs) */


/* ML-DSA low-memory options, required for ML-DSA-87 to fit in 264 KB of SRAM.
 * They lower peak heap use in key generation and signing at some cost in speed. */
#define WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
#define WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
#define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM

#endif /* WOLFSSL_USER_SETTINGS_H */
