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

/* Optional P-256 with wolfCrypt SP math and its ARMv6-M Thumb assembly
 * (classical alternative to X25519; enabled with -DWITH_P256). */
#ifdef WITH_P256
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_ARM_THUMB_ASM
    #define WOLFSSL_SP_NO_384
    #define WOLFSSL_SP_NO_521
    #define ECC_USER_CURVES
#endif

/* Optional wolfCrypt small Curve25519/Ed25519 implementation (fe_low_mem.c)
 * instead of the default ref10-style fe_operations.c (-DCURVE_SMALL). */
#ifdef CURVE_SMALL
    #define CURVED25519_SMALL
#endif

/* Optional speed-oriented ML-DSA build (-DMLDSA_SPEED): drops the low-memory
 * options below. ML-DSA-87 is not expected to fit in this configuration. */
#ifdef MLDSA_SPEED
    #undef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    #undef WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
    #undef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
    #undef WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#endif

/* Optional small-memory Falcon signer (-DFALCON_SIGN_SMALL). The default signer
 * allocates the expanded key and scratch as one block (about 180 KB for
 * Falcon-1024), which exceeds the RP2040 heap; this signer needs about 90 KB. */
#ifdef FALCON_SIGN_SMALL
    #define WOLFSSL_FALCON_SIGN_SMALL_MEM
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
