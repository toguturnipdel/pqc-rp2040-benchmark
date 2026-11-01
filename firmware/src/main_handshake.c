/*
 * Host-to-device hybrid key exchange over USB serial (Reviewer 3 point 1).
 * The Pico is the client (see hs_core.h); host/hs_server.py is the server.
 * Per round the device reports its own compute, binary serialisation, the
 * hex transport encoding, the wait for the server reply, and the server's
 * compute time, so link time = wait - host_compute can be separated.
 * USB full-speed CDC is not an IoT radio: the link figures characterise this
 * setup only; the device-side compute and serialisation figures are the
 * transferable part.
 */
#define FW_NAME            "handshake"
#define CORE1_STACK_WORDS  (32 * 1024 / 4)
#include "bench_common.h"
#include "hs_core.h"
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#ifndef HS_ROUNDS
#define HS_ROUNDS 50
#endif

/* Long hex lines (up to ~3.2 KB) are written in 64-byte chunks with a flush after
 * each, so the USB CDC driver never has to buffer a whole line; under WSL/usbipd
 * the default stdout timeout otherwise drops characters. */
static int io_put(const char *l)
{
    size_t n = strlen(l);
    for (size_t i = 0; i < n; i += 64) {
        size_t k = (n - i < 64) ? n - i : 64;
        fwrite(l + i, 1, k, stdout);
        fflush(stdout);
        stdio_flush();
    }
    putchar('\n'); fflush(stdout); stdio_flush();
    return 0;
}
static int io_get(char *buf, size_t max, uint32_t timeout_ms)
{
    size_t n = 0;
    absolute_time_t until = make_timeout_time_ms(timeout_ms);
    while (!time_reached(until)) {
        int c = getchar_timeout_us(1000);
        if (c == PICO_ERROR_TIMEOUT) continue;
        if (c == '\r') continue;
        if (c == '\n') { buf[n] = 0; return 0; }
        if (n + 1 < max) buf[n++] = (char)c;
    }
    return -1;
}
static uint64_t io_now(void) { return time_us_64(); }
static const hs_io_t IO = { io_put, io_get, io_now };

static const struct { const char *name, *lvl; int type; } KEMS[] = {
    { "X25519+ML-KEM-512", "L1", WC_ML_KEM_512 },
    { "X25519+ML-KEM-768", "L3", WC_ML_KEM_768 },
    { "X25519+ML-KEM-1024", "L5", WC_ML_KEM_1024 },
};

static void core1_entry(void)
{
    WC_RNG rng; int ret;
    uint64_t t[HS_N_T];
    char cfg[48]; snprintf(cfg, sizeof cfg, "rounds=%d transport=usb-cdc-hex", HS_ROUNDS);
    meta_print(cfg);
    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) { printf("ERROR init %d\n", ret); goto halt; }
    for (unsigned k = 0; k < 3; k++) {
        for (int i = -1; i < HS_ROUNDS; i++) {
            if ((ret = hs_client_round(&IO, &rng, KEMS[k].type, KEMS[k].lvl, (uint32_t)(i < 0 ? 0 : i), t)) != 0) {
                printf("CSV,hs_error,%s,%d,%d\n", KEMS[k].lvl, i, ret);
                goto done;
            }
            if (i < 0) continue;
            for (int j = 0; j < HS_N_T; j++) raw(KEMS[k].name, KEMS[k].lvl, HS_T_NAMES[j], (uint32_t)i, t[j]);
        }
    }
done:
    wc_FreeRng(&rng);
    printf("=== handshake benchmark done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    bench_main(core1_entry, "Hybrid key-exchange handshake over USB (device = client)");
}
