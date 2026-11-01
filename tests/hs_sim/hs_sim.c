/* Linux harness running firmware/src/hs_core.c over a pty (test only). */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <termios.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include "hs_core.h"

static int fd;
int host_rng_seed(unsigned char *o, unsigned int sz) { FILE *u = fopen("/dev/urandom", "rb"); size_t n = fread(o, 1, sz, u); fclose(u); return n == sz ? 0 : -1; }
static int put(const char *l) { size_t n = strlen(l); if (write(fd, l, n) != (ssize_t)n || write(fd, "\n", 1) != 1) return -1; return 0; }
static int get(char *b, size_t max, uint32_t ms)
{
    size_t n = 0; struct pollfd p = { fd, POLLIN, 0 };
    while (poll(&p, 1, (int)ms) > 0) {
        char c; if (read(fd, &c, 1) != 1) return -1;
        if (c == '\r') continue;
        if (c == '\n') { b[n] = 0; return 0; }
        if (n + 1 < max) b[n++] = c;
    }
    return -1;
}
static uint64_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000000u + t.tv_nsec / 1000; }

int main(int argc, char **argv)
{
    WC_RNG rng; uint64_t t[HS_N_T];
    const hs_io_t io = { put, get, now };
    const int types[3] = { WC_ML_KEM_512, WC_ML_KEM_768, WC_ML_KEM_1024 };
    const char *lv[3] = { "L1", "L3", "L5" };
    fd = open(argv[1], O_RDWR | O_NOCTTY);
    struct termios tio; tcgetattr(fd, &tio); cfmakeraw(&tio); tcsetattr(fd, TCSANOW, &tio);
    wolfCrypt_Init(); wc_InitRng(&rng);
    char buf[160];
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < 5; i++) {
            int r = hs_client_round(&io, &rng, types[k], lv[k], i, t);
            snprintf(buf, sizeof buf, "RAW,hs_sim,%s,%s,total,%d,%llu,ret=%d", lv[k], lv[k], i, (unsigned long long)t[HS_T_TOTAL], r);
            put(buf);
            if (r) return 1;
        }
    put("=== handshake benchmark done ===");
    return 0;
}
