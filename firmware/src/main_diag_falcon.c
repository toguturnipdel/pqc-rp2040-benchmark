/*
 * Diagnostic: Falcon-1024 signing with wolfCrypt's small-memory signer on the
 * RP2040, without the benchmark's allocator hook, with a HardFault handler.
 *
 * If core 1 faults, the handler records the stacked PC/LR/xPSR and spins; core 0
 * (which keeps USB alive) prints a CSV,fault line. Map the PC to a function with:
 *   arm-none-eabi-addr2line -f -e build/pqc_diag_falcon.elf <pc>
 */
#define FW_NAME            "diag_falcon"
#define CORE1_STACK_WORDS  (40 * 1024 / 4)
#define BENCH_NO_FAULT_HANDLER   /* this file defines its own isr_hardfault */
#include "bench_common.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include "hardware/sync.h"
#include "falcon_ext_keys.h"

typedef struct { volatile uint32_t magic, core, pc, lr, psr, sp, r0, r12; } fault_t;
static fault_t fault;

void __attribute__((used)) hf_capture(uint32_t *frame)
{
    fault.r0 = frame[0]; fault.r12 = frame[4]; fault.lr = frame[5]; fault.pc = frame[6];
    fault.psr = frame[7]; fault.sp = (uint32_t)(uintptr_t)frame;
    fault.core = *(volatile uint32_t *)0xd0000000;      /* SIO CPUID */
    __dmb();
    fault.magic = 0xDEADBEEF;
    while (1) { }
}

/* Overrides the SDK's weak HardFault vector (shared by both cores). */
void __attribute__((naked)) isr_hardfault(void)
{
    __asm volatile(
        "movs r0, #4      \n"
        "mov  r1, lr      \n"
        "tst  r0, r1      \n"
        "beq  1f          \n"
        "mrs  r0, psp     \n"
        "b    2f          \n"
        "1:               \n"
        "mrs  r0, msp     \n"
        "2:               \n"
        "bl   hf_capture  \n");
}

static falcon_key fk;
static uint8_t sig[2048], msg[32];

static void report_heap(const char *when)
{
    struct mallinfo mi = mallinfo();
    printf("CSV,diag_heap,%s,arena=%u,inuse=%u,free=%u\n", when,
           (unsigned)mi.arena, (unsigned)mi.uordblks, (unsigned)mi.fordblks);
}

static void core1_entry(void)
{
    WC_RNG rng; int ret, res;
#ifdef DIAG_HOOK
    meta_print("diag falcon1024 small-memory signer, WITH allocator hook");
    if ((ret = heaptrk_install()) != 0) { printf("ERROR hook %d\n", ret); goto halt; }
#else
    meta_print("diag falcon1024 small-memory signer, no allocator hook");
#endif
    if ((ret = wolfCrypt_Init()) != 0 || (ret = wc_InitRng(&rng)) != 0) { printf("ERROR init %d\n", ret); goto halt; }
    wc_falcon_init(&fk); wc_falcon_set_level(&fk, FALCON_LEVEL5);
    ret = wc_falcon_import_private_key(FALCON1024_PRIV, sizeof FALCON1024_PRIV, FALCON1024_PUB, sizeof FALCON1024_PUB, &fk);
    printf("CSV,diag,import,%d\n", ret);
    report_heap("before_sign");
    for (int i = 0; i < 5; i++) {
        word32 sl = sizeof sig; uint64_t t0, t1;
        msg[0] = (uint8_t)i;
        printf("CSV,diag,sign_start,%d\n", i);
        stdio_flush();
        t0 = time_us_64();
        ret = wc_falcon_sign_msg(msg, sizeof msg, sig, &sl, &fk, &rng);
        t1 = time_us_64();
        printf("CSV,diag,sign_done,%d,ret=%d,us=%llu,sig=%u\n", i, ret, (unsigned long long)(t1 - t0), (unsigned)sl);
        if (ret) { report_heap("after_failed_sign"); break; }
        res = 0;
        ret = wc_falcon_verify_msg(sig, sl, msg, sizeof msg, &res, &fk);
        printf("CSV,diag,verify,%d,ret=%d,res=%d\n", i, ret, res);
        report_heap("after_round");
    }
    wc_falcon_free(&fk);
    wc_FreeRng(&rng);
    printf("\n=== falcon diagnostic done ===\n");
halt:
    while (true) tight_loop_contents();
}

int main(void)
{
    stdio_init_all();
    meta_capture_board_id();
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(1000);
    printf("\n=== Falcon-1024 small-memory diagnostic ===\n");
    multicore_launch_core1_with_stack(core1_entry, core1_stack, sizeof(core1_stack));
    uint64_t last = time_us_64();
    while (true) {
        sleep_ms(200);
        if (fault.magic == 0xDEADBEEF) {
            printf("CSV,fault,core=%u,pc=0x%08x,lr=0x%08x,psr=0x%08x,sp=0x%08x,r0=0x%08x,r12=0x%08x\n",
                   (unsigned)fault.core, (unsigned)fault.pc, (unsigned)fault.lr, (unsigned)fault.psr,
                   (unsigned)fault.sp, (unsigned)fault.r0, (unsigned)fault.r12);
            printf("=== falcon diagnostic (fault) done ===\n");
            fault.magic = 0;
        }
        if (time_us_64() - last > 10000000) { printf("CSV,diag,alive,%llu\n", (unsigned long long)(time_us_64() / 1000000)); last = time_us_64(); }
    }
}
