/*
 * Shared benchmark infrastructure for the RP2040 firmware (header-only).
 *
 * Provides:
 *   - wolfCrypt DRBG seed hook (pico_rand)
 *   - timing with per-sample RAW output (analysis computes median, percentiles,
 *     confidence intervals and cycles from these lines)
 *   - per-operation peak heap tracking through wolfSSL_SetAllocators, with an
 *     optional hard heap cap used to emulate RFC 7228 RAM budgets
 *   - per-operation peak stack measurement by stack painting on core 1
 *   - optional GPIO trigger around every timed operation (for an external
 *     current meter or oscilloscope)
 *   - run metadata (wolfSSL version, clock, board unique id, firmware, config)
 *
 * Output lines (all parsed by analysis/pqcdata_v2.py):
 *   CSV,meta,<key>,<value>
 *   RAW,<fw>,<scheme>,<level>,<op>,<sample>,<us>
 *   CSV,mem,<fw>,<scheme>,<level>,<op>,<stack_B>,<heap_peak_B>,<heap_base_B>,<static_B>,<ret>
 *   CSV,budget,<fw>,<scheme>,<level>,<op>,<class>,<ram_B>,<heap_cap_B>,<stack_B>,<static_B>,<result>
 *   CSV,allocfail,<fw>,<scheme>,<level>,<op>,<fails>,<largest_failed_B>,<heap_at_fail_B>
 *
 * Include this file once per firmware, after defining CORE1_STACK_WORDS and FW_NAME.
 */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <malloc.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/rand.h"
#include "pico/unique_id.h"
#include "hardware/clocks.h"
#include "hardware/gpio.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifndef CORE1_STACK_WORDS
#error "define CORE1_STACK_WORDS before including bench_common.h"
#endif
#ifndef FW_NAME
#error "define FW_NAME before including bench_common.h"
#endif

/* ------------------------------------------------------------------------ */
/* Core 1 stack (used for stack painting)                                    */
/* ------------------------------------------------------------------------ */
/* AAPCS requires an 8-byte-aligned stack pointer at every public call boundary.
 * Without the attribute the array is only 4-byte aligned, and depending on the
 * link layout core 1 can start with SP = 4 (mod 8); -O3 code then mis-reads
 * 64-bit values (printf %llu, int64 locals) and wolfCrypt calls return garbage. */
static uint32_t core1_stack[CORE1_STACK_WORDS] __attribute__((aligned(8)));
_Static_assert((CORE1_STACK_WORDS * 4) % 8 == 0, "core-1 stack size must be a multiple of 8 bytes");

/* ------------------------------------------------------------------------ */
/* Entropy hook for wolfCrypt (benchmark-grade, not a certified source)       */
/* ------------------------------------------------------------------------ */
int pico_rng_seed(unsigned char *out, unsigned int sz)
{
    while (sz > 0) {
        uint32_t r = get_rand_32();
        unsigned int n = (sz < 4) ? sz : 4;
        memcpy(out, &r, n);
        out += n; sz -= n;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Optional GPIO trigger (define TRIG_GPIO=<pin> at build time)               */
/* High for the duration of each timed operation. Costs about 1 us.          */
/* ------------------------------------------------------------------------ */
#ifdef TRIG_GPIO
static inline void trig_init(void) { gpio_init(TRIG_GPIO); gpio_set_dir(TRIG_GPIO, GPIO_OUT); gpio_put(TRIG_GPIO, 0); }
static inline void trig_on(void)   { gpio_put(TRIG_GPIO, 1); }
static inline void trig_off(void)  { gpio_put(TRIG_GPIO, 0); }
#else
static inline void trig_init(void) {}
static inline void trig_on(void)   {}
static inline void trig_off(void)  {}
#endif

/* Time one call: ret receives the return value, dst the elapsed microseconds. */
#define TIMED(dst, call) do { trig_on(); uint64_t t0_ = time_us_64(); ret = (call); \
                              (dst) = time_us_64() - t0_; trig_off(); } while (0)

/* ------------------------------------------------------------------------ */
/* Summary statistics (mean/min/max kept for backward-compatible CSV lines)   */
/* ------------------------------------------------------------------------ */
typedef struct { uint64_t sum, min, max; uint32_t n; } stat_t;
static inline void st_init(stat_t *s) { s->sum = 0; s->min = UINT64_MAX; s->max = 0; s->n = 0; }
static inline void st_add(stat_t *s, uint64_t v) { s->sum += v; if (v < s->min) s->min = v; if (v > s->max) s->max = v; s->n++; }
static inline uint64_t st_avg(const stat_t *s) { return s->n ? s->sum / s->n : 0; }

/* One RAW line per measured sample. */
static inline void raw(const char *scheme, const char *lvl, const char *op, uint32_t i, uint64_t us)
{
    printf("RAW," FW_NAME ",%s,%s,%s,%" PRIu32 ",%llu\n", scheme, lvl, op, i, (unsigned long long)us);
}

/* ------------------------------------------------------------------------ */
/* Heap tracking through wolfSSL_SetAllocators                               */
/* Counts the bytes wolfCrypt requests (allocator overhead excluded).        */
/* A hard cap makes allocations fail once the live total would exceed it.    */
/* ------------------------------------------------------------------------ */
typedef struct {
    size_t   cur, peak, cap;
    uint32_t fails;
    size_t   largest_fail, cur_at_fail;
} heaptrk_t;

static heaptrk_t ht = { 0, 0, SIZE_MAX, 0, 0, 0 };
#define HT_HDR 8u   /* keeps 8-byte alignment of the returned pointer */

static void ht_fail(size_t sz)
{
    ht.fails++;
    if (sz > ht.largest_fail) { ht.largest_fail = sz; ht.cur_at_fail = ht.cur; }
}
static void *ht_malloc(size_t sz)
{
    if (ht.cap != SIZE_MAX && ht.cur + sz > ht.cap) { ht_fail(sz); return NULL; }
    uint8_t *p = (uint8_t *)malloc(sz + HT_HDR);
    if (p == NULL) { ht_fail(sz); return NULL; }
    *(size_t *)p = sz;
    ht.cur += sz;
    if (ht.cur > ht.peak) ht.peak = ht.cur;
    return p + HT_HDR;
}
static void ht_free(void *ptr)
{
    if (ptr == NULL) return;
    uint8_t *p = (uint8_t *)ptr - HT_HDR;
    ht.cur -= *(size_t *)p;
    free(p);
}
static void *ht_realloc(void *ptr, size_t sz)
{
    if (ptr == NULL) return ht_malloc(sz);
    if (sz == 0) { ht_free(ptr); return NULL; }
    uint8_t *p = (uint8_t *)ptr - HT_HDR;
    size_t old = *(size_t *)p;
    if (ht.cap != SIZE_MAX && ht.cur - old + sz > ht.cap) { ht_fail(sz); return NULL; }
    uint8_t *q = (uint8_t *)realloc(p, sz + HT_HDR);
    if (q == NULL) { ht_fail(sz); return NULL; }
    *(size_t *)q = sz;
    ht.cur = ht.cur - old + sz;
    if (ht.cur > ht.peak) ht.peak = ht.cur;
    return q + HT_HDR;
}
/* Must be called before wolfCrypt_Init() so every allocation is tracked. */
static inline int heaptrk_install(void) { return wolfSSL_SetAllocators(ht_malloc, ht_free, ht_realloc); }
static inline void heaptrk_reset_peak(void) { ht.peak = ht.cur; ht.fails = 0; ht.largest_fail = 0; ht.cur_at_fail = 0; }

/* ------------------------------------------------------------------------ */
/* Stack painting on core 1                                                  */
/* ------------------------------------------------------------------------ */
#define PAINT 0xC0FFEE11u
static __attribute__((noinline)) uint32_t *stack_ref(void)
{
    return (uint32_t *)((uintptr_t)__builtin_frame_address(0) & ~(uintptr_t)3);
}
static __attribute__((noinline)) void stack_paint(uint32_t *ref)
{
    for (uint32_t *p = core1_stack; p < ref - 128; p++)   /* stay 512 B below live frames */
        *p = PAINT;
}
static inline uint32_t stack_depth(uint32_t *ref)
{
    uint32_t *p = core1_stack;
    while (p < ref && *p == PAINT) p++;
    return (uint32_t)((ref - p) * 4);
}

/* ------------------------------------------------------------------------ */
/* Per-operation memory measurement and RAM-budget enforcement               */
/* ------------------------------------------------------------------------ */
typedef int (*op_fn)(void *ctx);

typedef struct { uint32_t stack; size_t heap_peak, heap_base; int ret; } mem_t;

/* Run op once, unconstrained; record peak stack and peak heap above the
 * baseline (memory already live before the call, e.g. the DRBG state). */
static int mem_measure(const char *scheme, const char *lvl, const char *op,
                       op_fn fn, void *ctx, size_t static_b, mem_t *out)
{
    heaptrk_reset_peak();
    size_t base = ht.cur;
    uint32_t *ref = stack_ref();
    stack_paint(ref);
    int r = fn(ctx);
    uint32_t d = stack_depth(ref);
    mem_t m = { d, ht.peak - base, base, r };
    if (out) *out = m;
    printf("CSV,mem," FW_NAME ",%s,%s,%s,%" PRIu32 ",%u,%u,%u,%d\n", scheme, lvl, op,
           d, (unsigned)(ht.peak - base), (unsigned)base, (unsigned)static_b, r);
    if (ht.fails)
        printf("CSV,allocfail," FW_NAME ",%s,%s,%s,%" PRIu32 ",%u,%u\n", scheme, lvl, op,
               ht.fails, (unsigned)ht.largest_fail, (unsigned)ht.cur_at_fail);
    return r;
}

/* RFC 7228 RAM classes emulated on the RP2040 (KiB = 1024 B). */
typedef struct { const char *name; size_t ram; } ram_class_t;
static const ram_class_t RAM_CLASSES[] = {
    { "C1", 10u * 1024u },
    { "C2", 50u * 1024u },
};
#define N_RAM_CLASSES (sizeof(RAM_CLASSES) / sizeof(RAM_CLASSES[0]))

/* Budget model: static objects + peak stack + live heap must fit in the class RAM.
 * The heap cap for the enforced run is RAM - static - stack (absolute live heap,
 * including the baseline). Ops whose measured footprint exceeds the class RAM are
 * reported EXCEEDS without running. Code/flash, the USB stack and the SDK runtime
 * are not counted; fragmentation of a real small-RAM allocator is not modelled. */
static void mem_budget(const char *scheme, const char *lvl, const char *op,
                       op_fn fn, void *ctx, size_t static_b, const mem_t *m)
{
    for (unsigned c = 0; c < N_RAM_CLASSES; c++) {
        size_t ram = RAM_CLASSES[c].ram;
        size_t footprint = static_b + m->stack + m->heap_base + m->heap_peak;
        const char *res;
        size_t cap = 0;
        if (m->ret != 0) {
            res = "NOT_RUN_UNCONSTRAINED_FAILED";
        } else if (footprint > ram) {
            res = "EXCEEDS";
        } else {
            cap = ram - static_b - m->stack;
            heaptrk_reset_peak();
            ht.cap = cap;
            uint32_t *ref = stack_ref();
            stack_paint(ref);
            int r = fn(ctx);
            uint32_t d = stack_depth(ref);
            ht.cap = SIZE_MAX;
            if (r != 0 || ht.fails)           res = "FAIL_ALLOC";
            else if (static_b + d + ht.peak > ram) res = "FAIL_STACK";
            else                               res = "PASS";
        }
        printf("CSV,budget," FW_NAME ",%s,%s,%s,%s,%u,%u,%" PRIu32 ",%u,%s\n", scheme, lvl, op,
               RAM_CLASSES[c].name, (unsigned)ram, (unsigned)cap, m->stack,
               (unsigned)static_b, res);
    }
}

/* ------------------------------------------------------------------------ */
/* Run metadata                                                              */
/* ------------------------------------------------------------------------ */
static char board_id[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];

/* Read the flash unique id on core 0 before core 1 starts (flash access). */
static inline void meta_capture_board_id(void) { pico_get_unique_board_id_string(board_id, sizeof board_id); }

static void meta_print(const char *config)
{
    extern char end, __StackLimit;          /* heap start and maximum heap address (linker) */
    printf("CSV,meta,firmware," FW_NAME "\n");
    printf("CSV,meta,wolfssl,%s\n", LIBWOLFSSL_VERSION_STRING);
    printf("CSV,meta,clk_sys_hz,%" PRIu32 "\n", clock_get_hz(clk_sys));
    printf("CSV,meta,board_id,%s\n", board_id);
    printf("CSV,meta,config,%s\n", config);
    printf("CSV,meta,heap_capacity_bytes,%u\n", (unsigned)(&__StackLimit - &end));
#ifdef PICO_COPY_TO_RAM
    printf("CSV,meta,code_location,%s\n", PICO_COPY_TO_RAM ? "SRAM" : "XIP");
#else
    printf("CSV,meta,code_location,XIP\n");
#endif
#ifdef TRIG_GPIO
    printf("CSV,meta,trigger_gpio,%d\n", TRIG_GPIO);
#endif
}

/* HardFault capture (both cores share the vector). The faulting core records the
 * stacked registers and spins; core 0 prints a CSV,fault line from bench_main.
 * Map the PC to a function: arm-none-eabi-addr2line -f -e build/<target>.elf <pc>
 * Firmware that defines its own isr_hardfault sets BENCH_NO_FAULT_HANDLER. */
typedef struct { volatile uint32_t magic, core, pc, lr, psr, sp; } bench_fault_t;
static bench_fault_t bench_fault;
#ifndef BENCH_NO_FAULT_HANDLER
void __attribute__((used)) bench_hf_capture(uint32_t *frame)
{
    bench_fault.lr = frame[5]; bench_fault.pc = frame[6]; bench_fault.psr = frame[7];
    bench_fault.sp = (uint32_t)(uintptr_t)frame;
    bench_fault.core = *(volatile uint32_t *)0xd0000000;     /* SIO CPUID */
    __asm volatile("dmb" ::: "memory");
    bench_fault.magic = 0xDEADBEEF;
    while (1) { }
}
void __attribute__((naked)) isr_hardfault(void)
{
    __asm volatile("movs r0, #4\n mov r1, lr\n tst r0, r1\n beq 1f\n mrs r0, psp\n b 2f\n"
                   "1: mrs r0, msp\n 2: bl bench_hf_capture\n");
}
#endif

/* Common core-0 main: wait for USB, capture id, start core 1, report faults. */
static void bench_main(void (*core1_entry)(void), const char *banner)
{
    stdio_init_all();
    meta_capture_board_id();
    trig_init();
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(1000);
    printf("\n=== %s ===\n", banner);
    multicore_launch_core1_with_stack(core1_entry, core1_stack, sizeof(core1_stack));
    while (true) {
        sleep_ms(200);
        if (bench_fault.magic == 0xDEADBEEF) {
            printf("CSV,fault,core=%u,pc=0x%08x,lr=0x%08x,psr=0x%08x,sp=0x%08x\n",
                   (unsigned)bench_fault.core, (unsigned)bench_fault.pc, (unsigned)bench_fault.lr,
                   (unsigned)bench_fault.psr, (unsigned)bench_fault.sp);
            printf("=== benchmark aborted by fault, done ===\n");
            bench_fault.magic = 0;
        }
    }
}

#endif /* BENCH_COMMON_H */
