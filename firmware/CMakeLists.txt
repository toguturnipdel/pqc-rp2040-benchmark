cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(pqc_pico_testbed C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
pico_sdk_init()

# wolfSSL source tree (tested with commit 5b9f179); override with -DWOLFSSL_ROOT=<path>
if(NOT DEFINED WOLFSSL_ROOT)
    set(WOLFSSL_ROOT $ENV{HOME}/pico/wolfssl)
endif()
if(NOT EXISTS ${WOLFSSL_ROOT}/wolfcrypt/src)
    message(FATAL_ERROR "wolfSSL not found at ${WOLFSSL_ROOT}")
endif()

file(GLOB WOLFCRYPT_SRC ${WOLFSSL_ROOT}/wolfcrypt/src/*.c)
# misc.c and evp.c are #included by other files, not compiled on their own
list(FILTER WOLFCRYPT_SRC EXCLUDE REGEX ".*/(misc|evp)\\.c$")

# Optional GPIO pin held high during every timed operation (external current
# meter or oscilloscope trigger), e.g. -DTRIG_GPIO=15. Empty: disabled.
set(TRIG_GPIO "" CACHE STRING "GPIO pin for the measurement trigger (empty = off)")

# Signature timing firmware split (runtime): 0 all, 1 lattice, 2 SLH-DSA f, 3 SLH-DSA s
set(SIG_PART "0" CACHE STRING "Signature firmware part: 0 all, 1 lattice, 2 SLH-DSA f, 3 SLH-DSA s")

# ---------------------------------------------------------------------------
# One executable. Extra compile definitions select the wolfCrypt configuration
# (WITH_P256, CURVE_SMALL, MLDSA_SPEED); they are applied to wolfCrypt too.
# ---------------------------------------------------------------------------
function(add_bench name)
    cmake_parse_arguments(B "" "" "SOURCES;DEFS;LIBS" ${ARGN})
    add_executable(${name} ${B_SOURCES} ${WOLFCRYPT_SRC})
    target_compile_definitions(${name} PRIVATE WOLFSSL_USER_SETTINGS
        PICO_MALLOC_PANIC=0     # OOM returns NULL instead of panicking; benchmark handles it
        PICO_DEBUG_MALLOC=0 ${B_DEFS})
    if(NOT TRIG_GPIO STREQUAL "")
        target_compile_definitions(${name} PRIVATE TRIG_GPIO=${TRIG_GPIO})
    endif()
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${WOLFSSL_ROOT})
    target_compile_options(${name} PRIVATE -O3)
    pico_enable_stdio_usb(${name} 1)
    pico_enable_stdio_uart(${name} 0)
    target_link_libraries(${name} pico_stdlib pico_multicore pico_rand pico_unique_id
        hardware_timer hardware_clocks hardware_gpio ${B_LIBS})
    pico_add_extra_outputs(${name})
endfunction()

# --- Key exchange ------------------------------------------------------------
add_bench(pqc_pico_testbed SOURCES src/main.c)                          # X25519 + ML-KEM, complete exchange
add_bench(pqc_kem_p256     SOURCES src/main.c DEFS WITH_P256)           # + P-256 (SP Thumb asm)
add_bench(pqc_kem_sram     SOURCES src/main.c)                          # same, code copied to SRAM
pico_set_binary_type(pqc_kem_sram copy_to_ram)

# --- Signatures --------------------------------------------------------------
# One target per run part, so all parts build in one tree (no SIG_PART rebuilds).
add_bench(pqc_sig_testbed  SOURCES src/main_sig.c DEFS SIG_PART=${SIG_PART})   # everything in one run (long)
add_bench(pqc_sig_lattice  SOURCES src/main_sig.c DEFS SIG_PART=1)             # Ed25519, ML-DSA, Falcon (default signer)
add_bench(pqc_sig_slh_f    SOURCES src/main_sig.c DEFS SIG_PART=2)             # SLH-DSA f sets
add_bench(pqc_sig_slh_s    SOURCES src/main_sig.c DEFS SIG_PART=3)             # SLH-DSA s sets
add_bench(pqc_sig_falcon_small SOURCES src/main_sig.c DEFS SIG_PART=4 FALCON_SIGN_SMALL)  # Falcon, small-memory signer
add_bench(pqc_sig_mem      SOURCES src/main_sig.c DEFS BENCH_MODE_MEM SIG_PART=${SIG_PART})
add_bench(pqc_sig_mem_lattice SOURCES src/main_sig.c DEFS BENCH_MODE_MEM SIG_PART=1)
add_bench(pqc_sig_mem_slh_f   SOURCES src/main_sig.c DEFS BENCH_MODE_MEM SIG_PART=2)
add_bench(pqc_sig_mem_slh_s   SOURCES src/main_sig.c DEFS BENCH_MODE_MEM SIG_PART=3)
add_bench(pqc_sig_mem_falcon_small SOURCES src/main_sig.c DEFS BENCH_MODE_MEM SIG_PART=4 FALCON_SIGN_SMALL)
add_bench(pqc_mldsa_dist       SOURCES src/main_mldsa_dist.c)                   # 10,000 samples/level
add_bench(pqc_mldsa_dist_speed SOURCES src/main_mldsa_dist.c DEFS MLDSA_SPEED BENCH_MLDSA_SAMPLES=1000)  # speed build, 1,000/level

# --- SLH-DSA code location (XIP vs SRAM) --------------------------------------
add_bench(pqc_slh_xip  SOURCES src/main_slh_codeloc.c)
add_bench(pqc_slh_sram SOURCES src/main_slh_codeloc.c)
pico_set_binary_type(pqc_slh_sram copy_to_ram)

# --- X25519 implementation comparison -----------------------------------------
# Two renamed copies of x25519-cm0.S: one in .text (XIP), one in .time_critical (SRAM)
set(CM0_SRC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/x25519-cm0/x25519-cm0.S)
file(READ ${CM0_SRC} CM0_ASM)
foreach(v flash ram)
    string(REPLACE "\t.global\tx25519\n" "\t.global\tx25519_cm0_${v}\n" A "${CM0_ASM}")
    string(REPLACE "\t.type\tx25519, %function\nx25519:" "\t.type\tx25519_cm0_${v}, %function\nx25519_cm0_${v}:" A "${A}")
    string(REPLACE "\t.size\tx25519, .-x25519" "\t.size\tx25519_cm0_${v}, .-x25519_cm0_${v}" A "${A}")
    if(v STREQUAL "ram")
        string(REPLACE "\t.text\n" "\t.section\t.time_critical.x25519_cm0,\"ax\",%progbits\n" A "${A}")
    endif()
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/x25519_cm0_${v}.S "${A}")
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CM0_SRC})
set(CM0_GEN ${CMAKE_CURRENT_BINARY_DIR}/x25519_cm0_flash.S ${CMAKE_CURRENT_BINARY_DIR}/x25519_cm0_ram.S)
add_bench(pqc_x25519_alt       SOURCES src/main_x25519_alt.c ${CM0_GEN})
add_bench(pqc_x25519_alt_small SOURCES src/main_x25519_alt.c ${CM0_GEN} DEFS CURVE_SMALL)

# --- Host-to-device handshake ---------------------------------------------------
add_bench(pqc_handshake SOURCES src/main_handshake.c src/hs_core.c DEFS PICO_STDIO_USB_STDOUT_TIMEOUT_US=3000000)

# --- Diagnostic: Falcon-1024 small-memory signer with HardFault capture -------
add_bench(pqc_diag_falcon SOURCES src/main_diag_falcon.c DEFS FALCON_SIGN_SMALL)
add_bench(pqc_diag_falcon_hook SOURCES src/main_diag_falcon.c DEFS FALCON_SIGN_SMALL DIAG_HOOK)

# --- Original SLH-DSA SHA2 completion run (unchanged, kept for reproducibility) -
add_bench(pqc_sha2_testbed SOURCES src/main_sha2.c)

# --- Energy calibration (GPIO trigger; defaults to GPIO 15 unless TRIG_GPIO is set) -
if(TRIG_GPIO STREQUAL "")
    add_bench(pqc_energy SOURCES src/main_energy.c DEFS TRIG_GPIO=15)
else()
    add_bench(pqc_energy SOURCES src/main_energy.c)
endif()
