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

add_executable(pqc_pico_testbed src/main.c ${WOLFCRYPT_SRC})

target_compile_definitions(pqc_pico_testbed PRIVATE WOLFSSL_USER_SETTINGS)
target_include_directories(pqc_pico_testbed PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${WOLFSSL_ROOT}
)
target_compile_options(pqc_pico_testbed PRIVATE -O3)

pico_enable_stdio_usb(pqc_pico_testbed 1)
pico_enable_stdio_uart(pqc_pico_testbed 0)

target_link_libraries(pqc_pico_testbed
    pico_stdlib pico_multicore pico_rand hardware_timer hardware_clocks
)
pico_add_extra_outputs(pqc_pico_testbed)

# Signature benchmark
add_executable(pqc_sig_testbed src/main_sig.c ${WOLFCRYPT_SRC})
target_compile_definitions(pqc_sig_testbed PRIVATE WOLFSSL_USER_SETTINGS
    PICO_MALLOC_PANIC=0        # OOM returns NULL instead of panicking; benchmark handles it
    PICO_DEBUG_MALLOC=0)
target_include_directories(pqc_sig_testbed PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src ${WOLFSSL_ROOT})
target_compile_options(pqc_sig_testbed PRIVATE -O3)
pico_enable_stdio_usb(pqc_sig_testbed 1)
pico_enable_stdio_uart(pqc_sig_testbed 0)
target_link_libraries(pqc_sig_testbed pico_stdlib pico_multicore pico_rand hardware_timer hardware_clocks)
pico_add_extra_outputs(pqc_sig_testbed)

# SLH-DSA SHA2 benchmark
add_executable(pqc_sha2_testbed src/main_sha2.c ${WOLFCRYPT_SRC})
target_compile_definitions(pqc_sha2_testbed PRIVATE WOLFSSL_USER_SETTINGS
    PICO_MALLOC_PANIC=0 PICO_DEBUG_MALLOC=0)
target_include_directories(pqc_sha2_testbed PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src ${WOLFSSL_ROOT})
target_compile_options(pqc_sha2_testbed PRIVATE -O3)
pico_enable_stdio_usb(pqc_sha2_testbed 1)
pico_enable_stdio_uart(pqc_sha2_testbed 0)
target_link_libraries(pqc_sha2_testbed pico_stdlib pico_multicore pico_rand hardware_timer hardware_clocks)
pico_add_extra_outputs(pqc_sha2_testbed)

# Signature firmware configuration:
#   S2 (default): all twelve SLH-DSA sets, 3 rounds
#   S1          : six fast SLH-DSA sets, 1 round
set(SIG_CONFIG "S2" CACHE STRING "Signature firmware configuration: S2 or S1")
if(SIG_CONFIG STREQUAL "S1")
    target_compile_definitions(pqc_sig_testbed PRIVATE SLHDSA_ROUNDS=1 SLHDSA_FAST_ONLY)
endif()
