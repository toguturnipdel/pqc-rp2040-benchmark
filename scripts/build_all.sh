#!/usr/bin/env bash
# Build every firmware target used by host/run_experiments.py.
#   export PICO_SDK_PATH=~/pico/pico-sdk            # Pico SDK 2.3.1
#   export WOLFSSL_ROOT=~/pico/wolfssl              # wolfSSL at commit 5b9f179
#   scripts/build_all.sh [build-dir]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-$ROOT/build}"
: "${PICO_SDK_PATH:?set PICO_SDK_PATH to the Pico SDK 2.3.1 checkout}"
WOLFSSL_ROOT="${WOLFSSL_ROOT:-$HOME/pico/wolfssl}"
if [ -d "$WOLFSSL_ROOT/.git" ]; then
  have=$(git -C "$WOLFSSL_ROOT" rev-parse --short=7 HEAD)
  [ "$have" = "5b9f179" ] || echo "WARNING: wolfSSL is at $have, the paper uses 5b9f179 (git -C $WOLFSSL_ROOT checkout 5b9f179)"
fi
TARGETS="pqc_pico_testbed pqc_kem_p256 pqc_kem_sram pqc_x25519_alt pqc_x25519_alt_small pqc_handshake
 pqc_sig_lattice pqc_sig_falcon_small pqc_sig_mem_lattice pqc_sig_mem_falcon_small pqc_slh_xip pqc_slh_sram
 pqc_mldsa_dist_speed pqc_sig_slh_f pqc_sig_mem_slh_f pqc_mldsa_dist pqc_sig_slh_s pqc_sig_mem_slh_s pqc_energy"
mkdir -p "$BUILD"
cmake -S "$ROOT/firmware" -B "$BUILD" -DPICO_BOARD=pico -DCMAKE_BUILD_TYPE=Release -DWOLFSSL_ROOT="$WOLFSSL_ROOT"
JOBS=$(nproc 2>/dev/null || echo 4)
for t in $TARGETS; do
  echo "== $t"
  cmake --build "$BUILD" --target "$t" -j "$JOBS"
done
echo "Built $(ls "$BUILD"/*.uf2 | wc -l) UF2 images in $BUILD"
