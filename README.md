# Hybrid post-quantum cryptography benchmark for the RP2040

Firmware for measuring hybrid X25519 + ML-KEM key exchange and Ed25519, ML-DSA, Falcon and SLH-DSA signatures (standalone and as Ed25519 hybrids) on the Raspberry Pi Pico (RP2040, ARM Cortex-M0+) with wolfCrypt, plus scripts that turn the serial output into tables and figures.

## Revision experiments

The firmware was extended for the first review round (paired standalone/hybrid
timing, complete key exchange with combiners and serialisation, 10,000-sample
ML-DSA distributions, per-operation memory and emulated RFC 7228 RAM budgets,
off-device Falcon keys, X25519 implementation comparison, XIP versus SRAM,
a host-to-device handshake, and energy calibration). See
[`docs/REVISION_EXPERIMENTS.md`](docs/REVISION_EXPERIMENTS.md) for what each
target measures, the reviewer comment it answers, how to run it, and runtimes.

## Layout

```
firmware/
  CMakeLists.txt                 all targets (see docs/REVISION_EXPERIMENTS.md)
  pico_sdk_import.cmake
  src/bench_common.h             shared timing, RAW output, heap/stack tracking, RAM budgets
  src/main.c                     complete hybrid X25519 + ML-KEM exchange, L1/L3/L5 (+ P-256 option)
  src/main_sig.c                 paired Ed25519 / ML-DSA / Falcon / SLH-DSA standalone + hybrid
  src/main_mldsa_dist.c          ML-DSA signing distribution (10,000 per level)
  src/main_x25519_alt.c          wolfCrypt X25519 vs x25519-cm0 (flash, SRAM)
  src/main_slh_codeloc.c         SLH-DSA 128f, XIP vs SRAM
  src/main_handshake.c, hs_core.*  device-as-client handshake over USB
  src/main_energy.c              energy calibration with GPIO trigger
  src/main_sha2.c                original SLH-DSA SHA2 completion run (unchanged)
  src/falcon_ext_keys.h          Falcon key pairs generated off-device
  src/wolfssl_user_settings.h    wolfCrypt configuration (+ WITH_P256, CURVE_SMALL, MLDSA_SPEED)
  third_party/x25519-cm0/        Pornin's ARMv6-M X25519 (MIT)
tools/falcon_keygen/             host tool generating falcon_ext_keys.h
host/hs_server.py                host side of the handshake
analysis/
  pqcdata.py, derived_numbers.py, make_figures.py   submitted tables and figures (original logs)
  pqcdata_v2.py, revision_analysis.py               revision runs (RAW samples)
  energy_from_trace.py                              current-meter trace integration
tests/                           handshake pty test, synthetic-log generator
docs/REVISION_EXPERIMENTS.md
```

## Requirements

- Raspberry Pi Pico SDK 2.3.1 and arm-none-eabi-gcc 13.2.1
- wolfSSL 5.9.2 (tested at commit `5b9f179`)
- Python 3.10+ for the analysis scripts

## Build

```bash
git clone https://github.com/wolfSSL/wolfssl.git ~/pico/wolfssl
git -C ~/pico/wolfssl checkout 5b9f179
export PICO_SDK_PATH=/path/to/pico-sdk
mkdir build && cd build
cmake -DPICO_BOARD=pico -DCMAKE_BUILD_TYPE=Release ../firmware
make -j4
```

Use `-DWOLFSSL_ROOT=<path>` if wolfSSL is elsewhere. `-DSIG_PART=1|2|3` restricts the signature firmware to the lattice schemes, the SLH-DSA f sets, or the SLH-DSA s sets. `-DTRIG_GPIO=<pin>` raises a GPIO during every timed operation. The submitted (pre-revision) firmware is commit `6e003f5`.

## Run

1. Hold BOOTSEL while connecting the Pico and copy a `.uf2` file to the `RPI-RP2` drive.
2. Capture the serial output, for example `minicom -b 115200 -D /dev/ttyACM0 -C results.txt`.
3. Keep the lines starting with `CSV,`: `grep '^CSV' results.txt > data/raw/<name>.csv`.

## Analysis

Place the captured CSV files in `data/raw/` using the file names listed in `analysis/pqcdata.py`, then:

```bash
pip install -r analysis/requirements.txt
python analysis/derived_numbers.py
python analysis/make_figures.py
```

## License

wolfSSL is available under GPLv3 or a commercial license; firmware built with it is subject to those terms. `pico_sdk_import.cmake` is from the Raspberry Pi Pico SDK (BSD-3-Clause).
