# Hybrid post-quantum cryptography benchmark for the RP2040

Firmware, host tools, analysis code and raw measurement logs for the paper
"What Fits and What Doesn't: Hybrid Post-Quantum Cryptography on a Cortex-M0+ Microcontroller for IoT"
(Computers, Materials & Continua, under review). The firmware measures hybrid X25519 + ML-KEM key exchange
and Ed25519, ML-DSA, Falcon and SLH-DSA signatures, standalone and as Ed25519 hybrids, on the Raspberry Pi
Pico (RP2040, ARM Cortex-M0+) with wolfCrypt.

All results in the revised manuscript come from the logs in `data/raw/v2/`, measured on one Raspberry Pi Pico
(board ID E66440A2CB935B2B) at 125 MHz with wolfSSL 5.9.2 (commit `5b9f179`), Pico SDK 2.3.1 and
arm-none-eabi-gcc 13.2.1. The submitted (pre-revision) firmware is commit `6e003f5`.

## Revision experiments

The firmware was extended for the first review round: paired standalone and hybrid timing, a complete key
exchange with serialisation and combiners, 10,000-sample ML-DSA signing distributions, per-operation memory
with emulated RFC 7228 RAM budgets, off-device Falcon keys, an X25519 implementation comparison, XIP versus
SRAM code placement, and a host-to-device handshake. [`docs/REVISION_EXPERIMENTS.md`](docs/REVISION_EXPERIMENTS.md)
describes each target, the reviewer comment it answers and its runtime; [`RUN.md`](RUN.md) gives the
step-by-step procedure. The firmware also supports a second-board comparison and energy calibration with a
current meter; these were not performed for the paper (see its Section 6.4).

## Layout

```
firmware/
  CMakeLists.txt                 all targets (see docs/REVISION_EXPERIMENTS.md)
  pico_sdk_import.cmake
  src/bench_common.h             shared timing, RAW output, heap/stack tracking, RAM budgets, fault handler
  src/main.c                     complete hybrid X25519 + ML-KEM exchange, L1/L3/L5 (+ P-256 option)
  src/main_sig.c                 paired Ed25519 / ML-DSA / Falcon / SLH-DSA standalone + hybrid
  src/main_mldsa_dist.c          ML-DSA signing distribution (10,000 per level)
  src/main_x25519_alt.c          wolfCrypt X25519 vs x25519-cm0 (flash, SRAM)
  src/main_slh_codeloc.c         SLH-DSA 128f, XIP vs SRAM
  src/main_handshake.c, hs_core.*  device-as-client handshake over USB
  src/main_diag_falcon.c         allocation tracing used to diagnose the Falcon-1024 out-of-memory failure
  src/main_energy.c              energy calibration with GPIO trigger (not used in the paper)
  src/main_sha2.c                original SLH-DSA SHA2 completion run (unchanged)
  src/falcon_ext_keys.h          Falcon key pairs generated off-device
  src/wolfssl_user_settings.h    wolfCrypt configuration (+ WITH_P256, CURVE_SMALL, MLDSA_SPEED)
  third_party/x25519-cm0/        Pornin's ARMv6-M X25519 (MIT)
tools/falcon_keygen/             host tool generating falcon_ext_keys.h
host/run_experiments.py          flashes each image, captures its log to data/raw/v2/, runs the analysis
host/hs_server.py                host side of the handshake
scripts/build_all.sh             builds every firmware image
analysis/
  pqcdata_v2.py, revision_analysis.py               revision runs (RAW samples) -> data/processed/v2/
  pqcdata.py, derived_numbers.py, make_figures.py   submitted tables and figures (original logs)
  energy_from_trace.py                              current-meter trace integration (not used in the paper)
data/raw/v2/                     the 18 measurement logs of the revision, plus diagnostics/
tests/                           handshake pty test, synthetic-log generator
docs/REVISION_EXPERIMENTS.md
RUN.md
```

## Data

`data/raw/v2/` holds the serial log of every revision run exactly as captured from the device. Lines starting
with `RAW,` are individual timed operations (`RAW,<firmware>,<scheme>,<level>,<operation>,<sample>,<microseconds>`);
`CSV,meta` lines identify the firmware, configuration and board; `CSV,mem` and `CSV,budget` lines give
per-operation memory and the emulated RAM-budget results. `data/raw/v2/diagnostics/` contains the Falcon-1024
allocation traces. Processed tables are not stored; `analysis/revision_analysis.py` regenerates them.

## Requirements

- Raspberry Pi Pico SDK 2.3.1 and arm-none-eabi-gcc 13.2.1
- wolfSSL 5.9.2 (commit `5b9f179`), not included in this repository
- Python 3.10+ (`pip install -r analysis/requirements.txt`)

## Build

```bash
git clone https://github.com/wolfSSL/wolfssl.git ~/pico/wolfssl
git -C ~/pico/wolfssl checkout 5b9f179
export PICO_SDK_PATH=/path/to/pico-sdk WOLFSSL_ROOT=~/pico/wolfssl
scripts/build_all.sh             # all firmware images in ./build
```

To build a single configuration by hand: `cmake -DPICO_BOARD=pico -DCMAKE_BUILD_TYPE=Release ../firmware`
in a `build` directory. `-DSIG_PART=1|2|3` restricts the signature firmware to the lattice schemes, the
SLH-DSA f sets or the SLH-DSA s sets; `-DTRIG_GPIO=<pin>` raises a GPIO during every timed operation.

## Run and analyse

```bash
python3 host/run_experiments.py --list    # plan, runtimes and which steps are done
python3 host/run_experiments.py --all     # every step (about 16 h); logs go to data/raw/v2/
python3 analysis/revision_analysis.py     # tables -> data/processed/v2/*.csv
```

To reproduce the paper's tables from the logs in this repository, only the last command is needed.
See [`RUN.md`](RUN.md) for details and for which output file feeds each table and figure.

## License

wolfSSL is available under GPLv3 or a commercial license; firmware built with it is subject to those terms.
`pico_sdk_import.cmake` is from the Raspberry Pi Pico SDK (BSD-3-Clause). `firmware/third_party/x25519-cm0`
is MIT-licensed (see its LICENSE file).
