# Hybrid post-quantum cryptography benchmark for the RP2040

Firmware for measuring hybrid X25519 + ML-KEM key exchange and Ed25519, ML-DSA, Falcon and SLH-DSA signatures (standalone and as Ed25519 hybrids) on the Raspberry Pi Pico (RP2040, ARM Cortex-M0+) with wolfCrypt, plus scripts that turn the serial output into tables and figures.

## Layout

```
firmware/
  CMakeLists.txt
  pico_sdk_import.cmake
  src/main.c                     X25519 + ML-KEM-512/768/1024
  src/main_sig.c                 Ed25519, ML-DSA, Falcon, SLH-DSA, Ed25519 hybrids
  src/main_sha2.c                SLH-DSA SHA2-192s/192f/256s/256f
  src/wolfssl_user_settings.h    wolfCrypt configuration
  src/user_settings.h
analysis/
  pqcdata.py                     parser for the CSV lines printed by the firmware
  derived_numbers.py             tables and summary statistics
  make_figures.py                figures
  requirements.txt
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
make -j4 pqc_pico_testbed pqc_sig_testbed pqc_sha2_testbed
```

Use `-DWOLFSSL_ROOT=<path>` if wolfSSL is elsewhere. `-DSIG_CONFIG=S1` builds the signature firmware with the six fast SLH-DSA sets and one round per set instead of all twelve sets with three rounds.

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
