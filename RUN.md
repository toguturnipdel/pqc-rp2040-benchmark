# Running the revision experiments

Everything needed to regenerate the numbers marked "xx" in the revised manuscript.

## 1. One-time setup (Linux or WSL)

```bash
sudo apt install cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib python3-pip
git clone --branch 2.3.1 https://github.com/raspberrypi/pico-sdk.git ~/pico/pico-sdk
git -C ~/pico/pico-sdk submodule update --init lib/tinyusb
git clone https://github.com/wolfSSL/wolfssl.git ~/pico/wolfssl && git -C ~/pico/wolfssl checkout 5b9f179
pip install -r analysis/requirements.txt          # pyserial, numpy, pandas, matplotlib, cryptography, kyber-py
```

Install `picotool` (Raspberry Pi tool) so the runner can flash without pressing BOOTSEL.
Under WSL2 attach the Pico with `usbipd attach --wsl --busid <id> --auto-attach`
(it re-enumerates after every flash), or run step 3 with Windows Python instead.

## 2. Build all firmware

```bash
export PICO_SDK_PATH=~/pico/pico-sdk WOLFSSL_ROOT=~/pico/wolfssl
scripts/build_all.sh            # 19 UF2 images in ./build
```

## 3. Run

```bash
python host/run_experiments.py --list     # plan, runtimes, what is done
python host/run_experiments.py            # core steps, about 2.5 h
python host/run_experiments.py --all      # core + long steps, about 16 h in total (overnight)
```

Logs go to `data/raw/v2/<step>.txt`. Finished steps are skipped, so you can stop
(Ctrl-C) and restart at any time; `--force` re-runs. Single steps: `--steps kem,sig_lattice`.

Optional:

* Second Pico (board agreement, R1-2): connect it alone and run
  `python host/run_experiments.py --board-tag board2 --steps kem,sig_lattice`.
* Energy calibration (R1-5, R2-5, R3-2): needs a current meter with a logic input on GPIO 15;
  `python host/run_experiments.py --steps energy`, then `analysis/energy_from_trace.py` as printed.

## 4. Analyse

The runner calls it automatically at the end; to run it yourself:

```bash
python analysis/revision_analysis.py      # tables -> data/processed/v2/*.csv, summary on screen
```

Where each manuscript placeholder comes from:

| Manuscript item | Step(s) | Output file |
|---|---|---|
| Table 3, Fig. 2, Section 5.1 | kem, kem_p256 | kem_ops.csv, kem_roles.csv, p256_ops.csv |
| Tables 4 and 5, Fig. 3, Sections 5.2–5.3 | sig_lattice, sig_falcon_small, sig_slh_f, sig_slh_s, mldsa_dist | sig_ops.csv, sig_additivity.csv, mldsa_distribution.csv |
| Fig. 4 | mldsa_dist | fig_mldsa_ccdf.pdf |
| Speed-build ML-DSA (Section 5.2) | mldsa_dist_speed | mldsa_distribution.csv (build = speed) |
| Table 6, Section 5.4, Table 12 | kem, sig_mem_* | memory_per_op.csv, ram_budget_matrix.csv, allocation_failures.csv |
| Tables 7 and 8 | kem, sig_* | kem_roles.csv (energy_model_mJ_median), sig_ops.csv × 0.0792 |
| Table 9, Section 5.6 | handshake | handshake.csv |
| Table 10, Section 5.7 | slh_xip, slh_sram, kem, kem_sram | codeloc_xip_vs_sram.csv, board_agreement.csv |
| Table 11, Section 6.1 | x25519_alt, x25519_alt_small | x25519_impls.csv, x25519_cm0_hybrid_share.csv |

Falcon rows from the small-memory signer carry the suffix "-smallmem" (step sig_falcon_small);
rows without it use wolfCrypt's default signer (step sig_lattice), where Falcon-1024 signing is
expected to run out of memory and the failing allocation size is logged.
