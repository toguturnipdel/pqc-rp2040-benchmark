# Revision experiments (CMC review round 1)

This guide maps every experiment-related reviewer comment to a firmware target,
the capture to make, the analysis output, and the expected runtime on a
125 MHz RP2040. Runtimes are estimates from the submitted means; the ML-DSA and
SLH-DSA runs are long and are best left running overnight.

All new firmware prints `CSV,meta,...` lines (firmware, wolfSSL version, clock,
board unique id, configuration, code location) and one `RAW,...` line per
measured sample, so every statistic in the revision is computed from raw samples
by `analysis/revision_analysis.py`.

## 1. Two findings from the original code (no run needed)

* **Tables 4 and 5 were not paired (R2-4).** In the original `main_sig.c` the
  hybrid rows came from a second, separate 20-round pass, and each hybrid sample
  added the *last* round's Ed25519 time. Standalone and hybrid figures were
  therefore independent draws from a heavy-tailed distribution, which explains
  the −32% to +65% differences the reviewer found. The new firmware times both
  components in the same iteration, so hybrid = bind + Ed25519 + PQ holds per
  sample (the analysis checks the residual is 0).
* **No warm-up round in the original signature firmware**, although Section 4
  states one. The new firmware has one warm-up round for every set with ≥10
  rounds (not for the SLH-DSA s sets, where one signature takes minutes).
* **Why wolfCrypt X25519 is slow on the M0+ (R4-3).** The build uses
  `wolfcrypt/src/fe_operations.c` (ref10-style, radix 2^25.5). Disassembly of the
  built firmware shows `fe_mul` makes 100 calls and `fe_sq` 55 calls to the
  64-bit multiply helper `__aeabi_lmul` (Pico SDK `__wrap___aeabi_lmul`), because
  ARMv6-M has no 32×32→64-bit multiply instruction. wolfSSL's Curve25519
  assembly (`port/arm/thumb2-curve25519.S`) targets Thumb-2 and cannot run on
  ARMv6-M. wolfCrypt does ship ARMv6-M Thumb assembly for P-256
  (`sp_armthumb.c`), which target `pqc_kem_p256` uses.

## 2. Experiments

| ID | Reviewer comments | Target | Captures | Runtime |
|---|---|---|---|---|
| E1 | R1-3, R1-6, R2-3, R2-4, R3-1, R3-2 | `pqc_sig_testbed` (`SIG_PART=1`, `2`, `3`) and `pqc_pico_testbed` | `sig_lattice.txt`, `sig_slh_f.txt`, `sig_slh_s.txt`, `kem.txt` | 15 min, 1.4 h, 3.2 h, 3 min |
| E2 | R2-4, R4-1 | `pqc_mldsa_dist` | `mldsa_dist.txt` | about 6 h |
| E3 | R1-9, R2-7, R3-2 | part of E1 (20 f-set rounds, 5 for SHA2-128s, 3 for other s sets) | (E1) | (E1) |
| E4 | R1-8, R2-6 | `pqc_sig_mem` (`SIG_PART` as E1) and the memory pass in `pqc_pico_testbed` | `sig_mem_*.txt` | lattice 5 min, f 10 min, s about 2 h |
| E5 | R2-6, R2-8, R3-3 | same as E4 (RAM-budget pass) | (E4) | (E4) |
| E6 | R1-3, R2-6, R4-2 | `pqc_sig_testbed` (Falcon with provisioned keys; on-device Falcon-1024 attempt) | (E1 lattice) | (E1) |
| E7 | R1-1, R2-2, R4-3 | `pqc_x25519_alt`, `pqc_x25519_alt_small` | `x25519_alt.txt`, `x25519_alt_small.txt` | 3 min each |
| E8 | R1-6, R3-1 | `pqc_handshake` + `host/hs_server.py` | `handshake.txt` (written by the script) | 2 min |
| E9 | R1-5, R2-5, R3-2 | `pqc_energy` + external current meter | `energy_log.txt` + meter export | 5 min (not performed for the paper) |
| E10 | R1-4 | `pqc_mldsa_dist_speed` (1,000 per level) | `mldsa_dist_speed.txt` | about 40 min |
| E11 | R1-2 | `pqc_pico_testbed` and `pqc_sig_testbed SIG_PART=1` on a second Pico | `kem_board2.txt`, `sig_lattice_board2.txt` | 20 min (not performed for the paper) |
| E12 | R2-7 | `pqc_slh_xip`, `pqc_slh_sram`, `pqc_kem_sram` | `slh_xip.txt`, `slh_sram.txt`, `kem_sram.txt` | 13 + 13 + 3 min |
| P-256 | R1-3 (other pairings), R1-1 | `pqc_kem_p256` | `kem_p256.txt` | about 5 min |

### What each target measures

* **`pqc_pico_testbed` (key exchange).** A complete exchange per round between a
  client and a server with separate key objects: client X25519 + ML-KEM keygen,
  binary serialisation of (X25519 pk ‖ ML-KEM ek), server parse, ephemeral
  X25519, shared secret, encapsulation, serialisation, and on the client the
  parse, shared secret, decapsulation. Two combiners are timed on both sides
  and must agree: HKDF-SHA256 over ss_MLKEM ‖ ss_X25519 (the TLS 1.3 hybrid
  concatenation fed to HKDF; the full TLS key schedule is not run) and an
  X-Wing-style SHA3-256 combiner. 100 rounds per level. The memory pass then
  records peak stack and peak heap per operation and re-runs each operation
  under emulated 10 KiB (Class 1) and 50 KiB (Class 2) budgets.
* **`pqc_sig_testbed` (signatures).** Paired rounds: Ed25519 and the
  post-quantum scheme run back to back on the same message. Hybrid composition:
  composite-style dual signature where both components sign
  M' = "CompositeAlgorithmSignatures2025" ‖ Label ‖ 0x00 ‖ SHA-512(M), which
  binds each component to the pair (prevents stripping a component and
  presenting it as a standalone signature over M). It follows the structure of
  the IETF LAMPS composite drafts but is not claimed to conform to a specific
  draft version. The binding cost is timed separately. Falcon-512/1024 signing
  and verification use key pairs generated off-device by `tools/falcon_keygen`
  (same wolfSSL commit and FPR backend); Falcon-512 on-device keygen is also
  timed; one on-device Falcon-1024 keygen attempt logs the failing allocation.
  Default rounds: 100 lattice, 20 Falcon-512 keygen, 20 SLH-DSA f, 5 SHA2-128s,
  3 other s sets (override with `-DLATTICE_ROUNDS=` etc.).
* **`pqc_sig_mem`.** Same schemes, one operation at a time: peak stack (stack
  painting), peak wolfCrypt heap above the baseline (allocator hook), static
  object bytes, and the RAM-budget results. `SIG_PART` splits it like the
  timing firmware.
* **`pqc_mldsa_dist`.** 10,000 signatures per ML-DSA level on fresh random
  messages, new key every 100 signatures, each verified, each paired with an
  Ed25519 sign/verify of the same message.
* **`pqc_x25519_alt`.** wolfCrypt X25519 versus x25519-cm0 (Pornin, ARMv6-M
  assembly, vendored under MIT licence) executing from flash and from SRAM,
  with an RFC 7748 test vector and a cm0 ↔ wolfCrypt Diffie-Hellman agreement
  check, then a complete hybrid exchange with x25519-cm0 (SRAM) + wolfCrypt
  ML-KEM at L1/L3/L5. `pqc_x25519_alt_small` repeats it with wolfCrypt's
  `CURVED25519_SMALL` implementation.
* **`pqc_handshake`.** The Pico is the client of a real exchange with the host
  over USB CDC: keygen, serialisation, hex transport, wait, parse, X25519,
  decapsulation, HKDF, and key confirmation (HMAC-SHA256 over a transcript
  hash). The server reports its own compute time so link time can be separated.
  USB is not an IoT radio: the device-side compute and serialisation figures
  transfer to other links; the link figure does not.
* **`pqc_energy`.** Each operation 20 times (5 for SLH-DSA-SHA2-128f signing)
  with GPIO 15 high only during the operation, 50 ms idle gaps, and a 5 s idle
  reference. `analysis/energy_from_trace.py` integrates measured current per
  pulse and compares with the constant-power model of Table 6.
* **`pqc_slh_xip` / `pqc_slh_sram` / `pqc_kem_sram`.** Identical code executed in
  place from flash and copied to SRAM, isolating XIP cache effects.

## 3. Running

The simplest path is `RUN.md`: `scripts/build_all.sh` builds every target and
`host/run_experiments.py` flashes, captures and resumes automatically. The manual
steps below remain valid.

Falcon-1024 signing needs the small-memory signer (target `pqc_sig_falcon_small`,
`-DFALCON_SIGN_SMALL`): the default signer requests one block of about 180 KB, more
than the free heap. Host measurements give about 115 KB peak heap (90 KB largest block)
for the small-memory signer.


Build everything once (about 14 targets):

```bash
export PICO_SDK_PATH=/path/to/pico-sdk          # 2.3.1
mkdir build && cd build
cmake -DPICO_BOARD=pico -DCMAKE_BUILD_TYPE=Release -DWOLFSSL_ROOT=$HOME/pico/wolfssl ../firmware
make -j4
# SIG_PART variants of the signature firmware:
cmake -DSIG_PART=1 . && make pqc_sig_testbed pqc_sig_mem && cp pqc_sig_testbed.uf2 sig_part1.uf2 && cp pqc_sig_mem.uf2 sig_mem_part1.uf2
cmake -DSIG_PART=2 . && make pqc_sig_testbed pqc_sig_mem && cp pqc_sig_testbed.uf2 sig_part2.uf2 && cp pqc_sig_mem.uf2 sig_mem_part2.uf2
cmake -DSIG_PART=3 . && make pqc_sig_testbed pqc_sig_mem && cp pqc_sig_testbed.uf2 sig_part3.uf2 && cp pqc_sig_mem.uf2 sig_mem_part3.uf2
```

Capture each run to its own file in `data/raw/v2/` (keep the whole log; the
parser ignores non-data lines):

```bash
minicom -b 115200 -D /dev/ttyACM0 -C data/raw/v2/kem.txt
```

Handshake (the script opens the port and writes the capture):

```bash
pip install -r analysis/requirements.txt
python host/hs_server.py /dev/ttyACM0 data/raw/v2/handshake.txt
```

Energy: wire the Pico's VSYS (or 3V3 with the regulator bypassed, state which)
through the meter, connect GPIO 15 to the meter's logic input, start recording,
flash `pqc_energy`, capture its serial log, export the trace as CSV, then:

```bash
python analysis/energy_from_trace.py trace.csv data/raw/v2/energy_log.txt --voltage <V at the meter>
```

Check the column-name options against the exported header first.

Falcon keys are already generated in `firmware/src/falcon_ext_keys.h`. To
regenerate: `make -C tools/falcon_keygen WOLFSSL_ROOT=$HOME/pico/wolfssl && ./tools/falcon_keygen/falcon_keygen firmware/src/falcon_ext_keys.h`.

Analysis:

```bash
python analysis/revision_analysis.py          # tables in data/processed/v2/, summary on stdout
```

The original scripts (`derived_numbers.py`, `make_figures.py`) still reproduce
the submitted tables from the original logs.

## 4. Tests

* `tests/hs_sim/`: builds the firmware's handshake client (`hs_core.c`) for
  Linux and runs it against `host/hs_server.py` over a pseudo-terminal
  (`make -C tests/hs_sim WOLFSSL_ROOT=... && python tests/hs_sim/run_test.py`).
  Last result: 15/15 exchanges key-confirmed at L1/L3/L5 against an
  independent host stack (pyca/cryptography X25519, kyber-py ML-KEM).
* `tests/synthetic_logs.py`: writes SYNTHETIC logs in the firmware formats to
  exercise the analysis scripts. These values are invented; never copy them
  into `data/raw/`.

## 5. Caveats to state in the manuscript

* Emulated budgets count static objects, peak stack and live wolfCrypt heap.
  They do not count code/flash, the USB stack or SDK runtime, and do not model
  allocator fragmentation on a real small-RAM device.
* Heap figures are bytes requested by wolfCrypt (allocator overhead excluded),
  read per operation, above the DRBG baseline that is reported separately.
* Cycles are µs × clk_sys; under XIP they include flash stall cycles.
* The new signature firmware has 153.8 KB of heap headroom versus 162.0 KB in
  the submitted build (the key union is static rather than on the stack). The
  submitted run peaked at 114 kB, so the margin is about 40 KB, but report any
  new out-of-memory result with this in mind.
* The synthetic tests check the parsers, not the hardware results.
