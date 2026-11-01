# x25519-cm0 (vendored)

ARMv6-M assembly X25519 by Thomas Pornin, MIT License (see `LICENSE`).
Source: https://github.com/pornin/x25519-cm0 at commit 75a53f2 (unmodified copy).

The firmware build generates two renamed copies of `x25519-cm0.S`:
`x25519_cm0_flash()` in `.text` (executes in place from QSPI flash) and
`x25519_cm0_ram()` in a `.time_critical` section (copied to SRAM at boot).
Used only by `src/main_x25519_alt.c` (Reviewer 1 point 1, Reviewer 2 point 2,
Reviewer 4 point 3).
