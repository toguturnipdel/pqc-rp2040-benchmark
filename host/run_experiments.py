#!/usr/bin/env python3
"""Run every revision experiment on a Raspberry Pi Pico, one firmware at a time.

For each step the script flashes the UF2 with picotool, waits for the Pico's USB
serial port, captures the whole log to data/raw/v2/<step>.txt and stops at the
firmware's "=== ... done ===" banner. Finished steps are skipped on the next
invocation, so the run can be interrupted and resumed.

Usage (from the repository root):
    pip install -r analysis/requirements.txt
    python host/run_experiments.py --list                 # show the plan and runtimes
    python host/run_experiments.py                        # run the core steps
    python host/run_experiments.py --all                  # core + long steps (about 16 h)
    python host/run_experiments.py --steps kem,sig_lattice
    python host/run_experiments.py --board-tag board2 --steps kem,sig_lattice   # second Pico
    python host/run_experiments.py --steps energy         # needs a current meter (see docs)

Requirements: picotool on PATH (otherwise the script asks you to drag the UF2 onto
the RPI-RP2 drive in BOOTSEL mode), pyserial. Under WSL2 the Pico must be attached
with usbipd-win using --auto-attach, because it re-enumerates after every flash;
running this script with Windows Python avoids that.
"""
import argparse, os, re, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "v2"
DONE = re.compile(r"^=== .*done ===")
PICO_VID = 0x2E8A

# id, firmware target, minutes (estimate), group, mode, note
STEPS = [
    ("kem",                  "pqc_pico_testbed",         5,   "core", "capture",   "complete hybrid exchange, combiners, memory/budgets (R1-6, R2-3, R2-6, R3-1)"),
    ("kem_p256",             "pqc_kem_p256",             6,   "core", "capture",   "P-256 alternative classical component (R1-3)"),
    ("kem_sram",             "pqc_kem_sram",             5,   "core", "capture",   "key exchange with code in SRAM (R2-7)"),
    ("x25519_alt",           "pqc_x25519_alt",           4,   "core", "capture",   "wolfCrypt X25519 vs x25519-cm0 (R1-1, R2-2, R4-3)"),
    ("x25519_alt_small",     "pqc_x25519_alt_small",     5,   "core", "capture",   "wolfCrypt small Curve25519 (R4-3)"),
    ("handshake",            "pqc_handshake",            3,   "core", "handshake", "USB host-to-device handshake (R3-1)"),
    ("sig_lattice",          "pqc_sig_lattice",          20,  "core", "capture",   "paired Ed25519/ML-DSA/Falcon, default Falcon signer (R2-4, R1-3)"),
    ("sig_falcon_small",     "pqc_sig_falcon_small",     15,  "core", "capture",   "Falcon-512/1024 with small-memory signer (R4-2, R2-6)"),
    ("sig_mem_lattice",      "pqc_sig_mem_lattice",      10,  "core", "capture",   "per-op stack/heap + RAM budgets, lattice (R1-8, R2-6, R3-3)"),
    ("sig_mem_falcon_small", "pqc_sig_mem_falcon_small", 10,  "core", "capture",   "per-op memory, Falcon small-memory signer (R2-6)"),
    ("slh_xip",              "pqc_slh_xip",              15,  "core", "capture",   "SLH-DSA 128f from flash (R2-7)"),
    ("slh_sram",             "pqc_slh_sram",             15,  "core", "capture",   "SLH-DSA 128f from SRAM (R2-7)"),
    ("mldsa_dist_speed",     "pqc_mldsa_dist_speed",     40,  "core", "capture",   "speed-oriented ML-DSA, 1,000/level (R1-4)"),
    ("sig_slh_f",            "pqc_sig_slh_f",            90,  "long", "capture",   "SLH-DSA f sets, 20 rounds, paired hybrids (R1-3, R1-9, R3-2)"),
    ("sig_mem_slh_f",        "pqc_sig_mem_slh_f",        15,  "long", "capture",   "per-op memory, SLH-DSA f sets"),
    ("mldsa_dist",           "pqc_mldsa_dist",           380, "long", "capture",   "ML-DSA 10,000 signatures/level (R4-1, R2-4)"),
    ("sig_slh_s",            "pqc_sig_slh_s",            200, "long", "capture",   "SLH-DSA s sets, 3-5 rounds, paired hybrids"),
    ("sig_mem_slh_s",        "pqc_sig_mem_slh_s",        130, "long", "capture",   "per-op memory, SLH-DSA s sets"),
    ("diag_falcon",          "pqc_diag_falcon",          5,   "optional", "capture", "diagnostic: Falcon-1024 small-memory signing with fault capture"),
    ("diag_falcon_hook",     "pqc_diag_falcon_hook",     5,   "optional", "capture", "diagnostic: as diag_falcon, with the benchmark allocator hook"),
    ("energy",               "pqc_energy",               8,   "optional", "energy", "energy calibration with a current meter on GPIO 15 (R1-5, R2-5, R3-2)"),
]


def log_path(step, tag):
    return RAW / (f"{step}_{tag}.txt" if tag else f"{step}.txt")


def finished(path):
    if not path.exists():
        return False
    with open(path, errors="replace") as f:
        return any(DONE.match(l.strip()) for l in f)


def find_port(explicit, timeout=30):
    if explicit:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.name == "nt" or os.path.exists(explicit):
                return explicit
            time.sleep(0.5)
        return explicit
    from serial.tools import list_ports
    deadline = time.time() + timeout
    while time.time() < deadline:
        ports = [p.device for p in list_ports.comports() if p.vid == PICO_VID]
        if ports:
            return ports[0]
        time.sleep(0.5)
    raise SystemExit("No Pico serial port found (VID 0x2E8A). Use --port.")


def flash(uf2):
    if not uf2.exists():
        raise SystemExit(f"{uf2} not found. Build first: scripts/build_all.sh")
    pt = shutil.which("picotool")
    if pt:
        r = subprocess.run([pt, "load", "-f", "-x", str(uf2)], capture_output=True, text=True)
        if r.returncode == 0:
            return
        print(r.stdout + r.stderr)
        print("picotool could not reboot the board into BOOTSEL; falling back to manual flashing.")
    input(f"Hold BOOTSEL, reconnect the Pico, copy {uf2.name} onto the RPI-RP2 drive, then press Enter... ")


def capture(port, out, minutes, echo_every=200):
    import serial
    limit = time.time() + max(10, minutes * 3) * 60   # generous: 3x the estimate
    n_raw = 0
    t_start = last_beat = time.time()
    with serial.Serial(port, 115200, timeout=5) as s, open(out, "w", encoding="utf-8") as f:
        while time.time() < limit:
            if time.time() - last_beat >= 60:          # heartbeat: long operations print nothing for minutes
                print(f"    ... still running: {(time.time() - t_start) / 60:.0f} min, {n_raw} samples so far", flush=True)
                last_beat = time.time()
            try:
                line = s.readline().decode(errors="replace")
            except serial.SerialException as e:
                print(f"    SERIAL DISCONNECTED: {e}")
                print("    The Pico left USB mid-run. Replug it (and re-run usbipd attach under WSL),")
                print("    then run the same command again; this step will be retried.")
                return False
            if not line:
                continue
            f.write(line); f.flush()
            l = line.strip()
            if l.startswith("RAW,"):
                n_raw += 1
                if n_raw % echo_every == 0:
                    print(f"    {n_raw} samples ...", flush=True)
            elif l:
                print("    " + l[:150], flush=True)
            if DONE.match(l):
                return True
    print("    TIMEOUT: banner not seen; log kept, step will be retried next time")
    return False


def run_handshake(port, out):
    sys.path.insert(0, str(ROOT / "host"))
    import serial, hs_server
    with serial.Serial(port, 115200, timeout=30) as s, open(out, "w", encoding="utf-8") as log:
        ok = hs_server.serve(s.readline, lambda l: (s.write((l + "\n").encode()), s.flush()), log)
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default=str(ROOT / "build"))
    ap.add_argument("--port", help="serial port (default: auto-detect VID 0x2E8A)")
    ap.add_argument("--steps", help="comma-separated step ids (default: core group)")
    ap.add_argument("--all", action="store_true", help="core + long steps")
    ap.add_argument("--board-tag", default="", help="suffix for logs from another board, e.g. board2")
    ap.add_argument("--force", action="store_true", help="re-run steps that already finished")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--no-analysis", action="store_true")
    a = ap.parse_args()

    by_id = {s[0]: s for s in STEPS}
    if a.steps:
        sel = [by_id[x.strip()] for x in a.steps.split(",")]
    else:
        sel = [s for s in STEPS if s[3] == "core" or (a.all and s[3] == "long")]

    if a.list:
        tot = 0
        for sid, tgt, mins, grp, mode, note in STEPS:
            mark = "x" if s_in(sel, sid) else " "
            st = "done" if finished(log_path(sid, a.board_tag)) else ""
            print(f"[{mark}] {sid:22s} {mins:4d} min  {grp:8s} {st:5s} {note}")
            tot += mins if s_in(sel, sid) else 0
        print(f"selected: about {tot / 60:.1f} h")
        return

    RAW.mkdir(parents=True, exist_ok=True)
    bdir = Path(a.build_dir)
    for i, (sid, tgt, mins, grp, mode, note) in enumerate(sel, 1):
        out = log_path(sid, a.board_tag)
        if finished(out) and not a.force:
            print(f"[{i}/{len(sel)}] {sid}: already done, skipping")
            continue
        print(f"[{i}/{len(sel)}] {sid}: {note} (about {mins} min)")
        if mode == "energy":
            input("    Start the current meter recording (logic input on GPIO 15), then press Enter... ")
        flash(bdir / f"{tgt}.uf2")
        time.sleep(2)
        port = find_port(a.port)
        time.sleep(1)
        ok = run_handshake(port, out) if mode == "handshake" else capture(port, out, mins)
        print(f"    -> {out.relative_to(ROOT)} {'OK' if ok else 'INCOMPLETE'}")
        if mode == "energy":
            print("    Stop the meter, export the trace as CSV, then run:\n"
                  f"    python analysis/energy_from_trace.py <trace.csv> {out.relative_to(ROOT)} --voltage <V>")

    if not a.no_analysis:
        print("\nRunning analysis ...")
        subprocess.run([sys.executable, str(ROOT / "analysis" / "revision_analysis.py")], check=False)


def s_in(sel, sid):
    return any(s[0] == sid for s in sel)


if __name__ == "__main__":
    main()
