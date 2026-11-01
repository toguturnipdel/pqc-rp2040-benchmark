"""Integrate measured current over trigger pulses (energy calibration run).

Inputs
  trace : CSV export from the current meter with a time column, a current column
          and a logic column carrying the trigger GPIO. Column names differ
          between tools and versions, so pass them explicitly. The defaults match
          a Nordic Power Profiler (PPK2) export with the trigger on logic
          input D0, but check them against your file header first.
  log   : serial capture of firmware target pqc_energy (ENERGY,<seq>,<op>,<rep>,<us> lines).

Method
  Pulses are the rising-to-falling intervals of the logic channel. The k-th
  pulse is matched to ENERGY line seq = k, and the pulse width is checked
  against the firmware's own timing (default tolerance 5% or 50 us). Gross energy
  is V x integral(I dt) over the pulse; net energy subtracts the idle current,
  taken as the median current outside all pulses. Results per operation are the
  medians over repetitions.

Usage
  python analysis/energy_from_trace.py trace.csv energy_log.txt --voltage 3.3 \
      [--time-col "Timestamp(ms)" --time-unit ms --current-col "Current(uA)" \
       --current-unit uA --logic-col "D0-D7" --logic-bit 0]
Writes data/processed/v2/energy_measured.csv (read by revision_analysis.py).
"""
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
import pqcdata_v2 as d

_trapz = getattr(np, "trapezoid", None) or np.trapz   # numpy 2 renamed trapz

UNITS = {"s": 1.0, "ms": 1e-3, "us": 1e-6, "A": 1.0, "mA": 1e-3, "uA": 1e-6, "nA": 1e-9}


def logic_high(col, bit):
    v = col.astype(str).str.strip()
    if v.str.fullmatch(r"[01]{2,}").all():          # bit string such as 00000001 (D7..D0)
        return v.str[-1 - bit] == "1"
    return pd.to_numeric(v, errors="coerce").fillna(0).astype(int).apply(lambda x: (x >> bit) & 1 == 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace"); ap.add_argument("log")
    ap.add_argument("--voltage", type=float, default=3.3, help="supply voltage at the measurement point (V)")
    ap.add_argument("--time-col", default="Timestamp(ms)"); ap.add_argument("--time-unit", default="ms")
    ap.add_argument("--current-col", default="Current(uA)"); ap.add_argument("--current-unit", default="uA")
    ap.add_argument("--logic-col", default="D0-D7"); ap.add_argument("--logic-bit", type=int, default=0)
    ap.add_argument("--tolerance", type=float, default=0.05)
    ap.add_argument("--out", default=str(d.ROOT / "data" / "processed" / "v2" / "energy_measured.csv"))
    a = ap.parse_args()

    tr = pd.read_csv(a.trace)
    t = tr[a.time_col].to_numpy(float) * UNITS[a.time_unit]
    i = tr[a.current_col].to_numpy(float) * UNITS[a.current_unit]
    hi = logic_high(tr[a.logic_col], a.logic_bit).to_numpy()
    edges = np.diff(hi.astype(int))
    rises, falls = np.where(edges == 1)[0] + 1, np.where(edges == -1)[0] + 1
    if len(falls) and len(rises) and falls[0] < rises[0]:
        falls = falls[1:]
    n = min(len(rises), len(falls))
    rises, falls = rises[:n], falls[:n]
    idle_A = float(np.median(i[~hi]))
    print(f"{n} pulses, idle current {idle_A*1e3:.3f} mA")

    run = d.load(a.log)
    ev = run.energy.sort_values("seq").reset_index(drop=True)
    if len(ev) != n:
        print(f"WARNING: {len(ev)} ENERGY lines but {n} pulses; matching the first {min(len(ev), n)} by order")
    m = min(len(ev), n)
    rows, bad = [], 0
    for k in range(m):
        s, e = rises[k], falls[k]
        width_us = (t[e] - t[s]) * 1e6
        fw_us = ev.us[k]
        if abs(width_us - fw_us) > max(a.tolerance * fw_us, 50):
            bad += 1
        q = _trapz(i[s:e + 1], t[s:e + 1])                      # coulombs
        rows.append(dict(seq=k, op=ev.op[k], fw_us=fw_us, pulse_us=width_us,
                         gross_mJ=a.voltage * q * 1e3,
                         net_mJ=a.voltage * (q - idle_A * (t[e] - t[s])) * 1e3,
                         mean_current_mA=q / (t[e] - t[s]) * 1e3))
    if bad:
        print(f"WARNING: {bad} pulses differ from firmware timing by more than tolerance (check alignment)")
    p = pd.DataFrame(rows)
    g = p.groupby("op", sort=False).agg(n=("seq", "size"), median_us=("fw_us", "median"),
                                         median_gross_mJ=("gross_mJ", "median"), median_net_mJ=("net_mJ", "median"),
                                         median_current_mA=("mean_current_mA", "median")).reset_index()
    g["idle_mA"] = idle_A * 1e3
    g["voltage_V"] = a.voltage
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    g.to_csv(a.out, index=False, float_format="%.5f")
    p.to_csv(Path(a.out).with_name("energy_pulses.csv"), index=False, float_format="%.5f")
    print(g.to_string(index=False))


if __name__ == "__main__":
    main()
