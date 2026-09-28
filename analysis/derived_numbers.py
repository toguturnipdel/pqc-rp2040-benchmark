"""Regenerate every table value and derived number reported in the manuscript from the raw logs.

Writes CSV tables to data/processed/ and prints the numbers quoted in the text.
Usage:  python analysis/derived_numbers.py
"""
import csv
from pathlib import Path
import pqcdata as d

OUT = Path(__file__).resolve().parent.parent / "data" / "processed"
OUT.mkdir(parents=True, exist_ok=True)
ms = lambda us: us / 1000.0

def write(name, header, rows):
    with open(OUT / name, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(header); w.writerows(rows)

# Table 3: hybrid KEM (run K1)
lat, stk = d.kem_latency(), d.kem_stack()
rows = []
for op, key in [("X25519 key generation", "X25519 keygen"), ("X25519 shared secret", "X25519 shared secret")]:
    v = lat[("--", key)]; rows.append([op, "n/a", ms(v["avg"]), ms(v["min"]), ms(v["max"]), stk[("--", key)]])
names = {"L1": "ML-KEM-512", "L3": "ML-KEM-768", "L5": "ML-KEM-1024"}
for L, nm in names.items():
    for op, lab in [("kem_keygen", "keygen"), ("kem_encaps", "encaps"), ("kem_decaps", "decaps")]:
        v = lat[(L, op)]; rows.append([f"{nm} {lab}", L, ms(v["avg"]), ms(v["min"]), ms(v["max"]), stk[(L, f"{nm} {lab}")]])
for L in names:
    r = [ms(lat[(L, o)]["avg"]) for o in ("hybrid_client_keygen", "hybrid_server_encaps", "hybrid_client_decaps")]
    rows.append(["Hybrid client KG / server En / client De", L, *r, "n/a"])
write("table3_hybrid_kem.csv", ["operation", "level", "avg_ms", "min_ms", "max_ms", "stack_B"], rows)

x = 2 * ms(lat[("--", "X25519 keygen")]["avg"]) + 2 * ms(lat[("--", "X25519 shared secret")]["avg"])
print("== Hybrid key exchange (Fig. 2, text) ==")
for L, nm in names.items():
    pq = sum(ms(lat[(L, o)]["avg"]) for o in ("kem_keygen", "kem_encaps", "kem_decaps"))
    print(f"  {nm}: X25519 {x:.1f} ms + ML-KEM {pq:.1f} ms = {x+pq:.1f} ms | classical {100*x/(x+pq):.0f}% | PQC {100*pq/(x+pq):.0f}%")
print(f"  KEM firmware heap high-water: {d.heap('K1')} B")

# Table 4: standalone signatures (S2 + S3)
st = d.standalone_signatures()
order = ["Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512"] + \
        [f"SLH-DSA-{h}-{p}{v}" for v in "fs" for h in ("SHA2", "SHAKE") for p in ("128", "192", "256")]
rows = []
for s in order:
    kg, sg, vf = (st[(s, o)] for o in ("keygen", "sign", "verify"))
    src = "S3" if (s, "sign") in d.sig("S3") else "S2"
    rows.append([s, sg["level"], sg["n"], ms(kg["avg"]), ms(sg["avg"]), ms(vf["avg"]), sg["sig"], src])
write("table4_standalone_signatures.csv", ["scheme", "level", "n", "keygen_ms", "sign_ms", "verify_ms", "sig_bytes", "run"], rows)
print("  failed (does not fit):", d.failed("S2"))

# Table 5: hybrid signatures (S1)
hy = d.hybrid_signatures()
rows = []
for s in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512"] + \
         [f"SLH-DSA-{h}-{p}f" for h in ("SHA2", "SHAKE") for p in ("128", "192", "256")]:
    k = "Ed25519+" + s; kg, sg, vf = (hy[(k, o)] for o in ("keygen", "sign", "verify"))
    rows.append([k, sg["level"], sg["n"], ms(kg["avg"]), ms(sg["avg"]), ms(vf["avg"]), sg["sig"]])
write("table5_hybrid_signatures.csv", ["scheme", "level", "n", "keygen_ms", "sign_ms", "verify_ms", "sig_bytes"], rows)
print(f"  signature firmware heap high-water (S1): {d.heap('S1')} B")

# Table 6: energy
cyc = lambda t, s: d.energy_mj(sum(t[(s, o)]["avg"] for o in ("keygen", "sign", "verify")))
L3 = sum(lat[("L3", o)]["avg"] for o in ("hybrid_client_keygen", "hybrid_server_encaps", "hybrid_client_decaps"))
kem768 = sum(lat[("L3", o)]["avg"] for o in ("kem_keygen", "kem_encaps", "kem_decaps"))
rows = [["X25519 + ML-KEM-768 key exchange", "hybrid KEM", d.energy_mj(L3)],
        ["ML-KEM-768 cycle (of the above)", "PQC only", d.energy_mj(kem768)]]
for s in ["Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512",
          "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-256f", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-192s"]:
    rows.append([f"{s} sign cycle", "classical" if s == "Ed25519" else "standalone", cyc(st, s)])
for s in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"]:
    rows.append([f"Ed25519 + {s} cycle", "hybrid", cyc(hy, "Ed25519+" + s)])
write("table6_energy.csv", ["operation", "type", "energy_mJ"], rows)
print("== Energy (Table 6) ==")
for r in rows: print(f"  {r[0]:36s} {r[2]:10.2f} mJ")

# Numbers quoted in the text
print("== ML-DSA signing spread (Fig. 4) ==")
for s in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
    v = st[(s, "sign")]; print(f"  {s}: {ms(v['min']):.0f}-{ms(v['max']):.0f} ms, mean {ms(v['avg']):.0f} ms, spread {v['max']/v['min']:.1f}x")
print("== SLH-DSA SHAKE/SHA2 signing ratio (Fig. 5) ==")
for v in "fs":
    for p in ("128", "192", "256"):
        a, b = st[(f"SLH-DSA-SHAKE-{p}{v}", "sign")]["avg"], st[(f"SLH-DSA-SHA2-{p}{v}", "sign")]["avg"]
        print(f"  {p}{v}: {b/1e6:.1f} s vs {a/1e6:.1f} s -> {a/b:.1f}x")
spread = max((st[k]["max"] - st[k]["min"]) / st[k]["avg"] for k in st if k[0].startswith("SLH") and k[1] == "sign")
print(f"== SLH-DSA 3-round signing spread: max {100*spread:.4f}%")
print("== Run-to-run difference, standalone SLH-DSA f signing (S1 vs S2/S3) ==")
s1 = d.sig("S1")
for h in ("SHA2", "SHAKE"):
    for p in ("128", "192", "256"):
        k = (f"SLH-DSA-{h}-{p}f", "sign"); a, b = s1[k]["avg"], st[k]["avg"]
        print(f"  {k[0]}: S1 {a/1e6:.2f} s vs {b/1e6:.2f} s ({100*(a-b)/b:+.1f}%)")
print(f"\nCSV tables written to {OUT}")
