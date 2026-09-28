"""Regenerate the manuscript figures (Figs. 2-5) from the raw benchmark logs.

Output: figures/<name>.{pdf,png,tif}  (PDF vector; PNG/TIFF RGB at 600 dpi, no alpha).
Usage:  python analysis/make_figures.py
"""
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from PIL import Image
import pqcdata as d

OUT = Path(__file__).resolve().parent.parent / "figures"; OUT.mkdir(exist_ok=True)
plt.rcParams.update({"font.family": "Liberation Sans", "font.size": 8, "axes.linewidth": 0.7,
                     "savefig.facecolor": "white", "pdf.fonttype": 42, "ps.fonttype": 42})
C = {"cls": "#555555", "pqc": "#0072B2", "falcon": "#E69F00", "sha2": "#009E73", "shake": "#D55E00"}
GRID = dict(which="major", ls="-", lw=0.4, color="0.85")

def save(fig, stem):
    fig.savefig(OUT / f"{stem}.pdf", bbox_inches="tight", pad_inches=0.02)
    fig.savefig(OUT / f"{stem}.png", dpi=600, bbox_inches="tight", pad_inches=0.02)
    im = Image.open(OUT / f"{stem}.png").convert("RGB")
    im.save(OUT / f"{stem}.png"); im.save(OUT / f"{stem}.tif", compression="tiff_lzw", dpi=(600, 600))
    plt.close(fig); print(f"  {stem}: {im.size[0]}x{im.size[1]} px")

ms = lambda us: us / 1000.0
lat = d.kem_latency()
st = d.standalone_signatures()

# Fig. 2: classical vs PQC share of the combined key exchange (run K1)
x25519 = 2 * ms(lat[("--", "X25519 keygen")]["avg"]) + 2 * ms(lat[("--", "X25519 shared secret")]["avg"])
levels = [("L1", "ML-KEM-512 (L1)"), ("L3", "ML-KEM-768 (L3)"), ("L5", "ML-KEM-1024 (L5)")]
pq = [sum(ms(lat[(L, o)]["avg"]) for o in ("kem_keygen", "kem_encaps", "kem_decaps")) for L, _ in levels]
cl = [x25519] * 3; tot = [a + b for a, b in zip(cl, pq)]; y = np.arange(3)
fig, ax = plt.subplots(figsize=(4.8, 1.6))
ax.barh(y, cl, height=0.6, color=C["cls"], edgecolor="black", lw=0.5, label="X25519 (classical)")
ax.barh(y, pq, height=0.6, left=cl, color=C["pqc"], edgecolor="black", lw=0.5, label="ML-KEM (post-quantum)")
for i, (a, b, t) in enumerate(zip(cl, pq, tot)):
    ax.text(t + 18, i, f"{100*a/t:.0f}% classical / {100*b/t:.0f}% PQC", va="center")
ax.set_yticks(y); ax.set_yticklabels([l for _, l in levels]); ax.invert_yaxis()
ax.set_xlabel("Combined key-exchange computation (ms)"); ax.set_xlim(0, 700)
ax.grid(True, axis="x", **GRID); ax.set_axisbelow(True)
ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False)
save(fig, "fig_classical_dominates")

# Fig. 3: signature design space (runs S2 + S3)
Lft, Rgt = (0.72, 1.0, "right", "center"), (1.38, 1.0, "left", "center")
pts = [("Ed25519", "Ed25519", "cls", "o", Rgt), ("ML-DSA-44", "ML-DSA-44", "pqc", "o", Lft),
       ("ML-DSA-65", "ML-DSA-65", "pqc", "o", Rgt), ("ML-DSA-87", "ML-DSA-87", "pqc", "o", (1, 1.35, "center", "bottom")),
       ("Falcon-512", "Falcon-512", "falcon", "o", (1, 0.62, "center", "top"))]
for v, mk in (("f", "o"), ("s", "s")):
    for p in ("128", "192", "256"):
        pts.append((f"SLH-DSA-SHA2-{p}{v}", f"{p}{v}", "sha2", mk, Lft))
        pts.append((f"SLH-DSA-SHAKE-{p}{v}", f"{p}{v}", "shake", mk, Rgt))
fig, ax = plt.subplots(figsize=(6.3, 2.6))
for key, lab, c, mk, (dx, dy, ha, va) in pts:
    sx, sy, kg = ms(st[(key, "sign")]["avg"]), st[(key, "sign")]["sig"], ms(st[(key, "keygen")]["avg"])
    ax.scatter(sx, sy, s=10 + (kg ** 0.40) * 1.3, color=C[c], alpha=0.85, edgecolor="black", lw=0.5, marker=mk, zorder=3)
    ax.annotate(lab, (sx * dx, sy * dy), ha=ha, va=va, zorder=4)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlim(20, 8e6); ax.set_ylim(35, 1.3e5)
ax.set_xlabel("Signing time (ms, log scale)"); ax.set_ylabel("Signature size (bytes, log scale)")
ax.grid(True, **GRID); ax.set_axisbelow(True)
ax.annotate("Better", xy=(45, 120), xytext=(250, 120), ha="center", va="center", arrowprops=dict(arrowstyle="->", lw=0.9))
h = [Line2D([0], [0], marker="o", ls="", mfc=C[k], mec="k", mew=.4, ms=5, label=l) for k, l in
     [("cls", "Ed25519"), ("pqc", "ML-DSA"), ("falcon", "Falcon"), ("sha2", "SLH-DSA SHA2"), ("shake", "SLH-DSA SHAKE")]]
h += [Line2D([0], [0], marker="o", ls="", mfc="0.6", mec="k", mew=.4, ms=5, label="Fast (f)"),
      Line2D([0], [0], marker="s", ls="", mfc="0.6", mec="k", mew=.4, ms=5, label="Small (s)")]
ax.legend(handles=h, loc="lower right", ncol=2, frameon=True, framealpha=1, edgecolor="0.7",
          columnspacing=0.8, handletextpad=0.3, borderpad=0.3, labelspacing=0.25)
save(fig, "fig_sig_tradeoff")

# Fig. 4: ML-DSA signing-time variance (run S2)
ei = {"ML-DSA-44": "4.25", "ML-DSA-65": "5.1", "ML-DSA-87": "3.85"}   # FIPS 204 expected iterations
names = [("ML-DSA-44", "ML-DSA-44 (L2)"), ("ML-DSA-65", "ML-DSA-65 (L3)"), ("ML-DSA-87", "ML-DSA-87 (L5)")]
x = np.arange(3)
fig, ax = plt.subplots(figsize=(4.6, 2.25))
for i, (k, _) in enumerate(names):
    v = st[(k, "sign")]; mn, av, mx = ms(v["min"]), ms(v["avg"]), ms(v["max"])
    ax.plot([x[i]] * 2, [mn, mx], color=C["pqc"], lw=7, alpha=0.35, solid_capstyle="butt")
    for w in (mn, mx): ax.plot([x[i] - 0.1, x[i] + 0.1], [w, w], color=C["pqc"], lw=1.2)
    ax.plot(x[i], av, "o", color="black", ms=5, zorder=5)
    ax.text(x[i] + 0.14, mx, f"{mx/mn:.1f}\u00d7 spread", va="center")
    ax.text(x[i] + 0.14, mn, f"Expected {ei[k]} iterations", va="center")
ax.set_yscale("log"); ax.set_ylim(60, 4000); ax.set_xlim(-0.4, 3.35)
ax.set_xticks(x); ax.set_xticklabels([l for _, l in names]); ax.set_ylabel("Signing time (ms, log scale)")
ax.grid(True, axis="y", **GRID); ax.set_axisbelow(True)
ax.legend(handles=[Line2D([0], [0], color=C["pqc"], lw=7, alpha=0.35, label="Min\u2013max range"),
                   Line2D([0], [0], marker="o", ls="", color="black", ms=5, label="Mean")],
          loc="upper left", frameon=True, edgecolor="0.7")
save(fig, "fig_mldsa_variance")

# Fig. 5: SLH-DSA SHA2 vs SHAKE signing (runs S2 + S3)
sets = ["128f", "192f", "256f", "128s", "192s", "256s"]
s2 = [st[(f"SLH-DSA-SHA2-{s}", "sign")]["avg"] / 1e6 for s in sets]
sk = [st[(f"SLH-DSA-SHAKE-{s}", "sign")]["avg"] / 1e6 for s in sets]
x = np.arange(6); w = 0.38
fig, ax = plt.subplots(figsize=(4.6, 2.25))
ax.bar(x - w/2, s2, w, color=C["sha2"], edgecolor="black", lw=0.4, label="SHA2")
ax.bar(x + w/2, sk, w, color=C["shake"], edgecolor="black", lw=0.4, label="SHAKE")
for i in range(6): ax.text(x[i], sk[i] * 1.18, f"{sk[i]/s2[i]:.1f}\u00d7", ha="center", va="bottom")
ax.set_yscale("log"); ax.set_ylim(4, 4000); ax.set_xticks(x); ax.set_xticklabels(sets)
ax.set_xlabel("SLH-DSA parameter set"); ax.set_ylabel("Signing time (s, log scale)")
ax.grid(True, axis="y", **GRID); ax.set_axisbelow(True)
ax.legend(loc="upper left", frameon=True, edgecolor="0.7")
save(fig, "fig_sha2_vs_shake")
