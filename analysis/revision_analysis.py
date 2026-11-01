"""Analysis of the revised benchmark runs (responses to Reviewers 1-4).

Reads every run in data/raw/v2/ (or --raw DIR), identifies each by its CSV,meta
lines, and writes tables to data/processed/v2/ (or --out DIR) plus a printed
summary of the numbers quoted in the revision.

Statistics: median with a 95% bootstrap confidence interval (percentile method,
2,000 resamples, fixed seed), p5/p95, p99 and p99.9 where n is large enough,
observed min/max, mean, coefficient of variation, and median in cycles
(median_us x clk_sys / 1e6; under XIP these cycles include flash stalls).

Usage:  python analysis/revision_analysis.py [--raw DIR] [--out DIR] [--no-figures]
"""
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
import pqcdata_v2 as d

POWER_MW = 79.2          # datasheet model used in the submitted Table 6 (3.3 V x 24 mA)
SEED = 20261020
B = 2000
_rng = np.random.default_rng(SEED)


def boot_ci(x, stat=np.median, b=B):
    x = np.asarray(x, dtype=float)
    if len(x) < 5:
        return (np.nan, np.nan)
    idx = _rng.integers(0, len(x), size=(b, len(x)))
    s = stat(x[idx], axis=1)
    return tuple(np.percentile(s, [2.5, 97.5]))


def summ(x, clk_hz):
    x = np.asarray(x, dtype=float)
    n = len(x)
    lo, hi = boot_ci(x)
    out = dict(n=n, median_ms=np.median(x) / 1e3, ci_lo_ms=lo / 1e3, ci_hi_ms=hi / 1e3,
               mean_ms=x.mean() / 1e3, cv_pct=100 * x.std(ddof=1) / x.mean() if n > 1 else np.nan,
               p5_ms=np.percentile(x, 5) / 1e3, p95_ms=np.percentile(x, 95) / 1e3,
               p99_ms=np.percentile(x, 99) / 1e3 if n >= 100 else np.nan,
               p999_ms=np.percentile(x, 99.9) / 1e3 if n >= 1000 else np.nan,
               min_ms=x.min() / 1e3, max_ms=x.max() / 1e3,
               median_Mcycles=np.median(x) * clk_hz / 1e12)
    if n >= 1000:
        l99, h99 = boot_ci(x, stat=lambda a, axis: np.percentile(a, 99, axis=axis), b=500)
        out.update(p99_ci_lo_ms=l99 / 1e3, p99_ci_hi_ms=h99 / 1e3)
    return out


def table(df, keys, clk_hz):
    rows = []
    for k, g in df.groupby(keys, sort=False):
        rows.append(dict(zip(keys, k if isinstance(k, tuple) else (k,)), **summ(g["us"].values, clk_hz)))
    return pd.DataFrame(rows)


def energy_mj(us):
    return np.asarray(us, dtype=float) * 1e-6 * POWER_MW


def write(out, name, df):
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / name, index=False, float_format="%.4f")
    print(f"  wrote {name} ({len(df)} rows)")


def hdr(t):
    print(f"\n== {t} ==")


# ---------------------------------------------------------------------------
# Key exchange
# ---------------------------------------------------------------------------
CLASSICAL = ["client_x25519_keygen", "server_x25519_keygen", "server_x25519_shared", "client_x25519_shared"]
PQ = ["client_kem_keygen", "server_kem_encaps", "client_kem_decaps"]
# wolfCrypt does part of the encapsulation work while decoding the public key
# (wc_MlKemKey_DecodePublicKey), so the server's parse step belongs to the
# post-quantum share when it was measured (complete-exchange firmware). The X25519
# import inside server_parse is about 10 us and is neglected.
PQ_PARSE = "server_parse"


def kem_roles(w):
    """Per-round role totals from a wide frame (one row per round, one column per op)."""
    r = pd.DataFrame(index=w.index)
    r["client_keygen_primitive"] = w.client_x25519_keygen + w.client_kem_keygen
    r["server_encaps_primitive"] = w.server_x25519_keygen + w.server_x25519_shared + w.server_kem_encaps
    r["client_decaps_primitive"] = w.client_x25519_shared + w.client_kem_decaps
    if "client_serialise" in w:
        r["client_keygen_complete"] = r.client_keygen_primitive + w.client_serialise
        r["server_encaps_complete"] = (w.server_parse + r.server_encaps_primitive + w.server_serialise
                                       + w.server_combine_hkdf)
        r["client_decaps_complete"] = w.client_parse + r.client_decaps_primitive + w.client_combine_hkdf
        r["client_total_primitive"] = r.client_keygen_primitive + r.client_decaps_primitive
        r["client_total_complete_hkdf"] = r.client_keygen_complete + r.client_decaps_complete
        r["client_total_complete_xwing"] = (r.client_keygen_complete + w.client_parse + r.client_decaps_primitive
                                            + w.client_combine_xwing)
    cl = w[CLASSICAL].sum(axis=1)
    pq = w[PQ].sum(axis=1) + (w[PQ_PARSE] if PQ_PARSE in w else 0)
    if "server_parse" in w:
        r["server_encaps_with_decode"] = w.server_parse + w.server_kem_encaps   # comparable to the submitted encaps figure
    r["classical_share_pct"] = 100 * cl / (cl + pq)
    return r


def analyse_kem(runs, out):
    xip = d.find(runs, "kem", code_location="XIP")
    base = [r for r in xip if "p256=1" not in r.meta.get("config", "")]
    p256 = [r for r in xip if "p256=1" in r.meta.get("config", "")]
    run = base[0] if base else (p256[0] if p256 else None)
    if run is None:
        return
    hdr(f"Key exchange ({run.path.name}, board {run.meta.get('board_id')})")
    clk = run.clk_hz
    raw = run.raw
    hy = raw[raw.scheme.str.startswith("X25519+")]
    write(out, "kem_ops.csv", table(hy, ["scheme", "level", "op"], clk))
    roles = []
    for (sch, lvl), g in hy.groupby(["scheme", "level"], sort=False):
        w = g.pivot(index="sample", columns="op", values="us")
        r = kem_roles(w)
        for c in r.columns:
            if c == "classical_share_pct":
                v = r[c].values
                lo, hi = boot_ci(v)
                roles.append(dict(scheme=sch, level=lvl, quantity=c, n=len(v), median=np.median(v), ci_lo=lo, ci_hi=hi))
            else:
                roles.append(dict(scheme=sch, level=lvl, quantity=c, **summ(r[c].values, clk),
                                  energy_model_mJ_median=float(energy_mj(np.median(r[c].values)))))
        if "client_total_complete_hkdf" in r:
            ov = 100 * (r.client_total_complete_hkdf / r.client_total_primitive - 1)
            print(f"  {sch}: classical share median {np.median(r.classical_share_pct):.1f}% | client total "
                  f"primitive {np.median(r.client_total_primitive)/1e3:.1f} ms, complete (HKDF) "
                  f"{np.median(r.client_total_complete_hkdf)/1e3:.1f} ms (+{np.median(ov):.2f}%), "
                  f"client energy (model) {energy_mj(np.median(r.client_total_complete_hkdf)):.1f} mJ")
    write(out, "kem_roles.csv", pd.DataFrame(roles))

    for nm in ("server_combine_hkdf", "server_combine_xwing", "client_serialise", "server_parse"):
        g = hy[hy.op == nm]
        if len(g):
            print(f"  {nm}: median {np.median(g.us)/1e3:.3f} ms (all levels)")

    p = p256[0].raw[p256[0].raw.scheme == "P-256"] if p256 else raw.iloc[0:0]
    if len(p):
        t = table(p, ["scheme", "op"], clk)
        write(out, "p256_ops.csv", t)
        kg, sh = (np.median(p[p.op == o].us) for o in ("keygen", "shared"))
        for lvl, g in hy.groupby("level"):
            pq = sum(np.median(g[g.op == o].us) for o in PQ)
            cl = 2 * kg + 2 * sh
            print(f"  P-256 + ML-KEM {lvl}: classical share (medians, not paired) {100*cl/(cl+pq):.1f}%")


# ---------------------------------------------------------------------------
# X25519 implementation comparison
# ---------------------------------------------------------------------------
def analyse_x25519(runs, out):
    rs = d.find(runs, "x25519_alt")
    if not rs:
        return
    hdr("X25519 implementation comparison")
    rows, share_rows = [], []
    for run in rs:
        raw, clk = run.raw, run.clk_hz
        impl = run.meta.get("config", "")
        sm = raw[~raw.scheme.str.contains(r"\+")]
        t = table(sm, ["scheme", "op"], clk)
        t.insert(0, "run_config", impl)
        rows.append(t)
        hy = raw[raw.scheme.str.contains(r"\+")]
        for (sch, lvl), g in hy.groupby(["scheme", "level"], sort=False):
            w = g.pivot(index="sample", columns="op", values="us")
            r = kem_roles(w)
            v = r.classical_share_pct.values
            lo, hi = boot_ci(v)
            share_rows.append(dict(run_config=impl, scheme=sch, level=lvl, n=len(v),
                                   classical_share_median_pct=np.median(v), ci_lo=lo, ci_hi=hi))
    t = pd.concat(rows)
    write(out, "x25519_impls.csv", t)
    for _, r in t.iterrows():
        print(f"  {r['scheme']:<44s} {r['op']:<11s} median {r['median_ms']:8.2f} ms  ({r['median_Mcycles']:.2f} Mcycles)")
    s = pd.DataFrame(share_rows).drop_duplicates(subset=["scheme", "level"])
    s = s.rename(columns={"classical_share_median_pct": "share_in_x25519_alt_run_pct"})
    s["note_in_run"] = "x25519_alt run; its encapsulation excludes ML-KEM public-key decoding"
    # Like-for-like share reported in the manuscript (Table 11): four x25519-cm0 scalar
    # multiplications (SRAM median) plus the same ML-KEM cycle as the wolfCrypt share,
    # i.e. key generation, public-key decoding, encapsulation and decapsulation from the
    # key-exchange run (medians).
    kem = d.one(runs, "kem")
    cm = t[(t.scheme == "x25519-cm0-sram") & (t.op == "scalarmult")].median_ms.iloc[0]
    if kem is not None:
        kr = kem.raw
        for i, r in s.iterrows():
            lvl = r["level"]; sch = r["scheme"].replace("X25519cm0+", "X25519+")
            g = kr[(kr.scheme == sch) & (kr.level == lvl)]
            pq = sum(np.median(g[g.op == o].us.values) / 1e3 for o in
                     ["client_kem_keygen", "server_parse", "server_kem_encaps", "client_kem_decaps"])
            s.loc[i, "classical_share_like_for_like_pct"] = 100 * 4 * cm / (4 * cm + pq)
    write(out, "x25519_cm0_hybrid_share.csv", s)
    for _, r in s.iterrows():
        print(f"  hybrid with x25519-cm0 (SRAM) {r['level']}: classical share {r.get('classical_share_like_for_like_pct', float('nan')):.1f}% "
              f"(like-for-like; {r['share_in_x25519_alt_run_pct']:.1f}% within the x25519_alt run)")


# ---------------------------------------------------------------------------
# Signatures (paired)
# ---------------------------------------------------------------------------
def analyse_sig(runs, out):
    rs = d.find(runs, "sig")
    if not rs:
        return
    hdr("Signatures (paired standalone + hybrid)")
    clk = rs[0].clk_hz
    raw = pd.concat([r.raw for r in rs])
    sigb = pd.concat([r.sig_summary for r in rs]).drop_duplicates(subset=["scheme", "op"])
    t = table(raw, ["scheme", "level", "op"], clk)
    t = t.merge(sigb[sigb.op == "sign"][["scheme", "sig_bytes"]], on="scheme", how="left")
    write(out, "sig_ops.csv", t)

    # Additivity check: hybrid sign/verify = bind + Ed25519 + PQ component, per sample
    chk = []
    for sch in raw.scheme.unique():
        if not sch.startswith("Ed25519+"):
            continue
        pqs = sch.split("+", 1)[1]
        h = raw[raw.scheme == sch].pivot_table(index="sample", columns="op", values="us")
        p = raw[raw.scheme == pqs].pivot_table(index="sample", columns="op", values="us")
        j = h.join(p, rsuffix="_pq", how="inner")
        if {"sign", "bind_sign", "ed_sign", "sign_pq"} <= set(j.columns):
            dsg = (j["sign"] - j.bind_sign - j.ed_sign - j.sign_pq).abs().max()
            dvf = (j["verify"] - j.bind_verify - j.ed_verify - j.verify_pq).abs().max()
            share_v = 100 * np.median(j.ed_verify / j["verify"])
            chk.append(dict(hybrid=sch, n=len(j), max_abs_residual_sign_us=dsg, max_abs_residual_verify_us=dvf,
                            bind_median_ms=np.median(j.bind_sign) / 1e3,
                            ed25519_share_of_hybrid_verify_pct=share_v))
    if chk:
        c = pd.DataFrame(chk)
        write(out, "sig_additivity.csv", c)
        print(f"  additivity residual (max over all hybrids): sign {c.max_abs_residual_sign_us.max():.0f} us, "
              f"verify {c.max_abs_residual_verify_us.max():.0f} us (0 by construction)")
        print(f"  composite binding (SHA-512 + concat): median {c.bind_median_ms.median():.2f} ms")

    slh = t[t.scheme.str.startswith("SLH-DSA") & (t.op == "sign")]
    if len(slh):
        print("  SLH-DSA signing CV across rounds: " +
              ", ".join(f"{r.scheme.replace('SLH-DSA-','')} {r.cv_pct:.3f}% (n={r.n})" for r in slh.itertuples()))
    for r in rs:
        for o in r.other:
            if o[0] == "falcon1024_keygen":
                print(f"  Falcon-1024 on-device keygen: ret {o[1]}, tracked heap peak {o[3]} B, "
                      f"failed allocations {o[4]}, largest failed request {o[5]} B (live heap then {o[6]} B)")


# ---------------------------------------------------------------------------
# ML-DSA distribution
# ---------------------------------------------------------------------------
def analyse_mldsa(runs, out, figures):
    rs = d.find(runs, "mldsa_dist")
    if not rs:
        return
    hdr("ML-DSA signing distribution")
    tabs = []
    for run in rs:
        build = "speed" if "speed" in run.meta.get("config", "") else "small_mem"
        t = table(run.raw, ["scheme", "level", "op"], run.clk_hz)
        t.insert(0, "build", build)
        sg = run.raw[run.raw.op == "sign"]
        ex = []
        for sch, g in sg.groupby("scheme"):
            ex.append(dict(scheme=sch, op="sign", frac_over_1s=(g.us > 1e6).mean(), frac_over_2s=(g.us > 2e6).mean()))
        t = t.merge(pd.DataFrame(ex), on=["scheme", "op"], how="left")
        tabs.append(t)
        for o in run.other:
            if o[0] in ("mldsa_dist_error", "mldsa_dist_heap"):
                print(f"  [{build}] {','.join(o)}")
    t = pd.concat(tabs)
    write(out, "mldsa_distribution.csv", t)
    for r in t[(t.op == "sign")].itertuples():
        print(f"  [{r.build}] {r.scheme:<20s} n={r.n:<6d} median {r.median_ms:7.1f} ms [{r.ci_lo_ms:.1f}, {r.ci_hi_ms:.1f}]"
              f"  p95 {r.p95_ms:7.1f}  p99 {r.p99_ms:7.1f}  p99.9 {r.p999_ms:7.1f}  max {r.max_ms:7.1f} ms")
    if figures:
        fig_mldsa_ecdf(rs[0], out)


def fig_mldsa_ecdf(run, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(4.6, 2.4))
    for (sch, lvl), g in run.raw[(run.raw.op == "sign") & ~run.raw.scheme.str.contains(r"\+")].groupby(["scheme", "level"]):
        x = np.sort(g.us.values) / 1e3
        ax.plot(x, 1 - np.arange(len(x)) / len(x), lw=1.2, label=f"{sch} ({lvl})")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Signing time (ms, log scale)"); ax.set_ylabel("P(time > x)")
    ax.grid(True, which="major", lw=0.4, color="0.85"); ax.legend(frameon=False, fontsize=7)
    p = out / "fig_mldsa_ccdf.pdf"
    fig.savefig(p, bbox_inches="tight"); fig.savefig(p.with_suffix(".png"), dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {p.name}")


# ---------------------------------------------------------------------------
# Code location (XIP vs SRAM)
# ---------------------------------------------------------------------------
def analyse_codeloc(runs, out):
    rows = []
    for fw in ("slh_codeloc", "kem"):
        xs = [r for r in d.find(runs, fw, code_location="XIP") if "p256=1" not in r.meta.get("config", "")]
        x, s = (xs[0] if xs else None), d.one(runs, fw, code_location="SRAM")
        if x is None or s is None:
            continue
        a = x.raw.groupby(["scheme", "op"]).us.median()
        b = s.raw.groupby(["scheme", "op"]).us.median()
        j = pd.DataFrame({"xip_median_ms": a / 1e3, "sram_median_ms": b / 1e3}).dropna()
        j["xip_over_sram"] = j.xip_median_ms / j.sram_median_ms
        j.insert(0, "firmware", fw)
        rows.append(j.reset_index())
    if rows:
        hdr("Code location: XIP vs SRAM")
        t = pd.concat(rows)
        write(out, "codeloc_xip_vs_sram.csv", t)
        for r in t[t.op.isin(["sign", "client_kem_decaps", "client_x25519_shared"])].itertuples():
            print(f"  {r.scheme:<26s} {r.op:<22s} XIP/SRAM = {r.xip_over_sram:.3f}")


# ---------------------------------------------------------------------------
# Memory and RAM budgets
# ---------------------------------------------------------------------------
def analyse_memory(runs, out):
    rs = d.find(runs, "sig_mem") + d.find(runs, "kem", code_location="XIP")
    mems = [r.mem for r in rs if len(r.mem)]
    if not mems:
        return
    hdr("Memory per operation and emulated RFC 7228 budgets")
    m = pd.concat(mems, ignore_index=True)
    m["footprint_B"] = m.static_B + m.stack_B + m.heap_base_B + m.heap_peak_B
    write(out, "memory_per_op.csv", m)
    bud = pd.concat([r.budget for r in rs if len(r.budget)])
    pv = bud.pivot_table(index=["scheme", "level", "op"], columns="cls", values="result", aggfunc="first").reset_index()
    write(out, "ram_budget_matrix.csv", pv)
    af = pd.concat([r.allocfail for r in rs if len(r.allocfail)]) if any(len(r.allocfail) for r in rs) else None
    if af is not None:
        write(out, "allocation_failures.csv", af)
    for cls in ("C1", "C2"):
        if cls in pv:
            ok = pv[pv[cls] == "PASS"]
            print(f"  {cls}: {len(ok)} of {len(pv)} operations pass the enforced budget")
    sig_stack = m[m.fw == "sig_mem"].stack_B
    if len(sig_stack):
        print(f"  signature stack: max {sig_stack.max()} B ({m.loc[sig_stack.idxmax(), 'scheme']} "
              f"{m.loc[sig_stack.idxmax(), 'op']})")


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------
def analyse_handshake(runs, out):
    run = d.one(runs, "handshake")
    if run is None:
        return
    hdr("Host-to-device handshake (device = client, USB CDC)")
    raw = run.raw
    rows = []
    for (sch, lvl), g in raw.groupby(["scheme", "level"], sort=False):
        w = g.pivot(index="sample", columns="op", values="us")
        w["link"] = w["wait"] - w["host_compute"]
        w["device_compute"] = w[["keygen", "serialise", "parse", "x25519_shared", "kem_decaps", "combine"]].sum(axis=1)
        for c in ["device_compute", "serialise", "combine", "hex_send", "hex_recv", "link", "host_compute", "confirm", "total"]:
            rows.append(dict(scheme=sch, level=lvl, quantity=c, **summ(w[c].values, run.clk_hz)))
        med = lambda c: np.median(w[c].values) / 1e3
        print(f"  {sch}: total {med('total'):.1f} ms, device compute {med('device_compute'):.1f} ms, "
              f"serialise {med('serialise'):.3f} ms, combine {med('combine'):.3f} ms, "
              f"link (USB+hex) {med('link'):.1f} ms")
    write(out, "handshake.csv", pd.DataFrame(rows))


# ---------------------------------------------------------------------------
# Energy: model vs measurement (if energy_from_trace.py output exists)
# ---------------------------------------------------------------------------
def analyse_energy(out):
    p = out / "energy_measured.csv"
    if not p.exists():
        return
    hdr("Energy: measured vs constant-power model")
    e = pd.read_csv(p)
    e["model_mJ"] = energy_mj(e.median_us)
    e["model_over_gross"] = e.model_mJ / e.median_gross_mJ    # model vs total board energy during the op
    e["model_over_net"] = e.model_mJ / e.median_net_mJ        # model vs energy above idle
    write(out, "energy_model_vs_measured.csv", e)
    for c in ("model_over_gross", "model_over_net"):
        print(f"  {c}: median {e[c].median():.2f}, range {e[c].min():.2f} to {e[c].max():.2f}")
    print(f"  measured active current during operations: median {e.median_current_mA.median():.1f} mA "
          f"(model assumes 24 mA); idle {e.idle_mA.iloc[0]:.1f} mA")


# ---------------------------------------------------------------------------
# Board-to-board agreement (same firmware on two or more boards)
# ---------------------------------------------------------------------------
def analyse_boards(runs, out):
    rows = []
    for fw in sorted({r.firmware for r in runs}):
        rs = [r for r in d.find(runs, fw) if len(r.raw)]
        boards = {}
        for r in rs:
            key = (r.meta.get("config", ""), r.meta.get("code_location", ""))
            boards.setdefault(key, {}).setdefault(r.meta.get("board_id"), r)
        for key, by in boards.items():
            if len(by) < 2:
                continue
            ids = sorted(by)
            ref = by[ids[0]].raw.groupby(["scheme", "level", "op"]).us.median()
            for b in ids[1:]:
                oth = by[b].raw.groupby(["scheme", "level", "op"]).us.median()
                j = pd.DataFrame({"ref_ms": ref / 1e3, "other_ms": oth / 1e3}).dropna()
                j["diff_pct"] = 100 * (j.other_ms / j.ref_ms - 1)
                j = j.reset_index(); j.insert(0, "firmware", fw); j.insert(1, "ref_board", ids[0]); j.insert(2, "other_board", b)
                rows.append(j)
    if rows:
        hdr("Board-to-board agreement")
        t = pd.concat(rows)
        write(out, "board_agreement.csv", t)
        for fw, g in t.groupby("firmware"):
            # exclude rejection-sampling signing, whose medians move with sampling noise
            g2 = g[~(g.scheme.str.contains("ML-DSA") & (g.op == "sign"))]
            print(f"  {fw}: median |diff| {g2.diff_pct.abs().median():.2f}%, max |diff| {g2.diff_pct.abs().max():.2f}% "
                  f"over {len(g2)} operations")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=str(d.RAW_V2))
    ap.add_argument("--out", default=str(d.ROOT / "data" / "processed" / "v2"))
    ap.add_argument("--no-figures", action="store_true")
    a = ap.parse_args()
    runs = d.load_dir(a.raw)
    out = Path(a.out)
    print(f"{len(runs)} runs in {a.raw}:")
    for r in runs:
        print(f"  {r.path.name}: {r.firmware} | {r.meta.get('config','')} | {r.meta.get('code_location','')} | board {r.meta.get('board_id','?')}")
    boards = {r.meta.get("board_id") for r in runs}
    all_runs = runs
    if len(boards) > 1:
        from collections import Counter
        primary = Counter(r.meta.get("board_id") for r in runs).most_common(1)[0][0]
        print(f"  note: runs come from {len(boards)} boards; tables use the primary board {primary}, "
              f"the others feed the board-agreement check")
        runs = [r for r in runs if r.meta.get("board_id") == primary]
    analyse_kem(runs, out)
    analyse_x25519(runs, out)
    analyse_sig(runs, out)
    analyse_mldsa(runs, out, not a.no_figures)
    analyse_codeloc(runs, out)
    analyse_memory(runs, out)
    analyse_handshake(runs, out)
    analyse_boards(all_runs, out)
    analyse_energy(out)


if __name__ == "__main__":
    main()
