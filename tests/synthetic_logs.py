"""SYNTHETIC serial logs in the exact line formats of the revised firmware.

For testing analysis/*.py only. Values are invented (loosely scaled from the
submitted manuscript) and every run is tagged config=SYNTHETIC. Never place
these files in data/raw/.

Usage: python tests/synthetic_logs.py OUT_DIR
"""
import sys
from pathlib import Path
import numpy as np

rng = np.random.default_rng(1)


def meta(f, fw, config, loc="XIP", board="E6614103E7000000"):
    f.write(f"CSV,meta,firmware,{fw}\nCSV,meta,wolfssl,5.9.2\nCSV,meta,clk_sys_hz,125000000\n"
            f"CSV,meta,board_id,{board}\nCSV,meta,config,SYNTHETIC {config}\nCSV,meta,code_location,{loc}\n")


def jit(us, cv=0.003, n=None):
    return np.maximum(1, rng.normal(us, us * cv, n)).astype(int)


KEM_US = {"L1": (9440, 12360, 13930), "L3": (14160, 18570, 20600), "L5": (21730, 27300, 29830)}


def kem(out, board="E6614103E7000000", loc="XIP", scale=1.0, p256=False):
    name = f"kem_{loc}_{board[-4:]}{'_p256' if p256 else ''}.txt"
    with open(out / name, "w") as f:
        meta(f, "kem", "rounds=100 warmup=1" + (" p256=1" if p256 else ""), loc, board)
        f.write("CSV,meta,sizeof_MlKemKey,5016\nCSV,meta,sizeof_curve25519_key,140\n")
        for i, (lvl, (kg, en, de)) in enumerate(KEM_US.items()):
            sch = ["X25519+ML-KEM-512", "X25519+ML-KEM-768", "X25519+ML-KEM-1024"][i]
            for r in range(100):
                ops = dict(client_x25519_keygen=88090, client_kem_keygen=kg, client_serialise=60 + 20 * i,
                           server_parse=120 + 40 * i, server_x25519_keygen=88090, server_x25519_shared=87550,
                           server_kem_encaps=en, server_combine_hkdf=1450, server_combine_xwing=980,
                           server_serialise=40, client_parse=35, client_x25519_shared=87550,
                           client_kem_decaps=de, client_combine_hkdf=1450, client_combine_xwing=980)
                for op, us in ops.items():
                    f.write(f"RAW,kem,{sch},{lvl},{op},{r},{int(jit(us) * scale)}\n")
        if p256:
            for r in range(200):
                f.write(f"RAW,kem,P-256,--,keygen,{r},{jit(41000)}\nRAW,kem,P-256,--,shared,{r},{jit(43000)}\n")
        for sch, lvl, op, st, hp, sb in [("X25519", "--", "keygen", 1228, 0, 140), ("X25519", "--", "shared", 1332, 0, 312),
                                         ("ML-KEM-512", "L1", "keygen", 888, 3200, 5016), ("ML-KEM-512", "L1", "encaps", 944, 3500, 5816),
                                         ("ML-KEM-512", "L1", "decaps", 928, 4100, 5816), ("ML-KEM-1024", "L5", "decaps", 928, 9800, 6616),
                                         ("HKDF-SHA256", "--", "combine", 600, 200, 96)]:
            f.write(f"CSV,mem,kem,{sch},{lvl},{op},{st},{hp},2200,{sb},0\n")
            for cls, ram in (("C1", 10240), ("C2", 51200)):
                fp = st + hp + 2200 + sb
                res = "PASS" if fp <= ram else "EXCEEDS"
                f.write(f"CSV,budget,kem,{sch},{lvl},{op},{cls},{ram},{ram - sb - st if res == 'PASS' else 0},{st},{sb},{res}\n")


def mldsa_sign(base, p, n):
    return (base * rng.geometric(p, n) * rng.normal(1, 0.02, n)).astype(int)


def sig(out):
    with open(out / "sig_lattice.txt", "w") as f:
        meta(f, "sig", "part=1 lattice_rounds=100")
        for r in range(100):
            f.write(f"RAW,sig,Ed25519,--,keygen,{r},{jit(39080)}\nRAW,sig,Ed25519,--,sign,{r},{jit(41720)}\nRAW,sig,Ed25519,--,verify,{r},{jit(106940)}\n")
        for name, lvl, kg, sbase, p, vf, sz, kop in [("ML-DSA-44", "L2", 41530, 68000, 1 / 4.25, 45930, 2420, "keygen"),
                                                     ("ML-DSA-65", "L3", 67810, 132000, 1 / 5.1, 73670, 3309, "keygen"),
                                                     ("ML-DSA-87", "L5", 112380, 139000, 1 / 3.85, 119750, 4627, "keygen"),
                                                     ("Falcon-512", "L1", 2100, 1236000, 1.0, 9790, 654, "import"),
                                                     ("Falcon-1024", "L5", 4100, 2600000, 1.0, 19500, 1271, "import")]:
            h = f"Ed25519+{name}"
            for r in range(100):
                t_kg, t_sg, t_vf = jit(kg), (mldsa_sign(sbase, p, 1)[0] if p < 1 else jit(sbase)), jit(vf)
                e_kg, e_sg, e_vf, b1, b2 = jit(39080), jit(41900), jit(107100), jit(1900), jit(1900)
                f.write(f"RAW,sig,{name},{lvl},{kop},{r},{t_kg}\nRAW,sig,{name},{lvl},sign,{r},{t_sg}\nRAW,sig,{name},{lvl},verify,{r},{t_vf}\n")
                f.write(f"RAW,sig,{h},{lvl},ed_keygen,{r},{e_kg}\nRAW,sig,{h},{lvl},ed_sign,{r},{e_sg}\nRAW,sig,{h},{lvl},ed_verify,{r},{e_vf}\n")
                f.write(f"RAW,sig,{h},{lvl},bind_sign,{r},{b1}\nRAW,sig,{h},{lvl},bind_verify,{r},{b2}\n")
                f.write(f"RAW,sig,{h},{lvl},{kop},{r},{t_kg + e_kg}\nRAW,sig,{h},{lvl},sign,{r},{b1 + e_sg + t_sg}\nRAW,sig,{h},{lvl},verify,{r},{b2 + e_vf + t_vf}\n")
            f.write(f"CSV,sig_us,{name},{lvl},sign,100,0,0,0,{sz}\nCSV,sig_us,{h},{lvl},sign,100,0,0,0,{sz + 64}\n")
        f.write("CSV,falcon1024_keygen,-125,812,98304,1,73728,98304\n")
    with open(out / "sig_slh_f.txt", "w") as f:
        meta(f, "sig", "part=2 slh_f=20")
        for name, us in [("SLH-DSA-SHA2-128f", 8.31e6), ("SLH-DSA-SHAKE-128f", 26.0e6)]:
            for r in range(20):
                f.write(f"RAW,sig,{name},L1,keygen,{r},{jit(355000)}\nRAW,sig,{name},L1,sign,{r},{jit(us, 0.0004)}\nRAW,sig,{name},L1,verify,{r},{jit(502000)}\n")


def sig_mem(out):
    with open(out / "sig_mem.txt", "w") as f:
        meta(f, "sig_mem", "part=0")
        rows = [("Ed25519", "--", "sign", 2900, 0, 300), ("ML-DSA-44", "L2", "sign", 3100, 33000, 9000),
                ("ML-DSA-87", "L5", "sign", 3300, 78000, 15000), ("Falcon-512", "L1", "sign", 2400, 26000, 6500),
                ("Falcon-512", "L1", "verify", 1800, 3600, 6500), ("SLH-DSA-SHA2-128f", "L1", "sign", 4200, 1100, 17400)]
        for sch, lvl, op, st, hp, sb in rows:
            f.write(f"CSV,mem,sig_mem,{sch},{lvl},{op},{st},{hp},2200,{sb},0\n")
            for cls, ram in (("C1", 10240), ("C2", 51200)):
                fp = st + hp + 2200 + sb
                f.write(f"CSV,budget,sig_mem,{sch},{lvl},{op},{cls},{ram},0,{st},{sb},{'PASS' if fp <= ram else 'EXCEEDS'}\n")
        f.write("CSV,mem,sig_mem,Falcon-1024,L5,keygen,1600,98304,2200,4144,-125\n")
        f.write("CSV,allocfail,sig_mem,Falcon-1024,L5,keygen,1,73728,98304\n")


def mldsa(out, speed=False):
    with open(out / f"mldsa_dist{'_speed' if speed else ''}.txt", "w") as f:
        meta(f, "mldsa_dist", f"n=10000 key_every=100 mldsa_build={'speed' if speed else 'small_mem'}")
        for name, lvl, base, p in [("ML-DSA-44", "L2", 68000, 1 / 4.25), ("ML-DSA-65", "L3", 132000, 1 / 5.1), ("ML-DSA-87", "L5", 139000, 1 / 3.85)]:
            if speed and name == "ML-DSA-87":
                f.write("CSV,mldsa_dist_error,ML-DSA-87,keygen,-1,-125\n"); continue
            s = mldsa_sign(base * (0.8 if speed else 1), p, 10000)
            for r, us in enumerate(s):
                f.write(f"RAW,mldsa_dist,{name},{lvl},sign,{r},{us}\n")
                f.write(f"RAW,mldsa_dist,Ed25519+{name},{lvl},sign,{r},{us + 41800}\n")


def x25519(out, small=False):
    with open(out / f"x25519_alt{'_small' if small else ''}.txt", "w") as f:
        impl = "wolfCrypt-CURVED25519_SMALL(fe_low_mem.c)" if small else "wolfCrypt-default(fe_operations.c)"
        meta(f, "x25519_alt", f"rounds=100 wolf_x25519={impl}")
        for r in range(100):
            f.write(f"RAW,x25519_alt,{impl},--,keygen,{r},{jit(150000 if small else 88090)}\n")
            f.write(f"RAW,x25519_alt,{impl},--,shared,{r},{jit(150000 if small else 87550)}\n")
            f.write(f"RAW,x25519_alt,x25519-cm0-flash,--,scalarmult,{r},{jit(30500, 0.0005)}\n")
            f.write(f"RAW,x25519_alt,x25519-cm0-sram,--,scalarmult,{r},{jit(25900, 0.0002)}\n")
        for (lvl, (kg, en, de)), sch in zip(KEM_US.items(), ["X25519cm0+ML-KEM-512", "X25519cm0+ML-KEM-768", "X25519cm0+ML-KEM-1024"]):
            for r in range(100):
                for op, us in dict(client_x25519_keygen=25900, client_kem_keygen=kg, server_x25519_keygen=25900,
                                   server_x25519_shared=25900, server_kem_encaps=en, client_x25519_shared=25900,
                                   client_kem_decaps=de).items():
                    f.write(f"RAW,x25519_alt,{sch},{lvl},{op},{r},{jit(us)}\n")


def slh_codeloc(out):
    for loc, s in (("XIP", 1.0), ("SRAM", 0.93)):
        with open(out / f"slh_{loc}.txt", "w") as f:
            meta(f, "slh_codeloc", "rounds=20", loc)
            for r in range(20):
                f.write(f"RAW,slh_codeloc,SLH-DSA-SHA2-128f,L1,sign,{r},{jit(8.31e6 * s, 0.0004)}\n")
                f.write(f"RAW,slh_codeloc,SLH-DSA-SHAKE-128f,L1,sign,{r},{jit(26.0e6 * s, 0.0004)}\n")


def handshake(out):
    with open(out / "handshake.txt", "w") as f:
        meta(f, "handshake", "rounds=50 transport=usb-cdc-hex")
        for (lvl, (kg, en, de)), sch in zip(KEM_US.items(), ["X25519+ML-KEM-512", "X25519+ML-KEM-768", "X25519+ML-KEM-1024"]):
            for r in range(50):
                host = jit(9000); wait = host + jit(4000)
                t = dict(keygen=88090 + kg, serialise=80, hex_send=900, wait=wait, hex_recv=850, parse=35,
                         x25519_shared=87550, kem_decaps=de, combine=1450, confirm=3800, host_compute=host)
                t["total"] = sum(v for k, v in t.items() if k != "host_compute")
                for op, us in t.items():
                    f.write(f"RAW,handshake,{sch},{lvl},{op},{r},{int(us)}\n")


def energy(out):
    ops = [("X25519 keygen", 88090), ("ML-KEM-768 encaps", 18570), ("Ed25519 verify", 106940)]
    t, dt, rows, lines = 0.0, 1e-5, [], []
    def emit(dur, cur, hi):
        nonlocal t
        n = int(round(dur / dt))
        for _ in range(n):
            rows.append((t * 1e3, cur * 1e6 + rng.normal(0, 50), "00000001" if hi else "00000000")); t += dt
    emit(0.2, 6.0e-3, False)
    seq = 0
    for name, us in ops:
        for rep in range(5):
            emit(us * 1e-6, 21.0e-3, True)
            lines.append(f"ENERGY,{seq},{name},{rep},{us}"); seq += 1
            emit(0.05, 6.0e-3, False)
    with open(out / "energy_trace.csv", "w") as f:
        f.write("Timestamp(ms),Current(uA),D0-D7\n")
        for a, b, c in rows:
            f.write(f"{a:.3f},{b:.1f},{c}\n")
    with open(out / "energy_log.txt", "w") as f:
        meta(f, "energy", "reps=5 gap_ms=50")
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    kem(out); kem(out, loc="SRAM", scale=0.95); kem(out, board="E6614103E700BEEF", scale=1.002); kem(out, p256=True, board="E6614103E7000001")
    sig(out); sig_mem(out); mldsa(out); mldsa(out, speed=True); x25519(out); x25519(out, small=True)
    slh_codeloc(out); handshake(out); energy(out)
    print(f"SYNTHETIC logs written to {out}")
