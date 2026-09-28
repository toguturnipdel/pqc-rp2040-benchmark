"""Load the raw serial-log CSV lines produced by the benchmark firmware.

Line formats (see firmware/src):
  CSV,latency_us,<level>,<operation>,<n>,<avg>,<min>,<max>             (KEM firmware)
  CSV,stack_bytes,<level>,<operation>,<bytes>                          (KEM firmware)
  CSV,sig_us,<scheme>,<level>,<op>,<n>,<avg>,<min>,<max>,<sig_bytes>   (signature firmware)
  CSV,heap_arena_bytes,all,<bytes>
All times are microseconds. Rows with n == 0 record failed operations (Falcon-1024 OOM).
"""
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"
RUNS = {
    "K1": "run_kem_three_levels.csv",
    "S1": "run_sig1_fast_hybrid_n1.csv",
    "S2": "run_sig2_full_n3.csv",
    "S3": "run_sig3_sha2_completion_n3.csv",
}

def _lines(run):
    for line in (RAW / RUNS[run]).read_text().splitlines():
        line = line.strip()
        if line.startswith("CSV,"):
            yield line.split(",")

def kem_latency(run="K1"):
    """{(level, op): dict(n, avg, min, max)} in microseconds."""
    out = {}
    for f in _lines(run):
        if f[1] == "latency_us":
            out[(f[2], f[3])] = dict(n=int(f[4]), avg=int(f[5]), min=int(f[6]), max=int(f[7]))
    return out

def kem_stack(run="K1"):
    return {(f[2], f[3]): int(f[4]) for f in _lines(run) if f[1] == "stack_bytes"}

def heap(run):
    for f in _lines(run):
        if f[1] == "heap_arena_bytes":
            return int(f[3])
    return None

def sig(run):
    """{(scheme, op): dict(level, n, avg, min, max, sig)}; failed rows (n == 0) are dropped."""
    out = {}
    for f in _lines(run):
        if f[1] == "sig_us" and int(f[5]) > 0:
            out[(f[2], f[4])] = dict(level=f[3], n=int(f[5]), avg=int(f[6]),
                                     min=int(f[7]), max=int(f[8]), sig=int(f[9]))
    return out

def failed(run):
    """Schemes whose operations failed in a run (n == 0 rows)."""
    return sorted({f[2] for f in _lines(run) if f[1] == "sig_us" and int(f[5]) == 0})

def standalone_signatures():
    """Table 4 source: run S2 (3 rounds), with the four SHA2 sets S2 did not reach taken from S3."""
    d = sig("S2")
    for k, v in sig("S3").items():
        d.setdefault(k, v)
    return {k: v for k, v in d.items() if not k[0].startswith("Ed25519+")}

def hybrid_signatures():
    """Table 5 source: run S1 (the only run that completed a hybrid pass)."""
    return {k: v for k, v in sig("S1").items() if k[0].startswith("Ed25519+")}

POWER_MW = 79.2   # RP2040 datasheet model: 3.3 V x 24 mA active

def energy_mj(us):
    return us * 1e-6 * POWER_MW
