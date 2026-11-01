"""Parser for the serial logs of the revised firmware (bench_common.h line formats).

Each capture file is one run. Runs are discovered automatically in a directory
(default data/raw/v2/) and identified by their own CSV,meta lines, so file names
are free. Line formats:

  CSV,meta,<key>,<value>
  RAW,<fw>,<scheme>,<level>,<op>,<sample>,<us>
  CSV,mem,<fw>,<scheme>,<level>,<op>,<stack_B>,<heap_peak_B>,<heap_base_B>,<static_B>,<ret>
  CSV,budget,<fw>,<scheme>,<level>,<op>,<class>,<ram_B>,<heap_cap_B>,<stack_B>,<static_B>,<result>
  CSV,allocfail,<fw>,<scheme>,<level>,<op>,<fails>,<largest_failed_B>,<heap_at_fail_B>
  CSV,falcon1024_keygen,<ret>,<us>,<heap_peak_B>,<fails>,<largest_failed_B>,<heap_at_fail_B>
  CSV,sig_us,<scheme>,<level>,<op>,<n>,<avg>,<min>,<max>,<sig_bytes>
  ENERGY,<seq>,<op>,<rep>,<us>
  HOST,... lines written by host/hs_server.py are ignored here.
"""
from dataclasses import dataclass, field
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW_V2 = ROOT / "data" / "raw" / "v2"


@dataclass
class Run:
    path: Path
    meta: dict = field(default_factory=dict)
    raw: pd.DataFrame = None
    mem: pd.DataFrame = None
    budget: pd.DataFrame = None
    allocfail: pd.DataFrame = None
    sig_summary: pd.DataFrame = None
    energy: pd.DataFrame = None
    other: list = field(default_factory=list)

    @property
    def firmware(self):
        return self.meta.get("firmware", "?")

    @property
    def clk_hz(self):
        return float(self.meta.get("clk_sys_hz", 125_000_000))

    def __repr__(self):
        return f"Run({self.path.name}, fw={self.firmware}, n_raw={0 if self.raw is None else len(self.raw)})"


def load(path):
    run = Run(Path(path))
    raw, mem, bud, af, sig, en = [], [], [], [], [], []
    for line in Path(path).read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        f = line.split(",")
        try:
            if f[0] == "RAW" and len(f) == 7:
                raw.append((f[1], f[2], f[3], f[4], int(f[5]), int(f[6])))
            elif f[0] == "ENERGY" and len(f) == 5:
                en.append((int(f[1]), f[2], int(f[3]), int(f[4])))
            elif f[0] != "CSV":
                continue
            elif f[1] == "meta":
                run.meta[f[2]] = ",".join(f[3:])
            elif f[1] == "mem":
                mem.append((f[2], f[3], f[4], f[5], int(f[6]), int(f[7]), int(f[8]), int(f[9]), int(f[10])))
            elif f[1] == "budget":
                bud.append((f[2], f[3], f[4], f[5], f[6], int(f[7]), int(f[8]), int(f[9]), int(f[10]), f[11]))
            elif f[1] == "allocfail":
                af.append((f[2], f[3], f[4], f[5], int(f[6]), int(f[7]), int(f[8])))
            elif f[1] == "sig_us":
                sig.append((f[2], f[3], f[4], int(f[5]), int(f[6]), int(f[7]), int(f[8]), int(f[9])))
            else:
                run.other.append(f[1:])
        except (IndexError, ValueError):
            continue   # truncated line at capture start/end
    run.raw = pd.DataFrame(raw, columns=["fw", "scheme", "level", "op", "sample", "us"])
    run.mem = pd.DataFrame(mem, columns=["fw", "scheme", "level", "op", "stack_B", "heap_peak_B", "heap_base_B", "static_B", "ret"])
    run.budget = pd.DataFrame(bud, columns=["fw", "scheme", "level", "op", "cls", "ram_B", "heap_cap_B", "stack_B", "static_B", "result"])
    run.allocfail = pd.DataFrame(af, columns=["fw", "scheme", "level", "op", "fails", "largest_failed_B", "heap_at_fail_B"])
    run.sig_summary = pd.DataFrame(sig, columns=["scheme", "level", "op", "n", "avg", "min", "max", "sig_bytes"])
    run.energy = pd.DataFrame(en, columns=["seq", "op", "rep", "us"])
    return run


def load_dir(d=RAW_V2):
    d = Path(d)
    runs = [load(p) for p in sorted(d.glob("*")) if p.suffix in (".txt", ".csv", ".log")]
    return [r for r in runs if r.meta]


def find(runs, firmware, **meta):
    """All runs of a firmware whose meta matches every key=value (substring match)."""
    out = []
    for r in runs:
        if r.firmware != firmware:
            continue
        if all(str(v) in r.meta.get(k, "") for k, v in meta.items()):
            out.append(r)
    return out


def one(runs, firmware, **meta):
    rs = find(runs, firmware, **meta)
    if not rs:
        return None
    if len(rs) > 1:
        print(f"  note: {len(rs)} runs match {firmware} {meta}; using {rs[0].path.name}")
    return rs[0]
