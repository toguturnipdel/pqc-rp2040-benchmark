"""End-to-end test: firmware handshake client logic (hs_core.c, built natively) against
host/hs_server.py over a pseudo-terminal. Run: python tests/hs_sim/run_test.py"""
import os, sys, subprocess, tty, io
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, "..", "..", "host"))
import hs_server
m, s = os.openpty(); tty.setraw(m)
p = subprocess.Popen([os.path.join(here, "hs_sim"), os.ttyname(s)])
f = os.fdopen(m, "rb+", buffering=0)
buf = b""
def readline():
    global buf
    while b"\n" not in buf:
        buf += f.read(4096)
    l, buf = buf.split(b"\n", 1)
    return l + b"\n"
log = io.StringIO()
ok = hs_server.serve(readline, lambda l: f.write((l + "\n").encode()), log)
p.wait()
print("device exit", p.returncode, "| server ok:", ok)
sys.exit(0 if ok and p.returncode == 0 else 1)
