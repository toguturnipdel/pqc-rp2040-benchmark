#!/usr/bin/env python3
"""Host (server) side of the RP2040 hybrid key-exchange handshake (Reviewer 3, point 1).

Runs against firmware target pqc_handshake. The Pico is the client; this script
answers each client message, logs every line the device prints, and checks key
confirmation. See firmware/src/hs_core.h for the protocol.

Usage:
    pip install pyserial cryptography kyber-py
    python host/hs_server.py /dev/ttyACM0 data/raw/run_handshake.txt
The device starts on its own once the port is opened; the script exits when the
device prints its completion banner.
"""
import sys, time, hmac, hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

KEM_BY_EK = {800: ML_KEM_512, 1184: ML_KEM_768, 1568: ML_KEM_1024}
EK_BY_LEVEL = {"L1": 800, "L3": 1184, "L5": 1568}
INFO = b"rp2040 hybrid x25519+mlkem"
DONE = "=== handshake benchmark done ==="


def hkdf(ikm):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(ikm)


class Server:
    def __init__(self):
        self.pending = None   # (K, transcript hash)
        self.ok = self.bad = 0

    def on_c2s(self, payload_hex):
        t0 = time.perf_counter_ns()
        c2s = bytes.fromhex(payload_hex)
        pk_c, ek = c2s[:32], c2s[32:]
        kem = KEM_BY_EK[len(ek)]
        xs = X25519PrivateKey.generate()
        ss_x = xs.exchange(X25519PublicKey.from_public_bytes(pk_c))
        ss_k, ct = kem.encaps(ek)
        pk_s = xs.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        s2c = pk_s + ct
        K = hkdf(ss_k + ss_x)
        H = hashlib.sha256(c2s + s2c).digest()
        self.pending = (K, H)
        host_us = (time.perf_counter_ns() - t0) // 1000
        return f"HS,S2C,{s2c.hex()},{host_us}"

    def on_fin(self, tag_hex):
        if self.pending is None:
            return "HS,BAD"
        K, H = self.pending
        self.pending = None
        good = hmac.compare_digest(hmac.new(K, b"client finished" + H, hashlib.sha256).digest(), bytes.fromhex(tag_hex))
        if good: self.ok += 1
        else: self.bad += 1
        return "HS,OK" if good else "HS,BAD"


def serve(readline, writeline, log):
    srv = Server()
    while True:
        raw = readline()
        if not raw:
            continue
        line = raw.decode(errors="replace").strip()
        if not line:
            continue
        if line.startswith("HS,C2S,"):
            parts = line.split(",", 4)          # HS,C2S,<lvl>,<round>,<hex>
            got = len(parts[4]) // 2 - 32 if len(parts) == 5 else -1
            want = EK_BY_LEVEL.get(parts[2] if len(parts) > 2 else "", 0)
            if got != want:
                msg = f"HOST,error,c2s_length,{parts[2] if len(parts) > 2 else '?'},{got},expected,{want}"
                print("    " + msg + "  (line damaged in transit; the device will report hs_error)")
                log.write(msg + "\n"); log.flush()
                writeline("HS,ERR")
                continue
            writeline(srv.on_c2s(parts[4]))
            log.write(f"HOST,c2s,{parts[2]},{parts[3]},{len(parts[4]) // 2}\n")
        elif line.startswith("HS,FIN,"):
            writeline(srv.on_fin(line[7:]))
        else:
            log.write(line + "\n"); log.flush()
            if not line.startswith("RAW,"):           # samples go to the log only
                print("    " + line)
            if line.startswith(DONE):
                break
    print(f"handshakes confirmed: {srv.ok}, failed: {srv.bad}")
    return srv.bad == 0


def main():
    import serial
    port, out = sys.argv[1], sys.argv[2]
    with serial.Serial(port, 115200, timeout=30) as s, open(out, "w") as log:
        ok = serve(s.readline, lambda l: (s.write((l + "\n").encode()), s.flush()), log)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
