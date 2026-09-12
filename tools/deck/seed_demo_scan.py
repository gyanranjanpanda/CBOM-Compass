"""Seed a demo store with a scan that exercises every source type."""
from __future__ import annotations

import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
from cbom_compass.engine import run_scan
from cbom_compass.policy import Policy
from cbom_compass.store import Store

APP = "samples/vulnerable-app"
POLICY = f"{APP}/crypto-policy.yaml"
DB = sys.argv[1]

# --- a loopback SSH responder, so the live-SSH source type is real ----------
KEX = ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com",
       "curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"]
HOST_KEYS = ["rsa-sha2-512", "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
CIPHERS = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com",
           "aes128-ctr", "3des-cbc"]
MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]


def kexinit():
    def nl(items):
        raw = ",".join(items).encode()
        return struct.pack(">I", len(raw)) + raw
    p = bytes([20]) + b"\x00" * 16
    p += nl(KEX) + nl(HOST_KEYS) + nl(CIPHERS) + nl(CIPHERS) + nl(MACS) + nl(MACS)
    p += nl(["none"]) * 2 + nl([]) * 2 + b"\x00" + b"\x00" * 4
    return p


def frame(payload):
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">I", len(payload) + pad + 1) + bytes([pad]) + payload + b"\x00" * pad


listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(4)
ssh_port = listener.getsockname()[1]


def serve():
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.9p1 Ubuntu-3\r\n")
                conn.recv(512)
                conn.sendall(frame(kexinit()))
            except OSError:
                pass


threading.Thread(target=serve, daemon=True).start()

# --- a real TLS endpoint ----------------------------------------------------
tls = subprocess.Popen([sys.executable, "samples/tls_demo_server.py"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2.5)

policy = Policy.load(POLICY)
store = Store(DB)

# Scan 1: code only. Gives the drift view something real to diff against.
store.save(run_scan({"source": [APP], "dependencies": [APP]}, policy,
                    label="payments-platform (code only)").to_dict())

# Scan 2: the whole estate.
targets = {
    "source": [APP],
    "config": [APP],
    "dependencies": [APP],
    "binary": [APP],
    "container": ["samples/vulnerable-image"],
    "tls": ["127.0.0.1:8443"],
    "ssh": [f"127.0.0.1:{ssh_port}"],
    "cloud": ["file://samples/keystore-export.json", "file://samples/hsm-export.json"],
}
report = run_scan(targets, policy, label="payments-platform (full estate)")
store.save(report.to_dict())

k = report.kpis()
print(f"sources covered : {', '.join(k['sources_covered'])}")
print(f"assets          : {k['total_assets']}  (raw {k['raw_findings']}, "
      f"merged {k['collapsed_by_dedup']})")
print(f"by status       : {k['by_status']}")
print(f"HNDL            : {k['hndl_flagged']}")
print(f"heat map        : {report.heat_map()}")
print(f"errors          : {[ (e.source_type, e.message[:70]) for e in report.errors ]}")

tls.terminate()
listener.close()
