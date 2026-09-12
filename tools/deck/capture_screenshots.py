"""Capture dashboard screenshots for the deck."""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

from playwright.sync_api import sync_playwright

DB, OUT = sys.argv[1], Path(sys.argv[2])
POLICY = "samples/vulnerable-app/crypto-policy.yaml"
OUT.mkdir(parents=True, exist_ok=True)

with closing(socket.socket()) as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

proc = subprocess.Popen(
    [sys.executable, "-m", "cbom_compass.cli", "--db", DB, "serve",
     "--policy", POLICY, "--port", str(port)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
url = f"http://127.0.0.1:{port}"
for _ in range(80):
    try:
        with closing(socket.create_connection(("127.0.0.1", port), timeout=0.3)):
            break
    except OSError:
        time.sleep(0.25)

try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1000},
                                device_scale_factor=2)
        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(2000)
        for view in ("overview", "inventory", "heat", "graph", "recs"):
            page.click(f'nav button[data-v="{view}"]')
            page.wait_for_timeout(1400)
            page.screenshot(path=str(OUT / f"{view}.png"))
            print("captured", view)
        browser.close()
finally:
    proc.terminate()
    proc.wait(timeout=10)
