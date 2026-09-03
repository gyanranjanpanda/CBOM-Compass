"""Local TLS endpoint for demoing the live-endpoint scanner.

Serves a self-signed RSA-2048 certificate on 127.0.0.1:8443, which is inside the
sample policy's scan allowlist. Nothing outside that allowlist is probeable.

    python samples/tls_demo_server.py &
    cbom-compass scan --tls 127.0.0.1:8443 --policy samples/vulnerable-app/crypto-policy.yaml
"""

import http.server
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

HOST, PORT = "127.0.0.1", 8443


def make_cert(directory: Path) -> tuple[Path, Path]:
    key, crt = directory / "demo.key", directory / "demo.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "30",
         "-subj", "/CN=payments.test.internal/O=CBOM Compass Demo"],
        check=True, capture_output=True,
    )
    return key, crt


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    try:
        key, crt = make_cert(tmp)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"could not generate a demo certificate (openssl required): {exc}", file=sys.stderr)
        return 1

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    httpd = http.server.HTTPServer((HOST, PORT), http.server.SimpleHTTPRequestHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"demo TLS endpoint on https://{HOST}:{PORT} (self-signed RSA-2048, 30-day cert)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
