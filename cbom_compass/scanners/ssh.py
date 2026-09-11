"""Live SSH endpoint scanner — PRD v1.1 sections 6.1 and 10.

SSH is the second protocol every organisation actually runs, and on internal
infrastructure it is usually the *first*: every jump host, every deploy account,
every git remote. Cataloguing TLS and stopping there leaves that whole surface
uninventoried.

This probe is strictly better-informed than the TLS one next door, and the
reason is a protocol difference rather than better engineering. A TLS handshake
returns the one suite the server picked, so `tls.py` can only ever report a
single answer. SSH opens with SSH_MSG_KEXINIT, in which the server announces
*every* algorithm it is willing to use, in preference order, before anything is
negotiated. Reading that one message yields the complete accepted set — the
enumeration that TLS needs sslyze to approximate.

So the handshake is deliberately abandoned after KEXINIT. We never complete a
key exchange, never authenticate, and never send a credential: the inventory is
already complete at that point, and going further would make this an access
attempt rather than a read.

Two findings here matter more than the rest:

  * `mlkem768x25519-sha256` and `sntrup761x25519-sha512@openssh.com` are hybrid
    key exchanges. Both halves are emitted as separate assets at the same
    location, which is what lets `risk.find_hybrid_partners` pair them and
    discount the classical half instead of reporting a migrated server as
    broken.
  * `ssh-rsa` is an RSA key with a *SHA-1* signature, which is not the same
    finding as `rsa-sha2-256` and must not collapse into it.

Section 10 gate: probing a host outside the policy allowlist is refused, not
warned about.
"""

from __future__ import annotations

import socket
import struct

from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from .base import ScanError, ScanResult, Scanner

SSH_MSG_KEXINIT = 20
BANNER = b"SSH-2.0-CBOMCompass_inventory\r\n"
MAX_PACKET = 64 * 1024

# The ten name-lists in a KEXINIT payload, in wire order (RFC 4253 section 7.1).
NAME_LISTS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)

# --- Key exchange ----------------------------------------------------------
# (algorithm, key size, parameters). A tuple of two entries means a hybrid, and
# both halves are emitted so the risk engine can pair them.
KEX: dict[str, tuple] = {
    "curve25519-sha256": (("ECDH", None, {"curve": "x25519"}),),
    "curve25519-sha256@libssh.org": (("ECDH", None, {"curve": "x25519"}),),
    "ecdh-sha2-nistp256": (("ECDH", 256, {"curve": "secp256r1"}),),
    "ecdh-sha2-nistp384": (("ECDH", 384, {"curve": "secp384r1"}),),
    "ecdh-sha2-nistp521": (("ECDH", 521, {"curve": "secp521r1"}),),
    "diffie-hellman-group1-sha1": (("DH", 1024, {}),),
    "diffie-hellman-group14-sha1": (("DH", 2048, {}),),
    "diffie-hellman-group14-sha256": (("DH", 2048, {}),),
    "diffie-hellman-group15-sha512": (("DH", 3072, {}),),
    "diffie-hellman-group16-sha512": (("DH", 4096, {}),),
    "diffie-hellman-group17-sha512": (("DH", 6144, {}),),
    "diffie-hellman-group18-sha512": (("DH", 8192, {}),),
    "diffie-hellman-group-exchange-sha1": (("DH", None, {"group": "negotiated"}),),
    "diffie-hellman-group-exchange-sha256": (("DH", None, {"group": "negotiated"}),),
    # --- Hybrids. Both halves, deliberately.
    "sntrup761x25519-sha512": (("sntrup761", None, {}),
                               ("ECDH", None, {"curve": "x25519"})),
    "sntrup761x25519-sha512@openssh.com": (("sntrup761", None, {}),
                                           ("ECDH", None, {"curve": "x25519"})),
    "mlkem768x25519-sha256": (("ML-KEM", None, {"parameter_set": "ML-KEM-768"}),
                              ("ECDH", None, {"curve": "x25519"})),
    "mlkem768nistp256-sha256": (("ML-KEM", None, {"parameter_set": "ML-KEM-768"}),
                                ("ECDH", 256, {"curve": "secp256r1"})),
    "mlkem1024nistp384-sha384": (("ML-KEM", None, {"parameter_set": "ML-KEM-1024"}),
                                 ("ECDH", 384, {"curve": "secp384r1"})),
}

# --- Host keys -------------------------------------------------------------
HOST_KEYS: dict[str, tuple[str, int | None, dict]] = {
    # `ssh-rsa` is RSA-with-SHA-1, which is a materially worse finding than
    # rsa-sha2-*. Recording the signature hash is what keeps them apart.
    "ssh-rsa": ("RSA", None, {"signature_hash": "SHA-1"}),
    "rsa-sha2-256": ("RSA", None, {"signature_hash": "SHA-256"}),
    "rsa-sha2-512": ("RSA", None, {"signature_hash": "SHA-512"}),
    "ssh-dss": ("DSA", 1024, {}),
    "ecdsa-sha2-nistp256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "ecdsa-sha2-nistp384": ("ECDSA", 384, {"curve": "secp384r1"}),
    "ecdsa-sha2-nistp521": ("ECDSA", 521, {"curve": "secp521r1"}),
    "ssh-ed25519": ("EdDSA", None, {"curve": "ed25519"}),
    "ssh-ed448": ("EdDSA", None, {"curve": "ed448"}),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", 256,
                                           {"curve": "secp256r1", "security_key": True}),
    "sk-ssh-ed25519@openssh.com": ("EdDSA", None,
                                   {"curve": "ed25519", "security_key": True}),
}

# --- Bulk ciphers ----------------------------------------------------------
CIPHERS: dict[str, tuple[str, int | None, dict]] = {
    "aes128-ctr": ("AES", 128, {"mode": "CTR"}),
    "aes192-ctr": ("AES", 192, {"mode": "CTR"}),
    "aes256-ctr": ("AES", 256, {"mode": "CTR"}),
    "aes128-cbc": ("AES", 128, {"mode": "CBC"}),
    "aes192-cbc": ("AES", 192, {"mode": "CBC"}),
    "aes256-cbc": ("AES", 256, {"mode": "CBC"}),
    "aes128-gcm@openssh.com": ("AES", 128, {"mode": "GCM"}),
    "aes256-gcm@openssh.com": ("AES", 256, {"mode": "GCM"}),
    "chacha20-poly1305@openssh.com": ("ChaCha20", 256, {"mode": "POLY1305"}),
    "3des-cbc": ("3DES", 168, {"mode": "CBC"}),
    "3des-ctr": ("3DES", 168, {"mode": "CTR"}),
    "blowfish-cbc": ("Blowfish", None, {"mode": "CBC"}),
    "arcfour": ("RC4", 128, {}),
    "arcfour128": ("RC4", 128, {}),
    "arcfour256": ("RC4", 256, {}),
    "rijndael-cbc@lysator.liu.se": ("AES", 256, {"mode": "CBC"}),
}

# --- MACs ------------------------------------------------------------------
MACS: dict[str, tuple[str, int | None, dict]] = {
    "hmac-md5": ("HMAC", None, {"hash": "MD5"}),
    "hmac-md5-96": ("HMAC", None, {"hash": "MD5", "truncated": 96}),
    "hmac-sha1": ("HMAC", None, {"hash": "SHA-1"}),
    "hmac-sha1-96": ("HMAC", None, {"hash": "SHA-1", "truncated": 96}),
    "hmac-sha2-256": ("HMAC", None, {"hash": "SHA-256"}),
    "hmac-sha2-512": ("HMAC", None, {"hash": "SHA-512"}),
    "umac-64@openssh.com": ("UMAC", 64, {}),
    "umac-128@openssh.com": ("UMAC", 128, {}),
}


def _declare_hybrid(parameters: dict, halves: tuple, algorithm: str) -> dict:
    """Name the partner explicitly when the algorithm identifier says so.

    `mlkem768x25519-sha256` states the pairing in its own name, so there is no
    need to infer it. Recording it means `risk.find_hybrid_partners` does not
    have to fall back on co-location — which would be wrong here, because a
    server offers hybrid and non-hybrid key exchanges side by side, and a bare
    `curve25519-sha256` in the same list is genuinely exposed.

    It also keeps the two X25519 findings apart as separate assets, which they
    are: one is protected by an ML-KEM half and one is not.
    """
    if len(halves) < 2:
        return parameters
    partner = next((a for a, _, _ in halves if a != algorithm), None)
    return {**parameters, "hybrid_with": partner} if partner else parameters


def _strip_etm(name: str) -> str:
    """`hmac-sha2-256-etm@openssh.com` is the encrypt-then-MAC ordering of the
    same primitive. The ordering is a protocol property, not a different MAC."""
    if name.endswith("-etm@openssh.com"):
        return name[: -len("-etm@openssh.com")]
    return name


def parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    """Decode a KEXINIT payload into its ten name-lists.

    Layout: byte msg_type, byte[16] cookie, then ten name-lists each encoded as
    a uint32 length followed by that many bytes of comma-separated ASCII.
    """
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError(f"expected SSH_MSG_KEXINIT, got message type {payload[:1].hex()}")
    offset = 17                                   # message type + 16-byte cookie
    lists: dict[str, list[str]] = {}
    for field in NAME_LISTS:
        if offset + 4 > len(payload):
            break
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        if offset + length > len(payload):
            break
        raw = payload[offset:offset + length].decode("ascii", errors="replace")
        offset += length
        lists[field] = [item for item in raw.split(",") if item]
    return lists


class SSHScanner(Scanner):
    source_type = SourceType.ENDPOINT
    name = "ssh"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        cleaned = target[len("ssh://"):] if target.startswith("ssh://") else target
        host, _, port_s = cleaned.partition(":")
        try:
            port = int(port_s or 22)
        except ValueError:
            result.errors.append(ScanError("endpoint", target, f"bad port '{port_s}'"))
            return result

        if not self.policy.target_allowed(host):
            result.errors.append(ScanError(
                "endpoint", target,
                f"refused: {host} is not in the scan allowlist. Add it to "
                f"crypto-policy.yaml under scanning.allowlist with a recorded "
                f"authorization attestation before probing.",
            ))
            return result

        try:
            banner, lists = self._probe(host, port)
        except (socket.timeout, socket.gaierror, ConnectionError, OSError) as exc:
            result.errors.append(ScanError("endpoint", target, f"SSH probe failed: {exc}"))
            return result
        except ValueError as exc:
            result.errors.append(ScanError("endpoint", target, str(exc)))
            return result

        return self._assets(banner, lists, f"{host}:{port}")

    # ------------------------------------------------------------------ wire
    def _probe(self, host: str, port: int) -> tuple[str, dict[str, list[str]]]:
        """Banner exchange, then read exactly one KEXINIT and hang up."""
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)
            banner = self._read_banner(sock)
            sock.sendall(BANNER)
            payload = self._read_packet(sock)
        return banner, parse_kexinit(payload)

    @staticmethod
    def _read_banner(sock: socket.socket) -> str:
        """Read the identification string.

        A server may emit arbitrary lines before its SSH- line (RFC 4253 allows
        it, and login banners use it), so lines are skipped until one starts
        with `SSH-`, with a cap so a chatty or hostile host cannot stream for
        ever.
        """
        buffer = b""
        for _ in range(64):
            while b"\r\n" not in buffer and b"\n" not in buffer:
                chunk = sock.recv(512)
                if not chunk:
                    raise ConnectionError("connection closed before the SSH banner")
                buffer += chunk
                if len(buffer) > MAX_PACKET:
                    raise ValueError("no SSH identification string in the first 64KB")
            line, _, buffer = buffer.partition(b"\n")
            text = line.rstrip(b"\r").decode("ascii", errors="replace")
            if text.startswith("SSH-"):
                return text
        raise ValueError("no SSH identification string found")

    @staticmethod
    def _read_packet(sock: socket.socket) -> bytes:
        """Read one unencrypted binary packet and return its payload.

        Before key exchange completes there is no MAC and no encryption, so the
        framing is plain: uint32 packet_length, byte padding_length, payload,
        padding.
        """
        header = b""
        while len(header) < 5:
            chunk = sock.recv(5 - len(header))
            if not chunk:
                raise ConnectionError("connection closed before KEXINIT")
            header += chunk
        (packet_length,) = struct.unpack(">I", header[:4])
        padding_length = header[4]
        if not 0 < packet_length <= MAX_PACKET:
            raise ValueError(f"implausible SSH packet length {packet_length}")
        remaining = packet_length - 1
        body = b""
        while len(body) < remaining:
            chunk = sock.recv(remaining - len(body))
            if not chunk:
                raise ConnectionError("connection closed mid-packet")
            body += chunk
        return body[: len(body) - padding_length]

    # ---------------------------------------------------------------- assets
    def _assets(self, banner: str, lists: dict[str, list[str]], target: str) -> ScanResult:
        result = ScanResult()
        software = banner.split("-", 2)[2] if banner.count("-") >= 2 else banner

        protocol = Asset(
            algorithm="SSH-2.0", asset_type=AssetType.PROTOCOL,
            location_class="negotiated",
            parameters={"software_version": software},
            evidence=[Evidence(
                self.source_type, "ssh-kexinit", target, Confidence.HIGH,
                f"{banner} offering {len(lists.get('kex_algorithms', []))} key exchange, "
                f"{len(lists.get('server_host_key_algorithms', []))} host key and "
                f"{len(lists.get('encryption_algorithms_server_to_client', []))} cipher "
                f"algorithms",
                {"offered": lists},
            )],
        )
        result.assets.append(protocol)

        seen: set[tuple] = set()

        def emit(algorithm, key_size, parameters, offered_as, category):
            identity = (algorithm, key_size, tuple(sorted(parameters.items())))
            if identity in seen:
                return
            seen.add(identity)
            asset = Asset(
                algorithm=algorithm, key_size=key_size, parameters=dict(parameters),
                location_class="negotiated",
                evidence=[Evidence(
                    self.source_type, "ssh-kexinit",
                    f"{target}/{category}/{offered_as}", Confidence.HIGH,
                    f"server offers {offered_as} ({category})",
                    {"offered_as": offered_as, "category": category},
                )],
            )
            result.assets.append(asset)
            result.relationships.append(
                Relationship(asset.id, protocol.id, "negotiated-by"))

        for name in lists.get("kex_algorithms", []):
            halves = KEX.get(name, ())
            for algorithm, key_size, parameters in halves:
                emit(algorithm, key_size,
                     _declare_hybrid(parameters, halves, algorithm), name, "kex")
        for name in lists.get("server_host_key_algorithms", []):
            # Certificate host-key variants carry the same key algorithm.
            base = name.replace("-cert-v01@openssh.com", "")
            mapped = HOST_KEYS.get(base)
            if mapped:
                algorithm, key_size, parameters = mapped
                if base != name:
                    parameters = {**parameters, "certificate": True}
                emit(algorithm, key_size, parameters, name, "host-key")
        for field, table, category in (
            ("encryption_algorithms_server_to_client", CIPHERS, "cipher"),
            ("mac_algorithms_server_to_client", MACS, "mac"),
        ):
            for name in lists.get(field, []):
                mapped = table.get(_strip_etm(name))
                if mapped:
                    algorithm, key_size, parameters = mapped
                    emit(algorithm, key_size, parameters, name, category)
        return result
