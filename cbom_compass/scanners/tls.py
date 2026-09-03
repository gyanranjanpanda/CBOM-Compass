"""Live endpoint scanner — PRD v1.1 sections 6.1 and 10.

Ground truth on what is actually negotiated, not what is configured. Uses the
stdlib `ssl` module, so it needs no external tooling.

KNOWN LIMITATION: this records the *negotiated* protocol, cipher suite and leaf
certificate — one handshake, one answer. It does not enumerate every suite the
server would accept, and under TLS 1.3 the suite name carries no key-exchange
identifier, so the negotiated group is not captured. Full suite enumeration
needs sslyze driven as a library; that is Phase 2 and is deliberately not
stubbed here.

Section 10 gate: probing a host outside the policy allowlist is **refused**, not
warned about. Without that, this module is simply a network scanner.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from .base import ScanError, ScanResult, Scanner

CIPHER_ALGORITHMS = {
    "AES": "AES", "CHACHA20": "ChaCha20", "3DES": "3DES", "DES": "DES", "RC4": "RC4",
}
KX_ALGORITHMS = {"ECDHE": "ECDH", "DHE": "DH", "ECDH": "ECDH", "DH": "DH", "RSA": "RSA"}
AUTH_ALGORITHMS = {"ECDSA": "ECDSA", "RSA": "RSA", "DSS": "DSA", "ED25519": "EdDSA"}


class TLSScanner(Scanner):
    source_type = SourceType.ENDPOINT
    name = "tls"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)

        if not self.policy.target_allowed(host):
            result.errors.append(ScanError(
                "endpoint", target,
                f"refused: {host} is not in the scan allowlist. Add it to "
                f"crypto-policy.yaml under scanning.allowlist with a recorded "
                f"authorization attestation before probing.",
            ))
            return result

        try:
            result.extend(self._probe(host, port, target))
        except (socket.timeout, socket.gaierror, ConnectionError, ssl.SSLError) as exc:
            result.errors.append(ScanError("endpoint", target, f"handshake failed: {exc}"))
        except Exception as exc:
            result.errors.append(ScanError("endpoint", target, str(exc)))

        return result

    def _probe(self, host: str, port: int, target: str) -> ScanResult:
        result = ScanResult()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or "unknown"
                cipher_name, cipher_version, cipher_bits = tls.cipher() or ("", "", 0)
                der = tls.getpeercert(binary_form=True)
                cert = tls.getpeercert()

        protocol_asset = Asset(
            algorithm=version, asset_type=AssetType.PROTOCOL, location_class="negotiated",
            parameters={"cipher_suite": cipher_name},
            evidence=[Evidence(self.source_type, "tls-handshake", target, Confidence.HIGH,
                               f"negotiated {version} with {cipher_name}")],
        )
        result.assets.append(protocol_asset)

        upper = cipher_name.upper()
        for token, algorithm in CIPHER_ALGORITHMS.items():
            if token in upper:
                key_size = cipher_bits if algorithm in {"AES", "ChaCha20"} else None
                mode = next((m for m in ("GCM", "CBC", "CCM", "POLY1305") if m in upper), None)
                result.assets.append(Asset(
                    algorithm=algorithm, key_size=key_size,
                    parameters={"mode": mode} if mode else {},
                    location_class="negotiated",
                    evidence=[Evidence(self.source_type, "tls-handshake", target,
                                       Confidence.HIGH,
                                       f"bulk cipher from suite {cipher_name}")],
                ))
                result.relationships.append(
                    Relationship(result.assets[-1].id, protocol_asset.id, "negotiated-by"))
                break
        for token, algorithm in KX_ALGORITHMS.items():
            if upper.startswith("TLS_" + token) or f"_{token}_" in upper or upper.startswith(token):
                result.assets.append(Asset(
                    algorithm=algorithm, location_class="negotiated",
                    evidence=[Evidence(self.source_type, "tls-handshake", target,
                                       Confidence.HIGH,
                                       f"key exchange from suite {cipher_name}")],
                ))
                result.relationships.append(
                    Relationship(result.assets[-1].id, protocol_asset.id, "negotiated-by"))
                break

        if der or cert:
            result.extend(self._certificate(cert, der, target, protocol_asset))
        return result

    def _certificate(self, cert: dict | None, der: bytes | None,
                     target: str, protocol_asset: Asset) -> ScanResult:
        """Certificate as a first-class asset with expiry — PRD section 9.

        A cert expiring in 30 days is an operational emergency independent of
        Q-Day, so expiry is tracked alongside quantum status.
        """
        result = ScanResult()
        import hashlib

        subject = issuer = not_after = not_before = None
        if cert:
            subject = ", ".join(f"{k}={v}" for rdn in cert.get("subject", ()) for k, v in rdn)
            issuer = ", ".join(f"{k}={v}" for rdn in cert.get("issuer", ()) for k, v in rdn)
            not_after, not_before = cert.get("notAfter"), cert.get("notBefore")

        days_left = None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                pass

        # Public key algorithm from the DER SPKI OID.
        algorithm, key_size, curve = "unknown", None, None
        if der:
            if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der:      # rsaEncryption
                algorithm = "RSA"
                for candidate, marker in ((4096, b"\x02\x82\x02\x01\x00"), (2048, b"\x02\x82\x01\x01\x00")):
                    if marker in der:
                        key_size = candidate
                        break
                else:
                    key_size = 1024 if len(der) < 700 else 2048
            elif b"\x2a\x86\x48\xce\x3d\x02\x01" in der:            # id-ecPublicKey
                algorithm = "ECDSA"
                if b"\x2a\x86\x48\xce\x3d\x03\x01\x07" in der:
                    curve, key_size = "secp256r1", 256
                elif b"\x2b\x81\x04\x00\x22" in der:
                    curve, key_size = "secp384r1", 384

        asset = Asset(
            algorithm=algorithm, asset_type=AssetType.CERTIFICATE, key_size=key_size,
            parameters={"curve": curve} if curve else {},
            location_class="negotiated",
            certificate={
                "subject": subject, "issuer": issuer,
                "not_before": not_before, "not_after": not_after,
                "days_until_expiry": days_left,
                "self_signed": bool(subject and subject == issuer),
                "fingerprint_sha256": hashlib.sha256(der).hexdigest() if der else None,
            },
            evidence=[Evidence(
                self.source_type, "tls-handshake", target, Confidence.HIGH,
                f"leaf certificate {algorithm}{f'-{key_size}' if key_size else ''}"
                + (f", expires in {days_left}d" if days_left is not None else ""),
                {"days_until_expiry": days_left},
            )],
        )
        result.assets.append(asset)
        result.relationships.append(Relationship(asset.id, protocol_asset.id, "negotiated-by"))
        return result

