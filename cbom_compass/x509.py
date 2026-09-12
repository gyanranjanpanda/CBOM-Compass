"""A small X.509 reader — enough of DER to build a certificate chain.

Written against the stdlib rather than pulling in `cryptography`, for two
reasons. The tool's claim is that it installs and runs anywhere with no heavy
dependencies, and — less obviously — adding a crypto library to our own
dependency list would put RSA and ECDSA into our own CBOM. A post-quantum
readiness tool whose self-scan comes back dirty is a bad look that no amount of
explanation recovers.

This replaces what `tls.py` used to do, which was to search the raw DER for OID
byte strings and guess the key size from the length of the certificate. That
told RSA from ECDSA and very little else; it could not read a subject, so it
could not tell which certificate signed which, so there was no chain.

Scope is deliberately narrow. It reads the fields needed to inventory a
certificate and link it to its issuer. It does **not** verify signatures, check
revocation, or validate a chain — a tool that said "this chain is valid" while
doing none of those things would be worse than one that says nothing.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- object identifiers we care about --------------------------------------
OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "email",
}
PUBLIC_KEY_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10046.2.1": "DH",
    "1.2.840.10045.2.1": "ECDSA",
    "1.3.101.112": "EdDSA",       # Ed25519
    "1.3.101.113": "EdDSA",       # Ed448
    "1.3.101.110": "ECDH",        # X25519
    "1.3.101.111": "ECDH",        # X448
    "2.16.840.1.101.3.4.4": "ML-KEM",
    "2.16.840.1.101.3.4.3.17": "ML-DSA",
}
SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.10": ("RSA", "PSS"),
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"),
    "1.2.840.10040.4.3": ("DSA", "SHA-1"),
    "1.3.101.112": ("EdDSA", "SHA-512"),
}
CURVE_OIDS = {
    "1.2.840.10045.3.1.1": ("secp192r1", 192),
    "1.3.132.0.33": ("secp224r1", 224),
    "1.2.840.10045.3.1.7": ("secp256r1", 256),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
}
EXT_SUBJECT_KEY_ID = "2.5.29.14"
EXT_KEY_USAGE = "2.5.29.15"
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_AUTHORITY_KEY_ID = "2.5.29.35"

PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


class DERError(ValueError):
    """Malformed input. Callers treat this as "not a certificate" and move on."""


# --- the smallest DER reader that does the job ------------------------------
@dataclass
class TLV:
    tag: int
    value: bytes
    raw: bytes                      # tag + length + value, needed for hashing

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)


def read_tlv(data: bytes, offset: int = 0) -> tuple[TLV, int]:
    """Read one tag-length-value triple, returning it and the next offset."""
    start = offset
    if offset >= len(data):
        raise DERError("truncated: no tag")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DERError("multi-byte tags are not supported")
    if offset >= len(data):
        raise DERError("truncated: no length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise DERError("indefinite or oversized length")
        if offset + count > len(data):
            raise DERError("truncated length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    if offset + length > len(data):
        raise DERError("truncated value")
    value = data[offset:offset + length]
    return TLV(tag, value, data[start:offset + length]), offset + length


def children(node: TLV) -> list[TLV]:
    out, offset = [], 0
    while offset < len(node.value):
        child, offset = read_tlv(node.value, offset)
        out.append(child)
    return out


def decode_oid(value: bytes) -> str:
    if not value:
        raise DERError("empty OID")
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(current))
            current = 0
    return ".".join(parts)


def decode_time(node: TLV) -> datetime | None:
    text = node.value.decode("ascii", "replace").strip()
    # UTCTime is YYMMDDHHMMSSZ; GeneralizedTime is YYYYMMDDHHMMSSZ.
    for pattern, century in (("%y%m%d%H%M%SZ", False), ("%Y%m%d%H%M%SZ", True)):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def decode_name(node: TLV) -> str:
    """RDNSequence to a readable string, e.g. `C=IN, O=Acme, CN=Acme Root`."""
    pieces: list[str] = []
    for rdn in children(node):
        for attribute in children(rdn):
            parts = children(attribute)
            if len(parts) != 2:
                continue
            try:
                oid = decode_oid(parts[0].value)
            except DERError:
                continue
            label = OID_NAMES.get(oid, oid)
            text = parts[1].value.decode("utf-8", "replace").strip()
            if text:
                pieces.append(f"{label}={text}")
    return ", ".join(pieces)


@dataclass
class Certificate:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    public_key_algorithm: str = "unknown"
    key_size: int | None = None
    curve: str | None = None
    signature_algorithm: str | None = None
    signature_hash: str | None = None
    subject_key_id: str | None = None
    authority_key_id: str | None = None
    is_ca: bool = False
    path_length: int | None = None
    fingerprint_sha256: str = ""
    extensions: list[str] = field(default_factory=list)

    @property
    def self_signed(self) -> bool:
        """Structurally self-issued. Not a signature check — see the module docstring."""
        if self.subject_key_id and self.authority_key_id:
            return self.subject_key_id == self.authority_key_id
        return bool(self.subject) and self.subject == self.issuer

    @property
    def days_until_expiry(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(timezone.utc)).days

    def to_dict(self) -> dict:
        return {
            "subject": self.subject or None,
            "issuer": self.issuer or None,
            "serial": self.serial or None,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_until_expiry": self.days_until_expiry,
            "self_signed": self.self_signed,
            "is_ca": self.is_ca,
            "path_length": self.path_length,
            "signature_algorithm": self.signature_algorithm,
            "signature_hash": self.signature_hash,
            "subject_key_id": self.subject_key_id,
            "authority_key_id": self.authority_key_id,
            "fingerprint_sha256": self.fingerprint_sha256,
        }


def _public_key(spki: TLV) -> tuple[str, int | None, str | None]:
    """SubjectPublicKeyInfo -> (algorithm, key size in bits, curve)."""
    parts = children(spki)
    if len(parts) != 2:
        return "unknown", None, None
    algorithm_id = children(parts[0])
    if not algorithm_id:
        return "unknown", None, None
    try:
        oid = decode_oid(algorithm_id[0].value)
    except DERError:
        return "unknown", None, None
    algorithm = PUBLIC_KEY_OIDS.get(oid, "unknown")

    curve = None
    if algorithm == "ECDSA" and len(algorithm_id) > 1:
        try:
            curve_oid = decode_oid(algorithm_id[1].value)
        except DERError:
            curve_oid = ""
        named = CURVE_OIDS.get(curve_oid)
        if named:
            return algorithm, named[1], named[0]
        return algorithm, None, None

    # The key itself is a BIT STRING whose first byte counts unused bits.
    bits = parts[1].value[1:] if parts[1].value else b""
    if algorithm in {"RSA", "DSA", "DH"} and bits:
        try:
            sequence, _ = read_tlv(bits)
            modulus = children(sequence)[0].value if sequence.constructed else b""
            # A leading zero byte is the DER sign padding, not key material.
            modulus = modulus.lstrip(b"\x00")
            if modulus:
                return algorithm, len(modulus) * 8, None
        except (DERError, IndexError):
            pass
    if algorithm == "EdDSA":
        return algorithm, 255 if oid == "1.3.101.112" else 448, (
            "ed25519" if oid == "1.3.101.112" else "ed448")
    if algorithm == "ECDH":
        return algorithm, None, "x25519" if oid == "1.3.101.110" else "x448"
    return algorithm, None, curve


def _extensions(node: TLV, certificate: Certificate) -> None:
    for extension in children(node):
        parts = children(extension)
        if not parts:
            continue
        try:
            oid = decode_oid(parts[0].value)
        except DERError:
            continue
        certificate.extensions.append(oid)
        payload = parts[-1].value           # skip the optional critical BOOLEAN
        try:
            if oid == EXT_BASIC_CONSTRAINTS:
                inner, _ = read_tlv(payload)
                fields = children(inner)
                certificate.is_ca = bool(fields and fields[0].tag == 0x01
                                         and fields[0].value not in (b"\x00", b""))
                if len(fields) > 1 and fields[1].tag == 0x02:
                    certificate.path_length = int.from_bytes(fields[1].value, "big")
            elif oid == EXT_SUBJECT_KEY_ID:
                inner, _ = read_tlv(payload)
                certificate.subject_key_id = inner.value.hex()
            elif oid == EXT_AUTHORITY_KEY_ID:
                inner, _ = read_tlv(payload)
                for child in children(inner):
                    if child.tag == 0x80:           # [0] keyIdentifier
                        certificate.authority_key_id = child.value.hex()
                        break
        except (DERError, IndexError, ValueError):
            continue


def parse_der(data: bytes) -> Certificate:
    """Parse a DER certificate. Raises DERError on anything that is not one."""
    root, _ = read_tlv(data)
    if not root.constructed:
        raise DERError("certificate is not a SEQUENCE")
    top = children(root)
    if len(top) < 3:
        raise DERError("certificate has too few fields")
    tbs = top[0]
    fields = children(tbs)
    if not fields:
        raise DERError("empty tbsCertificate")

    index = 0
    certificate = Certificate(
        fingerprint_sha256=hashlib.sha256(root.raw).hexdigest())
    if fields[0].tag == 0xA0:                    # [0] EXPLICIT version
        index = 1
    if index < len(fields) and fields[index].tag == 0x02:
        certificate.serial = fields[index].value.hex()
        index += 1
    if index < len(fields):                       # signature AlgorithmIdentifier
        algorithm_id = children(fields[index])
        if algorithm_id:
            try:
                signature = SIGNATURE_OIDS.get(decode_oid(algorithm_id[0].value))
            except DERError:
                signature = None
            if signature:
                certificate.signature_algorithm, certificate.signature_hash = signature
        index += 1
    if index < len(fields):
        certificate.issuer = decode_name(fields[index])
        index += 1
    if index < len(fields):                       # Validity
        validity = children(fields[index])
        if len(validity) == 2:
            certificate.not_before = decode_time(validity[0])
            certificate.not_after = decode_time(validity[1])
        index += 1
    if index < len(fields):
        certificate.subject = decode_name(fields[index])
        index += 1
    if index < len(fields):
        (certificate.public_key_algorithm, certificate.key_size,
         certificate.curve) = _public_key(fields[index])
        index += 1
    for extra in fields[index:]:
        if extra.tag == 0xA3:                     # [3] EXPLICIT extensions
            inner = children(extra)
            if inner:
                _extensions(inner[0], certificate)
    return certificate


def parse_pem_bundle(data: bytes) -> list[Certificate]:
    """Every certificate in a PEM file — bundles routinely hold a whole chain."""
    found: list[Certificate] = []
    for block in PEM_BLOCK.findall(data):
        try:
            found.append(parse_der(base64.b64decode(
                re.sub(rb"\s+", b"", block), validate=False)))
        except (DERError, ValueError):
            continue
    return found


def parse_any(data: bytes) -> list[Certificate]:
    """PEM bundle if it looks like one, otherwise a single DER certificate."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        return parse_pem_bundle(data)
    try:
        return [parse_der(data)]
    except (DERError, ValueError):
        return []
