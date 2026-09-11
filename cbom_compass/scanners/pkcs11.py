"""PKCS#11 hardware module reader — PRD v1.1 section 6.1, "hardware modules".

The problem statement names hardware modules alongside algorithms, keys and
certificates, and an HSM is the one place where "we will just bump the library"
is not an available answer: the key cannot leave, so migration waits on vendor
firmware that supports ML-KEM or ML-DSA. That makes an HSM-resident RSA key a
*worse* migration problem than the same algorithm in application code, not a
better one, which is why these findings land with `location_class`
``hardware-module`` and pick up the long migration estimate in
`knowledge/mosca.py`.

PKCS#11 is the right interface for this. It is the one API that SoftHSM, Luna,
nCipher, Utimaco, AWS CloudHSM, YubiHSM and tpm2-pkcs11 all speak, so a single
connector covers the whole category rather than one vendor.

Section 10 constrains what may be read. `READABLE_ATTRIBUTES` is the complete
set of attributes this module ever asks for, kept as data so the constraint is
testable rather than a comment nobody checks. It holds no attribute that can
return key material: CKA_VALUE, CKA_PRIVATE_EXPONENT, CKA_PRIME_1 and friends
are absent by construction, and `assert_no_key_material` fails loudly if anyone
adds one. Reading a public modulus is deliberately allowed — it is public, and
CKA_MODULUS_BITS is how the key size is known at all.
"""

from __future__ import annotations

import os
import re
from typing import Any

# The complete attribute set this connector reads. Anything not named here is
# never requested. Compared against DISALLOWED_ATTRIBUTES at import time.
READABLE_ATTRIBUTES = {
    "CKA_CLASS", "CKA_KEY_TYPE", "CKA_LABEL", "CKA_ID",
    "CKA_MODULUS_BITS", "CKA_VALUE_LEN", "CKA_EC_PARAMS",
    "CKA_SENSITIVE", "CKA_EXTRACTABLE", "CKA_ALWAYS_SENSITIVE",
    "CKA_NEVER_EXTRACTABLE", "CKA_TOKEN", "CKA_PRIVATE",
    "CKA_SIGN", "CKA_VERIFY", "CKA_ENCRYPT", "CKA_DECRYPT",
    "CKA_WRAP", "CKA_UNWRAP", "CKA_DERIVE",
}

# Attributes that return, or let you reconstruct, secret key material. Reading
# any of these would turn an inventory tool into an exfiltration tool.
DISALLOWED_ATTRIBUTES = {
    "CKA_VALUE", "CKA_PRIVATE_EXPONENT", "CKA_PRIME_1", "CKA_PRIME_2",
    "CKA_EXPONENT_1", "CKA_EXPONENT_2", "CKA_COEFFICIENT", "CKA_BASE",
}


def assert_no_key_material() -> None:
    """Fail loudly if the readable set ever grows a key-material attribute."""
    overlap = READABLE_ATTRIBUTES & DISALLOWED_ATTRIBUTES
    if overlap:
        raise AssertionError(
            f"PKCS#11 reader would request key material: {sorted(overlap)}")


assert_no_key_material()

# CKK_* key type -> (algorithm, parameters). Key size comes from
# CKA_MODULUS_BITS or CKA_VALUE_LEN, and the curve from CKA_EC_PARAMS.
KEY_TYPES: dict[str, tuple[str, dict[str, Any]]] = {
    "RSA": ("RSA", {}),
    "DSA": ("DSA", {}),
    "DH": ("DH", {}),
    "X9_42_DH": ("DH", {}),
    "EC": ("ECDSA", {}),
    "ECDSA": ("ECDSA", {}),
    "EC_EDWARDS": ("EdDSA", {}),
    "EC_MONTGOMERY": ("ECDH", {}),
    "AES": ("AES", {}),
    "DES": ("DES", {}),
    "DES2": ("3DES", {"keying_option": 2}),
    "DES3": ("3DES", {}),
    "GENERIC_SECRET": ("HMAC", {}),
    "SHA_1_HMAC": ("HMAC", {"hash": "SHA-1"}),
    "SHA256_HMAC": ("HMAC", {"hash": "SHA-256"}),
    "SHA384_HMAC": ("HMAC", {"hash": "SHA-384"}),
    "SHA512_HMAC": ("HMAC", {"hash": "SHA-512"}),
    "CHACHA20": ("ChaCha20", {}),
    "BLOWFISH": ("Blowfish", {}),
    "RC4": ("RC4", {}),
    # PKCS#11 3.2 registered the post-quantum families. A token that already
    # holds these is partly migrated, and reporting it as such is what stops
    # the tool telling someone to migrate something they already migrated.
    "ML_KEM": ("ML-KEM", {}),
    "ML_DSA": ("ML-DSA", {}),
    "SLH_DSA": ("SLH-DSA", {}),
    "FN_DSA": ("FN-DSA", {}),
    "HSS": ("LMS", {}),
    "XMSS": ("XMSS", {}),
    "XMSSMT": ("XMSS", {"variant": "XMSS^MT"}),
}

# DER-encoded named-curve OIDs as they appear in CKA_EC_PARAMS.
EC_PARAM_CURVES: dict[bytes, str] = {
    bytes.fromhex("06082a8648ce3d030101"): "secp192r1",
    bytes.fromhex("06052b81040021"): "secp224r1",
    bytes.fromhex("06082a8648ce3d030107"): "secp256r1",
    bytes.fromhex("06052b8104000a"): "secp256k1",
    bytes.fromhex("06052b81040022"): "secp384r1",
    bytes.fromhex("06052b81040023"): "secp521r1",
    bytes.fromhex("06032b6570"): "ed25519",
    bytes.fromhex("06032b6571"): "ed448",
    bytes.fromhex("06032b656e"): "x25519",
    bytes.fromhex("06032b656f"): "x448",
}
# Some tokens hand back a PrintableString curve name instead of an OID.
EC_PARAM_NAMES = {
    "prime256v1": "secp256r1", "secp256r1": "secp256r1", "p-256": "secp256r1",
    "secp384r1": "secp384r1", "p-384": "secp384r1",
    "secp521r1": "secp521r1", "p-521": "secp521r1",
    "secp256k1": "secp256k1", "secp224r1": "secp224r1",
    "edwards25519": "ed25519", "curve25519": "x25519",
}

OBJECT_CLASSES = ("PRIVATE_KEY", "PUBLIC_KEY", "SECRET_KEY", "CERTIFICATE")


def curve_from_ec_params(raw: Any) -> str | None:
    """Decode CKA_EC_PARAMS into a curve name.

    Tokens are inconsistent here: most return the DER OID, some return a
    PrintableString, and a few return the OID wrapped in extra bytes. Try the
    exact OID, then a containment check, then the string spellings.
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        return EC_PARAM_NAMES.get(raw.strip().lower())
    if isinstance(raw, (bytes, bytearray)):
        blob = bytes(raw)
        if blob in EC_PARAM_CURVES:
            return EC_PARAM_CURVES[blob]
        for oid, name in EC_PARAM_CURVES.items():
            if oid in blob:
                return name
        # PrintableString form: 13 <len> <ascii>
        text = blob.decode("ascii", errors="ignore").strip("\x00 ")
        cleaned = re.sub(r"[^A-Za-z0-9\-]", "", text).lower()
        if cleaned in EC_PARAM_NAMES:
            return EC_PARAM_NAMES[cleaned]
    return None


def normalise_key_type(raw: Any) -> str | None:
    """`CKK_RSA`, `KeyType.RSA`, `pkcs11.KeyType.EC`, or a bare `RSA`."""
    if raw is None:
        return None
    text = str(raw)
    text = text.rsplit(".", 1)[-1]
    text = text.removeprefix("CKK_").upper()
    return text or None


def resolve_pin(pin_env: str | None) -> str | None:
    """Read a user PIN from the named environment variable.

    A PIN is never accepted inline. Putting it in the target string would put it
    in the scan's `target_scope`, which is written to the store, the CBOM and
    the audit log — a credential leak with a long half-life.

    Public objects are readable without a PIN, so the connector still produces a
    useful inventory unauthenticated; a PIN only adds private-key objects.
    """
    if not pin_env:
        return None
    value = os.environ.get(pin_env)
    return value or None


def key_size_for(algorithm: str, modulus_bits: Any, value_len: Any) -> int | None:
    """CKA_MODULUS_BITS is already in bits; CKA_VALUE_LEN is in bytes."""
    if modulus_bits:
        try:
            return int(modulus_bits)
        except (TypeError, ValueError):
            return None
    if value_len:
        try:
            size = int(value_len) * 8
        except (TypeError, ValueError):
            return None
        # 3DES is stored as 24 bytes but carries 112 bits of strength; report
        # the stored size and let the knowledge base apply the strength rule.
        return size
    return None
