"""Algorithm risk knowledge base — PRD v1.1 sections 4 and 6.2.

The important thing in this file is what it does *not* do. It does not classify
AES-128 or SHA-256 as "weakened". Grover needs ~2^64 sequential quantum
operations and parallelises poorly (m machines buy only sqrt(m)); the relevant
attack on hash collision resistance is Brassard-Hoyer-Tapp, a cube-root speedup
that is not considered practically better than the classical birthday bound once
quantum memory costs are counted. NIST defines its own PQC security-strength
categories *using* AES-128 and SHA-256 as reference points.

Classifying them as weakened would flood the "act now" bucket with every hash
call in the codebase and bury the RSA findings that actually matter. Where
AES-256/SHA-384 is required it surfaces as a CNSA 2.0 policy flag instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import QuantumStatus

# Algorithms whose underlying hard problem Shor solves outright.
SHOR_BROKEN_FAMILIES = {
    "RSA", "DSA", "DH", "ECDH", "ECDSA", "EDDSA", "ELGAMAL", "ECIES", "DHE", "ECDHE",
}

# Canonical names, keyed by the many spellings scanners actually encounter.
# Normalising here is what the CycloneDX 1.7 Cryptography Registry exists to do;
# this table is our local stand-in until we pin the registry as a data dependency.
ALIASES = {
    "rsaencryption": "RSA", "rsassa-pss": "RSA", "rsa-pss": "RSA", "rsa": "RSA",
    "sha1withrsa": "RSA", "sha256withrsa": "RSA", "rsa_pkcs1": "RSA",
    "ecdsa": "ECDSA", "ecdsa-with-sha256": "ECDSA", "prime256v1": "ECDSA",
    "ed25519": "EdDSA", "ed448": "EdDSA", "eddsa": "EdDSA",
    "ecdh": "ECDH", "ecdhe": "ECDH", "x25519": "ECDH", "x448": "ECDH",
    "dh": "DH", "dhe": "DH", "diffie-hellman": "DH", "dsa": "DSA",
    "aes": "AES", "rijndael": "AES", "aeswrap": "AES", "aesgcm": "AES",
    "pbkdf2withhmacsha": "PBKDF2", "pbkdf2withhmacsha1": "PBKDF2",
    "pbkdf2withhmacsha256": "PBKDF2", "pbkdf2withhmacsha512": "PBKDF2",
    "hmacsha1": "HMAC", "hmacsha256": "HMAC", "hmacsha384": "HMAC", "hmacsha512": "HMAC",
    "3des": "3DES", "des-ede3": "3DES", "tripledes": "3DES", "des3": "3DES",
    # JCA spells Triple-DES "DESede"; Node spells it "des-ede3-cbc".
    "desede": "3DES", "des-ede": "3DES", "desede3": "3DES",
    # JCA names the EC keypair algorithm just "EC".
    "ec": "ECDSA", "ecc": "ECDSA",
    "des": "DES", "rc4": "RC4", "arcfour": "RC4", "blowfish": "Blowfish", "rc2": "RC2",
    "chacha20": "ChaCha20",
    "md5": "MD5", "md4": "MD4", "sha1": "SHA-1", "sha-1": "SHA-1",
    "sha256": "SHA-256", "sha-256": "SHA-256", "sha384": "SHA-384", "sha-384": "SHA-384",
    "sha512": "SHA-512", "sha-512": "SHA-512", "sha224": "SHA-224",
    "sha3-256": "SHA3-256", "sha3-512": "SHA3-512", "blake2b": "BLAKE2b",
    "ml-kem": "ML-KEM", "kyber": "ML-KEM", "mlkem": "ML-KEM",
    "ml-dsa": "ML-DSA", "dilithium": "ML-DSA", "mldsa": "ML-DSA",
    "slh-dsa": "SLH-DSA", "sphincs+": "SLH-DSA", "sphincs": "SLH-DSA",
    "fn-dsa": "FN-DSA", "falcon": "FN-DSA", "hqc": "HQC",
    "lms": "LMS", "xmss": "XMSS",
    # JOSE/JWT algorithm identifiers
    "rs256": "RSA", "rs384": "RSA", "rs512": "RSA",
    "ps256": "RSA", "ps384": "RSA", "ps512": "RSA",
    "es256": "ECDSA", "es384": "ECDSA", "es512": "ECDSA",
    "hs256": "HMAC", "hs384": "HMAC", "hs512": "HMAC",
    "eddsa-jose": "EdDSA",
    "pbkdf2": "PBKDF2", "bcrypt": "bcrypt", "scrypt": "scrypt", "argon2": "Argon2",
    "hmac": "HMAC",
}

PRIMITIVE = {
    "RSA": "pke", "DSA": "signature", "ECDSA": "signature", "EdDSA": "signature",
    "DH": "key-agree", "ECDH": "key-agree",
    "AES": "block-cipher", "3DES": "block-cipher", "DES": "block-cipher",
    "Blowfish": "block-cipher", "RC2": "block-cipher",
    "RC4": "stream-cipher", "ChaCha20": "stream-cipher",
    "MD5": "hash", "MD4": "hash", "SHA-1": "hash", "SHA-224": "hash", "SHA-256": "hash",
    "SHA-384": "hash", "SHA-512": "hash", "SHA3-256": "hash", "SHA3-512": "hash",
    "BLAKE2b": "hash",
    "ML-KEM": "kem", "HQC": "kem",
    "ML-DSA": "signature", "SLH-DSA": "signature", "FN-DSA": "signature",
    "LMS": "signature", "XMSS": "signature",
    "PBKDF2": "kdf", "bcrypt": "kdf", "scrypt": "kdf", "Argon2": "kdf", "HMAC": "mac",
}

# PQC algorithms — quantum-resistant by construction.
PQC = {"ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC", "LMS", "XMSS"}


@dataclass
class Classification:
    algorithm: str
    primitive: str | None
    quantum_status: QuantumStatus
    rationale: str
    nist_quantum_security_level: int | None
    regulatory_flags: list[str]
    advisories: list[str]


def normalise(name: str) -> str:
    """Map a scanner's raw spelling onto a canonical algorithm name."""
    if not name:
        return "unknown"
    key = name.strip().lower().replace("_", "-")
    if key in ALIASES:
        return ALIASES[key]
    # Longest prefix wins, so "des-ede3-cbc" resolves to 3DES rather than
    # matching the shorter "des" and being reported as single DES.
    parts = key.replace("/", "-").split("-")
    for length in range(len(parts), 0, -1):
        candidate = "-".join(parts[:length])
        if candidate in ALIASES:
            return ALIASES[candidate]
    return name.strip().upper() if len(name) <= 8 else name.strip()


def _aes_level(key_size: int | None) -> int:
    return {128: 1, 192: 3, 256: 5}.get(key_size or 128, 1)


def _sha_level(name: str) -> int:
    return {"SHA-256": 2, "SHA3-256": 2, "SHA-384": 4, "SHA-512": 5, "SHA3-512": 5}.get(name, 2)


def classify(algorithm: str, key_size: int | None = None,
             parameters: dict | None = None) -> Classification:
    """Classify one algorithm usage. Returns status, rationale, and flag sets."""
    parameters = parameters or {}
    algo = normalise(algorithm)
    primitive = PRIMITIVE.get(algo)
    reg: list[str] = []
    adv: list[str] = []

    mode = str(parameters.get("mode", "")).upper()
    if mode == "ECB":
        adv.append("insecure_mode_ecb")
    if parameters.get("padding") in {"PKCS1v15", "pkcs1"}:
        adv.append("rsa_pkcs1v15_padding")

    # --- Protocol versions -------------------------------------------------
    proto = algo.upper().replace("V", "V").replace(" ", "")
    if proto.startswith(("TLSV", "SSLV", "DTLSV")):
        version = proto.replace("TLSV", "").replace("SSLV", "").replace("DTLSV", "")
        if proto.startswith("SSLV") or version in {"1.0", "1.1", "1"}:
            return Classification(
                algo, "protocol", QuantumStatus.DEPRECATED_INSUFFICIENT,
                f"{algorithm} is deprecated on classical grounds (RFC 8996 for TLS 1.0/1.1; "
                f"SSL 3.0 is broken by POODLE). Not a quantum issue.",
                0, ["cnsa2_noncompliant"], adv,
            )
        return Classification(
            algo, "protocol", QuantumStatus.ADEQUATE,
            f"{algorithm} is current. Its quantum exposure lives in the key exchange and "
            f"certificate it negotiates, which are inventoried as separate assets.",
            3, [] if version == "1.3" else ["cnsa2_noncompliant"], adv,
        )

    # --- Shor-broken public-key cryptography -------------------------------
    if algo.upper() in SHOR_BROKEN_FAMILIES or algo in {"RSA", "DSA", "DH", "ECDH", "ECDSA", "EdDSA"}:
        reg.append("nist8547_disallowed_2035")
        reg.append("cnsa2_noncompliant")
        curve = str(parameters.get("curve", "")).lower()
        weak = False
        if algo in {"RSA", "DSA", "DH"}:
            if key_size and key_size < 2048:
                weak = True
            elif key_size and key_size < 3072:
                reg.append("nist8547_deprecated_2030")
            elif key_size is None:
                reg.append("nist8547_deprecated_2030")
        else:  # elliptic curve
            if curve in {"secp192r1", "prime192v1", "secp160r1"} or (key_size and key_size < 256):
                weak = True
            elif curve in {"", "secp256r1", "prime256v1", "p-256", "x25519", "curve25519"}:
                reg.append("nist8547_deprecated_2030")
        if weak:
            adv.append("classically_insufficient")
            rationale = (
                f"{algo} at this parameter size is below acceptable classical strength "
                f"and is additionally solved outright by Shor's algorithm. Retire now on "
                f"classical grounds; do not wait for the PQC timeline."
            )
        else:
            rationale = (
                f"Shor's algorithm solves the hard problem underlying {algo} "
                f"({'integer factorisation' if algo == 'RSA' else 'discrete logarithms'}). "
                f"This is a break, not a weakening — no key size fixes it."
            )
        return Classification(algo, primitive, QuantumStatus.BROKEN, rationale, 0, reg, adv)

    # --- Post-quantum ------------------------------------------------------
    if algo in PQC:
        param = str(parameters.get("parameter_set", "")).upper()
        if algo == "ML-KEM" and param and "1024" not in param:
            reg.append("cnsa2_noncompliant")
        if algo == "ML-DSA" and param and "87" not in param:
            reg.append("cnsa2_noncompliant")
        return Classification(
            algo, primitive, QuantumStatus.ADEQUATE,
            f"{algo} is a post-quantum standard; no known quantum or classical break.",
            5, reg, adv,
        )

    # --- Classically broken ------------------------------------------------
    if algo in {"MD5", "MD4", "DES", "RC4", "RC2"}:
        return Classification(
            algo, primitive, QuantumStatus.BROKEN_CLASSICAL,
            f"{algo} is broken by practical classical attacks. Quantum computing is "
            f"irrelevant here — retire immediately.",
            0, ["cnsa2_noncompliant"], adv,
        )

    # --- Deprecated / insufficient (weak, but not 'broken') ----------------
    if algo == "3DES":
        return Classification(
            algo, primitive, QuantumStatus.DEPRECATED_INSUFFICIENT,
            "3DES is not broken, but its 64-bit block size makes it vulnerable to "
            "birthday-bound attacks (Sweet32) and NIST has disallowed it. Retire on "
            "classical grounds.",
            0, ["cnsa2_noncompliant"], adv,
        )
    if algo == "SHA-1":
        return Classification(
            algo, primitive, QuantumStatus.DEPRECATED_INSUFFICIENT,
            "Chosen-prefix collisions against SHA-1 have been practical since 2020; "
            "treat as broken for any signature or certificate use. Not a quantum issue.",
            0, ["cnsa2_noncompliant"], adv,
        )
    if algo in {"Blowfish", "SHA-224"}:
        return Classification(
            algo, primitive, QuantumStatus.DEPRECATED_INSUFFICIENT,
            f"{algo} is below current strength recommendations.",
            1, ["cnsa2_noncompliant"], adv,
        )

    # --- Symmetric and hash: adequate (see module docstring) ---------------
    if algo == "AES":
        level = _aes_level(key_size)
        if (key_size or 128) < 256:
            reg.append("cnsa2_noncompliant")
        return Classification(
            algo, primitive, QuantumStatus.ADEQUATE,
            f"AES-{key_size or 128} remains adequate against quantum attack. Grover gives "
            f"only a quadratic speedup, requires ~2^{(key_size or 128)//2} sequential "
            f"operations, and parallelises poorly."
            + (" CNSA 2.0 requires AES-256 as policy, not because of a break."
               if (key_size or 128) < 256 else ""),
            level, reg, adv,
        )
    if algo == "ChaCha20":
        return Classification(
            algo, primitive, QuantumStatus.ADEQUATE,
            "ChaCha20 uses a 256-bit key; Grover leaves an ample margin.",
            5, ["cnsa2_noncompliant"], adv,
        )
    if algo.startswith("SHA") or algo in {"BLAKE2b"}:
        level = _sha_level(algo)
        if level < 4:
            reg.append("cnsa2_noncompliant")
        return Classification(
            algo, primitive, QuantumStatus.ADEQUATE,
            f"{algo} is adequate post-quantum. The relevant quantum attack on collision "
            f"resistance (Brassard-Hoyer-Tapp) is not practically better than the classical "
            f"birthday bound once quantum memory cost is counted."
            + (" CNSA 2.0 requires SHA-384+ as policy." if level < 4 else ""),
            level, reg, adv,
        )
    if algo in {"PBKDF2", "bcrypt", "scrypt", "Argon2", "HMAC"}:
        return Classification(
            algo, primitive, QuantumStatus.ADEQUATE,
            f"{algo} is a symmetric construction; no quantum-specific concern.",
            2, reg, adv,
        )

    return Classification(
        algo, primitive, QuantumStatus.UNKNOWN,
        f"No classification rule matched '{algorithm}'. Review manually.",
        None, reg, adv,
    )
