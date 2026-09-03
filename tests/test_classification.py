"""The classification corrections are the whole point of v1.1 — lock them in."""

import pytest

from cbom_compass.knowledge.algorithms import classify, normalise
from cbom_compass.models import QuantumStatus


@pytest.mark.parametrize("algorithm,key_size", [("AES", 128), ("AES", 192), ("AES", 256)])
def test_aes_is_adequate_not_weakened(algorithm, key_size):
    """Grover needs ~2^64 sequential operations and parallelises poorly.

    Classifying AES-128 as 'weakened' would flood the act-now bucket and bury the
    RSA findings that actually matter.
    """
    assert classify(algorithm, key_size).quantum_status is QuantumStatus.ADEQUATE


@pytest.mark.parametrize("algorithm", ["SHA-256", "SHA-384", "SHA-512", "SHA3-256"])
def test_hashes_are_adequate(algorithm):
    """Brassard-Hoyer-Tapp is not practically better than the birthday bound."""
    assert classify(algorithm).quantum_status is QuantumStatus.ADEQUATE


def test_aes128_flagged_for_cnsa_but_not_as_a_break():
    result = classify("AES", 128)
    assert result.quantum_status is QuantumStatus.ADEQUATE
    assert "cnsa2_noncompliant" in result.regulatory_flags
    assert "policy" in result.rationale.lower()


@pytest.mark.parametrize("algorithm,params", [
    ("RSA", {}), ("ECDSA", {"curve": "secp256r1"}), ("ECDH", {}), ("DSA", {}), ("DH", {}),
])
def test_shor_broken_families(algorithm, params):
    result = classify(algorithm, 2048 if algorithm in {"RSA", "DSA", "DH"} else None, params)
    assert result.quantum_status is QuantumStatus.BROKEN
    assert "nist8547_disallowed_2035" in result.regulatory_flags
    assert result.nist_quantum_security_level == 0


def test_rsa_2048_is_deprecated_2030():
    assert "nist8547_deprecated_2030" in classify("RSA", 2048).regulatory_flags


def test_rsa_1024_is_classically_insufficient_not_merely_quantum_broken():
    result = classify("RSA", 1024)
    assert result.quantum_status is QuantumStatus.BROKEN
    assert "classically_insufficient" in result.advisories


def test_3des_is_deprecated_not_broken():
    """3DES is not broken — the issue is Sweet32 and a 64-bit block."""
    result = classify("3DES")
    assert result.quantum_status is QuantumStatus.DEPRECATED_INSUFFICIENT
    assert "block" in result.rationale.lower()


@pytest.mark.parametrize("algorithm", ["MD5", "DES", "RC4"])
def test_classically_broken(algorithm):
    assert classify(algorithm).quantum_status is QuantumStatus.BROKEN_CLASSICAL


def test_pqc_is_adequate():
    for algorithm in ("ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC", "LMS", "XMSS"):
        assert classify(algorithm).quantum_status is QuantumStatus.ADEQUATE


def test_ecb_mode_is_flagged():
    assert "insecure_mode_ecb" in classify("AES", 256, {"mode": "ECB"}).advisories


def test_protocol_versions():
    assert classify("TLSv1.3").quantum_status is QuantumStatus.ADEQUATE
    assert classify("TLSv1.0").quantum_status is QuantumStatus.DEPRECATED_INSUFFICIENT
    assert classify("SSLv3").quantum_status is QuantumStatus.DEPRECATED_INSUFFICIENT


@pytest.mark.parametrize("raw,expected", [
    ("rsaEncryption", "RSA"), ("prime256v1", "ECDSA"), ("RS256", "RSA"), ("ES256", "ECDSA"),
    ("HS256", "HMAC"), ("kyber", "ML-KEM"), ("dilithium", "ML-DSA"), ("sphincs+", "SLH-DSA"),
    ("aes-gcm", "AES"), ("des-ede3", "3DES"), ("arcfour", "RC4"),
])
def test_alias_normalisation(raw, expected):
    assert normalise(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("DESede", "3DES"),          # JCA spelling
    ("des-ede3-cbc", "3DES"),    # Node spelling — must not resolve via "des"
    ("des-ede3", "3DES"),
    ("EC", "ECDSA"),             # JCA names the EC keypair algorithm just "EC"
    ("des-cbc", "DES"),
])
def test_real_api_spellings_normalise(raw, expected):
    """Every one of these was a false positive or a miss before the corpus
    measured it — see corpus/README.md."""
    assert normalise(raw) == expected
