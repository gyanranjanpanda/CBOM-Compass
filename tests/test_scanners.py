"""Scanner behaviour, including the section 10 authorization gate."""

from pathlib import Path

import pytest

from cbom_compass.models import Confidence
from cbom_compass.policy import Policy
from cbom_compass.scanners import (BinaryScanner, ContainerScanner,
                                   DependencyScanner, SourceScanner, TLSScanner)

APP = "samples/vulnerable-app"
IMAGE = "samples/vulnerable-image"


def found(result):
    return {a.display_name for a in result.assets}


def test_python_ast_resolves_literal_key_sizes():
    names = found(SourceScanner().scan(f"{APP}/src/payments.py"))
    assert "RSA-2048" in names
    assert "RSA-1024" in names


def test_positional_key_size_is_read_from_the_right_argument(tmp_path):
    """`rsa.generate_private_key(65537, 2048)` is RSA-2048, not RSA-65537.

    The public exponent comes first in the cryptography API, so reading "the
    first integer argument" reported the exponent as the key size and the real
    size never reached the risk engine. Every sample in this repo passes these
    by keyword, which is why the regression needs its own fixture.
    """
    module = tmp_path / "keys.py"
    module.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, dsa, dh\n"
        "a = rsa.generate_private_key(65537, 2048)\n"
        "b = rsa.generate_private_key(65537, 1024)\n"
        "c = dsa.generate_private_key(1024)\n"
        "d = dh.generate_parameters(2, 2048)\n")
    names = found(SourceScanner().scan(str(module)))
    assert {"RSA-2048", "RSA-1024", "DSA-1024", "DH-2048"} <= names
    assert not any("65537" in n for n in names)


def test_python_ast_resolves_curves_and_modes():
    names = found(SourceScanner().scan(f"{APP}/src/payments.py"))
    assert "ECDSA-secp256r1" in names
    assert "AES-ECB" in names
    assert "AES-GCM" in names


def test_literal_arguments_give_high_confidence():
    result = SourceScanner().scan(f"{APP}/src/payments.py")
    rsa = next(a for a in result.assets if a.display_name == "RSA-2048")
    assert rsa.confidence is Confidence.HIGH


def test_java_and_js_patterns():
    java = found(SourceScanner().scan(f"{APP}/java/TokenService.java"))
    assert {"DES", "MD5", "AES-ECB"} <= java
    js = found(SourceScanner().scan(f"{APP}/js/auth.js"))
    assert "MD5" in js
    # The suite name carries the mode too: aes-128-cbc, not just aes-128.
    assert "AES-128-CBC" in js


def test_composite_suite_names_are_split_into_algorithm_size_and_mode():
    """Node and the JCA pack all three into one token, in different shapes."""
    from cbom_compass.scanners.source import split_suite

    assert split_suite("aes-128-cbc") == ("AES", 128, "CBC")
    assert split_suite("aes-256-gcm") == ("AES", 256, "GCM")
    assert split_suite("DESede/CBC/PKCS5Padding") == ("3DES", None, "CBC")
    # Longest-prefix matching: the leading "des" token must not win here.
    assert split_suite("des-ede3-cbc") == ("3DES", None, "CBC")
    assert split_suite("des-cbc") == ("DES", None, "CBC")
    assert split_suite("chacha20-poly1305") == ("ChaCha20", None, "POLY1305")


def test_jwt_algorithm_names_normalise():
    """RS256 is RSA, not a separate algorithm."""
    assert "RS256" not in found(SourceScanner().scan(f"{APP}/js/auth.js"))
    assert any(a.algorithm == "RSA" for a in SourceScanner().scan(f"{APP}/js/auth.js").assets)


def test_dependency_manifests_resolve_versions():
    result = DependencyScanner().scan(APP)
    libs = {(a.library, a.library_version) for a in result.assets if a.library}
    assert ("cryptography", "41.0.7") in libs
    assert ("pycrypto", "2.6.1") in libs


def test_binary_resolves_library_and_version():
    result = BinaryScanner().scan(IMAGE)
    assert ("openssl", "3.0.11") in {(a.library, a.library_version) for a in result.assets}


def _methods(result):
    by_method = {}
    for asset in result.assets:
        for ev in asset.evidence:
            by_method.setdefault(ev.detection_method, set()).add(ev.confidence)
    return by_method


def test_stripped_binary_falls_back_to_byte_scanning_at_lower_confidence():
    """The fixture has no import table, which is what a statically-linked or
    stripped binary looks like. Byte-scan findings must not claim the confidence
    a structural parse would earn."""
    by_method = _methods(BinaryScanner().scan(IMAGE))
    assert "binary-symbol-string" in by_method
    assert by_method["binary-symbol-string"] == {Confidence.MEDIUM}
    if "binary-constant" in by_method:
        assert by_method["binary-constant"] == {Confidence.LOW}


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="needs a real dynamic binary")
def test_import_table_parsing_yields_high_confidence_findings():
    """A real dynamically-linked binary: the import table names the algorithm,
    and sometimes the key size and mode too (EVP_aes_128_gcm)."""
    result = BinaryScanner().scan("/usr/bin/ssh")
    by_method = _methods(result)
    assert by_method["binary-import-table"] >= {Confidence.HIGH}
    names = {a.display_name for a in result.assets}
    assert "AES-128-GCM" in names or "AES-256-GCM" in names
    assert any(a.library == "libcrypto" for a in result.assets)


def test_container_finds_embedded_private_key():
    """The differentiated container find — nothing else locates this."""
    result = ContainerScanner().scan(IMAGE)
    keys = [a for a in result.assets if a.parameters.get("material") == "private-key"]
    assert keys, "expected an embedded private key"
    assert "server.key" in keys[0].primary_location


def test_container_records_a_fingerprint_never_the_key_bytes():
    """Section 10: discovered key material is stored as fingerprint + location."""
    result = ContainerScanner().scan(IMAGE)
    key = next(a for a in result.assets if a.parameters.get("material") == "private-key")
    evidence = key.evidence[0]
    assert evidence.detail.get("fingerprint_sha256")
    assert "PRIVATE KEY" not in (evidence.snippet or "")
    assert "MII" not in (evidence.snippet or "")


def test_tls_refuses_targets_outside_the_allowlist():
    """Refused, not warned — otherwise this is just a network scanner."""
    result = TLSScanner(Policy(scan_allowlist=["localhost"])).scan("example.com:443")
    assert result.assets == []
    assert result.errors and "refused" in result.errors[0].message


def test_tls_allowlist_supports_globs():
    policy = Policy(scan_allowlist=["*.test.internal"])
    assert policy.target_allowed("payments.test.internal")
    assert not policy.target_allowed("payments.example.com")


def test_empty_allowlist_refuses_everything():
    assert not Policy().target_allowed("localhost")


def test_missing_path_is_an_error_not_a_crash():
    result = SourceScanner().scan("/nonexistent/path/xyz")
    assert result.assets == []
    assert result.errors
