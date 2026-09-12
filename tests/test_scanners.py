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


# ---------------------------------------------------------------------------
# C / C++, C# and Rust
# ---------------------------------------------------------------------------
def _scan_text(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body)
    return SourceScanner().scan(str(path)).assets


def test_c_openssl_evp_names_carry_size_and_mode(tmp_path):
    assets = _scan_text(tmp_path, "a.c",
                        "EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, k, iv);\n")
    asset = next(a for a in assets if a.algorithm == "AES")
    assert asset.key_size == 128
    assert asset.parameters["mode"] == "GCM"


def test_c_key_size_comes_from_the_argument_not_the_name(tmp_path):
    assets = _scan_text(tmp_path, "a.c", "RSA_generate_key_ex(rsa, 1024, e, NULL);\n")
    assert any(a.algorithm == "RSA" and a.key_size == 1024 for a in assets)


def test_c_named_curve_is_extracted(tmp_path):
    """ECDSA with no curve cannot be told apart from a P-192 key."""
    assets = _scan_text(tmp_path, "a.c",
                        "k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n")
    asset = next(a for a in assets if a.algorithm == "ECDSA")
    assert asset.parameters["curve"] == "secp256r1"
    assert asset.key_size == 256


def test_mbedtls_embedded_calls_are_found(tmp_path):
    assets = _scan_text(tmp_path, "a.c",
                        "mbedtls_aes_setkey_enc(&aes, key, 256);\n"
                        "mbedtls_md5(in, len, out);\n")
    found = {(a.algorithm, a.key_size) for a in assets}
    assert ("AES", 256) in found and ("MD5", None) in found


def test_windows_cng_and_capi_constants_are_found(tmp_path):
    assets = _scan_text(tmp_path, "a.c",
                        "BCryptOpenAlgorithmProvider(&h, BCRYPT_AES_ALGORITHM, NULL, 0);\n"
                        "CryptCreateHash(p, CALG_MD5, 0, 0, &h);\n")
    assert {a.algorithm for a in assets} >= {"AES", "MD5"}


def test_a_multiline_block_comment_is_not_code(tmp_path):
    """The middle line of a /* */ block neither opens nor closes it."""
    assets = _scan_text(tmp_path, "a.c",
                        "/* disabled for now:\n"
                        "   EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, k, NULL);\n"
                        "*/\n"
                        "EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, k, iv);\n")
    assert {a.algorithm for a in assets} == {"AES"}


def test_a_double_slash_inside_a_string_does_not_open_a_comment(tmp_path):
    assets = _scan_text(tmp_path, "a.c",
                        'const char *u = "https://example.com";\n'
                        "EVP_DigestInit_ex(m, EVP_md5(), NULL);\n")
    assert any(a.algorithm == "MD5" for a in assets)


def test_csharp_constructor_argument_is_the_key_size(tmp_path):
    assets = _scan_text(tmp_path, "A.cs", "var k = new RSACryptoServiceProvider(1024);\n")
    assert any(a.algorithm == "RSA" and a.key_size == 1024 for a in assets)


def test_csharp_legacy_providers_map_to_their_algorithms(tmp_path):
    assets = _scan_text(tmp_path, "A.cs",
                        "var a = new TripleDESCryptoServiceProvider();\n"
                        "var b = new SHA1Managed();\n"
                        "var c = new RijndaelManaged();\n")
    assert {a.algorithm for a in assets} == {"3DES", "SHA-1", "AES"}


def test_csharp_named_curve_replaces_the_bare_finding(tmp_path):
    """One call, one row — and the row that survives is the one with the curve."""
    assets = _scan_text(tmp_path, "A.cs",
                        "var k = ECDsa.Create(ECCurve.NamedCurves.nistP384);\n")
    ecdsa = [a for a in assets if a.algorithm == "ECDSA"]
    assert len(ecdsa) == 1
    assert ecdsa[0].parameters["curve"] == "secp384r1"


def test_rust_camelcase_type_carries_all_three_attributes(tmp_path):
    assets = _scan_text(tmp_path, "a.rs", "let c = Aes256Gcm::new(key.into());\n")
    asset = next(a for a in assets if a.algorithm == "AES")
    assert (asset.key_size, asset.parameters["mode"]) == (256, "GCM")


def test_rust_chacha_is_not_split_into_syllables(tmp_path):
    """Generic CamelCase splitting mangles this one, which is why it is listed."""
    assets = _scan_text(tmp_path, "a.rs", "let c = ChaCha20Poly1305::new(key.into());\n")
    asset = next(a for a in assets if a.algorithm == "ChaCha20")
    assert asset.parameters["mode"] == "POLY1305"


def test_rust_key_size_argument_is_read(tmp_path):
    assets = _scan_text(tmp_path, "a.rs",
                        "let k = RsaPrivateKey::new(&mut rng, 1024).unwrap();\n")
    assert any(a.algorithm == "RSA" and a.key_size == 1024 for a in assets)


def test_rust_curve_crates_resolve_to_curves(tmp_path):
    assets = _scan_text(tmp_path, "a.rs",
                        "use ed25519_dalek::SigningKey;\nuse p256::ecdsa::Signature;\n")
    curves = {a.parameters.get("curve") for a in assets}
    assert "ed25519" in curves and "secp256r1" in curves


def test_new_languages_report_medium_confidence(tmp_path):
    """Pattern rules, not an AST — the confidence has to say so."""
    for name, body in (("a.c", "EVP_DigestInit_ex(m, EVP_md5(), NULL);\n"),
                       ("A.cs", "var h = MD5.Create();\n"),
                       ("a.rs", "let mut h = Md5::new();\n")):
        assets = _scan_text(tmp_path, name, body)
        assert assets and all(a.confidence.value == "medium" for a in assets)


# ---------------------------------------------------------------------------
# Module-level constant folding
# ---------------------------------------------------------------------------
def test_algorithm_named_by_a_module_constant_is_resolved(tmp_path):
    assets = _scan_text(tmp_path, "a.py",
                        'import hashlib\nALGO = "md5"\n'
                        'def d(b): return hashlib.new(ALGO, b)\n')
    assert any(a.algorithm == "MD5" for a in assets)


def test_key_size_behind_a_constant_is_resolved(tmp_path):
    """RSA with no size loses the attribute that makes it urgent."""
    assets = _scan_text(tmp_path, "a.py",
                        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                        "BITS = 1024\n"
                        "k = rsa.generate_private_key(public_exponent=65537, key_size=BITS)\n")
    assert any(a.algorithm == "RSA" and a.key_size == 1024 for a in assets)


def test_environment_default_is_reported_but_marked_conditional(tmp_path):
    assets = _scan_text(tmp_path, "a.py",
                        'import hashlib, os\nALGO = os.environ.get("D", "md5")\n'
                        'def d(b): return hashlib.new(ALGO, b)\n')
    md5 = next(a for a in assets if a.algorithm == "MD5")
    assert md5.confidence.value == "medium"
    assert "override" in md5.evidence[0].detail["resolved_from"]


def test_getattr_with_a_literal_attribute_resolves(tmp_path):
    assets = _scan_text(tmp_path, "a.py",
                        'import hashlib\nfn = getattr(hashlib, "sha1")\n')
    assert any(a.algorithm == "SHA-1" for a in assets)


def test_a_function_local_binding_is_not_folded(tmp_path):
    """Only module scope is walked. A local can be rebound on another path, and
    following that is dataflow analysis, not constant folding."""
    assets = _scan_text(tmp_path, "a.py",
                        'import hashlib\n'
                        'def d(b):\n    algo = "md5"\n    return hashlib.new(algo, b)\n')
    assert not [a for a in assets if a.algorithm == "MD5"]


def test_folding_never_executes_what_it_reads(tmp_path):
    """A scanner that evaluates expressions can be made to run anything."""
    assets = _scan_text(tmp_path, "a.py",
                        'import hashlib\nALGO = __import__("os").popen("id").read()\n'
                        'def d(b): return hashlib.new(ALGO, b)\n')
    assert assets == []


def test_unresolvable_constant_is_dropped_not_guessed(tmp_path):
    assets = _scan_text(tmp_path, "a.py",
                        'import hashlib, os\nALGO = os.environ["DIGEST"]\n'
                        'def d(b): return hashlib.new(ALGO, b)\n')
    assert assets == []


def test_one_algorithm_in_one_binary_is_one_row(tmp_path):
    """A symbol observation and a library inference are the same fact.

    Emitting both put two identical-looking rows on the dashboard for one
    algorithm in one file, and they could never merge: `identity_key` keys a
    library-backed finding on the library and a symbol finding on the location.
    """
    blob = tmp_path / "app.bin"
    blob.write_bytes(b"\x7fELF" + b"\x00" * 64
                     + b"OpenSSL 3.0.11 19 Sep 2023" + b"\x00" * 16
                     + b"DH_generate_key" + b"\x00" * 16)
    assets = BinaryScanner().scan(str(blob)).assets

    dh = [a for a in assets if a.algorithm == "DH"]
    assert len(dh) == 1, [(a.algorithm, a.library, a.detection_methods) for a in dh]
    # The stronger evidence is the one that survives...
    assert dh[0].detection_methods == ["binary-symbol-string"]
    # ...and the library context is kept on it rather than thrown away.
    assert "openssl" in dh[0].evidence[0].detail["linked_libraries"]


def test_a_library_algorithm_not_observed_directly_is_still_reported(tmp_path):
    """Dropping the inference entirely would lose real coverage."""
    blob = tmp_path / "app.bin"
    blob.write_bytes(b"\x7fELF" + b"\x00" * 64
                     + b"OpenSSL 3.0.11 19 Sep 2023" + b"\x00" * 16)
    assets = BinaryScanner().scan(str(blob)).assets
    inferred = [a for a in assets if a.algorithm == "DH"]
    assert len(inferred) == 1
    assert inferred[0].library == "openssl"
    assert inferred[0].detection_methods == ["binary-version-string"]


def test_binary_scanner_skips_the_same_directories_as_the_others(tmp_path):
    """`scan .` walked the whole virtualenv and every pack file in .git.

    Every other path scanner skipped those; this one excluded only `.git`, and
    matched on the absolute path. On this repository it turned a two-second scan
    into minutes, which made the CI gate unusable at its default of `.`.
    """
    root = tmp_path / "proj"
    (root / ".venv" / "lib").mkdir(parents=True)
    (root / ".git" / "objects").mkdir(parents=True)
    (root / "src").mkdir(parents=True)
    elf = b"\x7fELF" + b"\x00" * 64 + b"OpenSSL 3.0.11" + b"\x00" * 16
    (root / ".venv" / "lib" / "vendored.so").write_bytes(elf)
    (root / ".git" / "objects" / "pack.bin").write_bytes(elf)
    (root / "src" / "app.bin").write_bytes(elf)

    locations = {a.primary_location
                 for a in BinaryScanner().scan(str(root)).assets}
    assert locations, "the one real binary should still be found"
    assert all(loc.startswith("src/") for loc in locations), locations


def test_a_virtualenv_is_still_scannable_when_it_is_the_target(tmp_path):
    """The skip is relative to the scan root, so pointing at a virtualenv on
    purpose still works — the same rule the source scanner already used."""
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "vendored.so").write_bytes(
        b"\x7fELF" + b"\x00" * 64 + b"OpenSSL 3.0.11" + b"\x00" * 16)
    assert BinaryScanner().scan(str(venv)).assets


def test_kotlin_reaches_the_same_jca_as_java(tmp_path):
    """Found by the ecosystem survey: okhttp returned zero findings from 844
    files because it is 573 Kotlin files to 71 Java. A silent zero on a TLS
    client is the worst kind of wrong answer — nothing about it looks like a
    failure."""
    assets = _scan_text(tmp_path, "Held.kt",
                        'val kp = KeyPairGenerator.getInstance("RSA").run {\n'
                        '  initialize(2048, SecureRandom())\n}\n'
                        'val md = MessageDigest.getInstance("SHA-1")\n')
    found = {a.algorithm for a in assets}
    assert {"RSA", "SHA-1"} <= found, found


def test_an_identifier_that_merely_starts_with_tls_is_not_a_protocol(tmp_path):
    """`tlsVersion` classified as a TLS protocol version and was reported as an
    adequate cryptographic asset, because the check matched the prefix without
    requiring the remainder to be a version."""
    from cbom_compass.knowledge.algorithms import classify
    from cbom_compass.models import QuantumStatus

    for identifier in ("tlsVersion", "tlsVersions", "TLSVersion", "sslVersion"):
        assert classify(identifier).quantum_status is QuantumStatus.UNKNOWN, identifier
    # real versions still resolve
    assert classify("TLSv1.3").quantum_status is QuantumStatus.ADEQUATE
    assert classify("SSLv3").quantum_status is QuantumStatus.DEPRECATED_INSUFFICIENT
    assert classify("DTLSv1.2").quantum_status is QuantumStatus.ADEQUATE
