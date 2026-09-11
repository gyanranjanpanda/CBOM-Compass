"""Cloud and hardware-module key-store scanner.

Every provider is tested against a fake client rather than live credentials or a
physical token, so the key-spec mappings and the read-only constraints are all
actually covered rather than only asserted in a docstring.
"""

import pytest

from cbom_compass.models import QuantumStatus, SourceType
from cbom_compass.policy import Policy
from cbom_compass.risk import classify_asset
from cbom_compass.scanners import pkcs11 as p11
from cbom_compass.scanners.cloud import (ALLOWED_AWS_CALLS, ALLOWED_AZURE_CALLS,
                                         ALLOWED_GCP_CALLS, CloudScanner)

EXPORT = "samples/keystore-export.json"
HSM_EXPORT = "samples/hsm-export.json"


class FakeKMS:
    """Records every call, so the test can assert we stay read-only."""

    def __init__(self, keys):
        self._keys = keys
        self.calls: list[str] = []

    def list_keys(self, **kwargs):
        self.calls.append("list_keys")
        return {"Keys": [{"KeyId": k["KeyId"]} for k in self._keys]}

    def describe_key(self, KeyId):
        self.calls.append("describe_key")
        return {"KeyMetadata": next(k for k in self._keys if k["KeyId"] == KeyId)}

    def get_key_rotation_status(self, KeyId):
        self.calls.append("get_key_rotation_status")
        return {"KeyRotationEnabled":
                next(k for k in self._keys if k["KeyId"] == KeyId).get("RotationEnabled", False)}

    def decrypt(self, **kwargs):        # pragma: no cover - must never be called
        self.calls.append("decrypt")
        raise AssertionError("the scanner must never call decrypt")


AWS_KEYS = [
    {"KeyId": "k-rsa", "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY",
     "Enabled": True, "RotationEnabled": False},
    {"KeyId": "k-sym", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
     "Enabled": True, "RotationEnabled": True, "Origin": "AWS_CLOUDHSM"},
    {"KeyId": "k-pqc", "KeySpec": "ML_DSA_87", "KeyUsage": "SIGN_VERIFY",
     "Enabled": True, "RotationEnabled": True},
]


@pytest.fixture
def aws_scanner():
    fake = FakeKMS(AWS_KEYS)
    policy = Policy(scan_allowlist=["aws:us-east-1"])
    return CloudScanner(policy, client_factory=lambda region: fake), fake


def test_aws_key_specs_map_to_algorithms(aws_scanner):
    scanner, _ = aws_scanner
    result = scanner.scan("aws://us-east-1")
    found = {(a.algorithm, a.key_size) for a in result.assets}
    assert ("RSA", 2048) in found
    assert ("AES", 256) in found
    assert ("ML-DSA", None) in found


def test_scanner_stays_within_read_only_apis(aws_scanner):
    scanner, fake = aws_scanner
    scanner.scan("aws://us-east-1")
    assert set(fake.calls) <= ALLOWED_AWS_CALLS
    assert "decrypt" not in fake.calls


def test_no_key_material_is_recorded(aws_scanner):
    """Section 10: metadata only, never key bytes."""
    scanner, _ = aws_scanner
    result = scanner.scan("aws://us-east-1")
    for asset in result.assets:
        for ev in asset.evidence:
            assert "PRIVATE" not in (ev.snippet or "").upper()
            assert not any(k.lower() in {"plaintext", "keymaterial", "privatekey"}
                           for k in ev.detail)


def test_aws_region_outside_allowlist_is_refused():
    fake = FakeKMS(AWS_KEYS)
    scanner = CloudScanner(Policy(scan_allowlist=["aws:eu-west-1"]),
                           client_factory=lambda region: fake)
    result = scanner.scan("aws://us-east-1")
    assert result.assets == []
    assert result.errors and "refused" in result.errors[0].message
    assert fake.calls == []


def test_rotation_disabled_is_surfaced(aws_scanner):
    scanner, _ = aws_scanner
    result = scanner.scan("aws://us-east-1")
    rsa = next(a for a in result.assets if a.algorithm == "RSA")
    assert rsa.evidence[0].detail["rotation_enabled"] is False
    assert "rotation is disabled" in rsa.evidence[0].snippet


def test_hsm_backing_is_recorded(aws_scanner):
    scanner, _ = aws_scanner
    result = scanner.scan("aws://us-east-1")
    sym = next(a for a in result.assets if a.algorithm == "AES")
    assert sym.evidence[0].detail["hsm_backed"] is True


def test_file_provider_reads_an_export():
    """The sample-environment mode: demoing this source type needs no credentials."""
    result = CloudScanner().scan(f"file://{EXPORT}")
    assert len(result.assets) == 7
    assert all(e.source_type is SourceType.CLOUD_KMS
               for a in result.assets for e in a.evidence)


def test_managed_keys_are_risk_scored():
    result = CloudScanner().scan(f"file://{EXPORT}")
    policy = Policy(z_year=2031)
    by_algorithm = {}
    for asset in result.assets:
        by_algorithm.setdefault(asset.algorithm, classify_asset(asset, policy, 2026))
    assert by_algorithm["RSA"].quantum_status is QuantumStatus.BROKEN
    assert by_algorithm["ML-DSA"].quantum_status is QuantumStatus.ADEQUATE
    assert by_algorithm["AES"].quantum_status is QuantumStatus.ADEQUATE
    assert by_algorithm["RSA"].score > by_algorithm["ML-DSA"].score


def test_missing_export_is_an_error_not_a_crash():
    result = CloudScanner().scan("file://does/not/exist.json")
    assert result.assets == []
    assert result.errors


def test_unrecognised_target_is_rejected():
    result = CloudScanner().scan("gopher://keys")
    assert result.errors and "unrecognised" in result.errors[0].message


# ---------------------------------------------------------------------------
# Azure Key Vault
# ---------------------------------------------------------------------------
class FakeJWK:
    def __init__(self, kty, n=None, crv=None, key_ops=None):
        self.kty, self.n, self.crv = kty, n, crv
        self.key_ops = key_ops or []


class FakeKeyProperties:
    def __init__(self, name, enabled=True, expires_on=None):
        self.name, self.enabled, self.expires_on = name, enabled, expires_on


class FakeAzureKey:
    def __init__(self, properties, jwk):
        self.properties, self.key = properties, jwk
        self.key_type = jwk.kty


class FakeKeyVault:
    """Records calls, so the read-only constraint is actually asserted."""

    def __init__(self, keys):
        self._keys = keys
        self.calls: list[str] = []

    def list_properties_of_keys(self):
        self.calls.append("list_properties_of_keys")
        return [k.properties for k in self._keys]

    def get_key(self, name):
        self.calls.append("get_key")
        return next(k for k in self._keys if k.properties.name == name)

    def decrypt(self, **kwargs):        # pragma: no cover - must never be called
        self.calls.append("decrypt")
        raise AssertionError("the scanner must never call decrypt")


AZURE_KEYS = [
    FakeAzureKey(FakeKeyProperties("payments-signing"),
                 FakeJWK("RSA-HSM", n=b"\x00" * 256, key_ops=["sign", "verify"])),
    FakeAzureKey(FakeKeyProperties("token-signing"),
                 FakeJWK("EC", crv="P-384", key_ops=["sign"])),
    FakeAzureKey(FakeKeyProperties("retired-key", enabled=False),
                 FakeJWK("RSA", n=b"\x00" * 128, key_ops=["verify"])),
]


@pytest.fixture
def azure_scanner():
    fake = FakeKeyVault(AZURE_KEYS)
    policy = Policy(scan_allowlist=["azure:kv-prod"])
    return CloudScanner(policy, azure_factory=lambda vault: fake), fake


def test_azure_key_types_and_sizes_map(azure_scanner):
    scanner, _ = azure_scanner
    result = scanner.scan("azure://kv-prod")
    found = {(a.algorithm, a.key_size) for a in result.assets}
    # Azure reports RSA size only as the length of the public modulus.
    assert ("RSA", 2048) in found
    assert ("RSA", 1024) in found
    assert ("ECDSA", 384) in found


def test_azure_hsm_suffix_is_recorded(azure_scanner):
    scanner, _ = azure_scanner
    result = scanner.scan("azure://kv-prod")
    signing = next(a for a in result.assets
                   if a.evidence[0].detail["key_id"] == "payments-signing")
    assert signing.evidence[0].detail["hsm_backed"] is True


def test_azure_stays_within_read_only_apis(azure_scanner):
    scanner, fake = azure_scanner
    scanner.scan("azure://kv-prod")
    assert set(fake.calls) <= ALLOWED_AZURE_CALLS
    assert "decrypt" not in fake.calls


def test_azure_vault_outside_allowlist_is_refused():
    fake = FakeKeyVault(AZURE_KEYS)
    scanner = CloudScanner(Policy(scan_allowlist=["azure:kv-dev"]),
                           azure_factory=lambda vault: fake)
    result = scanner.scan("azure://kv-prod")
    assert result.assets == []
    assert result.errors and "refused" in result.errors[0].message
    assert fake.calls == []


def test_azure_disabled_key_is_still_inventoried(azure_scanner):
    """A disabled key still holds material and still has to be migrated."""
    scanner, _ = azure_scanner
    result = scanner.scan("azure://kv-prod")
    retired = next(a for a in result.assets
                   if a.evidence[0].detail["key_id"] == "retired-key")
    assert retired.evidence[0].detail["enabled"] is False
    assert "disabled but still present" in retired.evidence[0].snippet


# ---------------------------------------------------------------------------
# GCP Cloud KMS
# ---------------------------------------------------------------------------
class FakeNamed:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeGCPKMS:
    def __init__(self, rings):
        self._rings = rings
        self.calls: list[str] = []

    def list_key_rings(self, request):
        self.calls.append("list_key_rings")
        return [r["ring"] for r in self._rings]

    def list_crypto_keys(self, request):
        self.calls.append("list_crypto_keys")
        ring = next(r for r in self._rings if r["ring"].name == request["parent"])
        return [k["key"] for k in ring["keys"]]

    def list_crypto_key_versions(self, request):
        self.calls.append("list_crypto_key_versions")
        for ring in self._rings:
            for key in ring["keys"]:
                if key["key"].name == request["parent"]:
                    return key["versions"]
        return []

    def decrypt(self, **kwargs):        # pragma: no cover - must never be called
        self.calls.append("decrypt")
        raise AssertionError("the scanner must never call decrypt")


RING = "projects/p/locations/global/keyRings/r"
GCP_RINGS = [{
    "ring": FakeNamed(name=RING),
    "keys": [
        {"key": FakeNamed(name=f"{RING}/cryptoKeys/signing",
                          purpose="ASYMMETRIC_SIGN", rotation_period=None),
         "versions": [
             FakeNamed(name=f"{RING}/cryptoKeys/signing/cryptoKeyVersions/1",
                       algorithm="RSA_SIGN_PSS_3072_SHA256",
                       protection_level="HSM", state="ENABLED"),
             # An older version left enabled is residual exposure, and is
             # exactly what an inventory is supposed to surface.
             FakeNamed(name=f"{RING}/cryptoKeys/signing/cryptoKeyVersions/2",
                       algorithm="EC_SIGN_P256_SHA256",
                       protection_level="SOFTWARE", state="ENABLED"),
             FakeNamed(name=f"{RING}/cryptoKeys/signing/cryptoKeyVersions/3",
                       algorithm="RSA_SIGN_PSS_3072_SHA256",
                       protection_level="HSM", state="DESTROYED"),
         ]},
        {"key": FakeNamed(name=f"{RING}/cryptoKeys/envelope",
                          purpose="ENCRYPT_DECRYPT", rotation_period=7776000),
         "versions": [
             FakeNamed(name=f"{RING}/cryptoKeys/envelope/cryptoKeyVersions/1",
                       algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
                       protection_level="SOFTWARE", state="ENABLED"),
         ]},
    ],
}]


@pytest.fixture
def gcp_scanner():
    fake = FakeGCPKMS(GCP_RINGS)
    policy = Policy(scan_allowlist=["gcp:p/global"])
    return CloudScanner(policy, gcp_factory=lambda: fake), fake


def test_gcp_walks_rings_keys_and_versions(gcp_scanner):
    scanner, _ = gcp_scanner
    result = scanner.scan("gcp://p/global")
    found = {(a.algorithm, a.key_size) for a in result.assets}
    assert ("RSA", 3072) in found
    assert ("ECDSA", 256) in found
    assert ("AES", 256) in found


def test_gcp_destroyed_versions_are_not_counted(gcp_scanner):
    """A destroyed version holds no material, so counting it inflates every KPI."""
    scanner, _ = gcp_scanner
    result = scanner.scan("gcp://p/global")
    assert len(result.assets) == 3
    assert not any("cryptoKeyVersions/3" in a.evidence[0].detail["key_id"]
                   for a in result.assets)


def test_gcp_protection_level_marks_hsm_keys(gcp_scanner):
    scanner, _ = gcp_scanner
    result = scanner.scan("gcp://p/global")
    by_hsm = {a.algorithm: a.evidence[0].detail["hsm_backed"] for a in result.assets}
    assert by_hsm["RSA"] is True
    assert by_hsm["ECDSA"] is False


def test_gcp_stays_within_read_only_apis(gcp_scanner):
    scanner, fake = gcp_scanner
    scanner.scan("gcp://p/global")
    assert set(fake.calls) <= ALLOWED_GCP_CALLS


def test_gcp_needs_project_and_location():
    result = CloudScanner(Policy(scan_allowlist=["gcp:*"])).scan("gcp://only-project")
    assert result.assets == []
    assert "project and location" in result.errors[0].message


# ---------------------------------------------------------------------------
# PKCS#11 hardware modules
# ---------------------------------------------------------------------------
class FakeP11Object:
    def __init__(self, key_type, object_class, label, modulus_bits=None,
                 value_len=None, ec_params=None, extractable=None, sensitive=None):
        self.key_type = key_type
        self.object_class = object_class
        self.label = label
        self.modulus_bits = modulus_bits
        self.value_len = value_len
        self.ec_params = ec_params
        self.extractable = extractable
        self.sensitive = sensitive

    # If the scanner ever reaches for key material it will land here.
    @property
    def value(self):                    # pragma: no cover - must never be read
        raise AssertionError("the scanner must never read CKA_VALUE")

    @property
    def private_exponent(self):         # pragma: no cover - must never be read
        raise AssertionError("the scanner must never read CKA_PRIVATE_EXPONENT")


class FakeSession:
    def __init__(self, objects, log):
        self._objects, self._log = objects, log

    def get_objects(self, *args, **kwargs):
        self._log.append("get_objects")
        return list(self._objects)

    def close(self):
        self._log.append("close")


class FakeToken:
    def __init__(self, label, objects, log, model="Luna K7", manufacturer="Thales"):
        self.label, self.model, self.manufacturer_id = label, model, manufacturer
        self._objects, self._log = objects, log

    def open(self, user_pin=None):
        self._log.append(f"open(pin={'yes' if user_pin else 'no'})")
        return FakeSession(self._objects, self._log)


class FakeSlot:
    def __init__(self, token, slot_id=0):
        self._token, self.slot_id = token, slot_id

    def get_token(self):
        return self._token


class FakeP11Lib:
    def __init__(self, slots, log):
        self._slots, self._log = slots, log

    def get_slots(self, token_present=True):
        self._log.append("get_slots")
        return list(self._slots)


P11_OBJECTS = [
    FakeP11Object("CKK_RSA", "ObjectClass.PRIVATE_KEY", "root-ca-key",
                  modulus_bits=4096, extractable=False, sensitive=True),
    FakeP11Object("CKK_EC", "ObjectClass.PRIVATE_KEY", "tls-leaf-key",
                  ec_params=bytes.fromhex("06082a8648ce3d030107"),
                  extractable=False, sensitive=True),
    FakeP11Object("CKK_DES3", "ObjectClass.SECRET_KEY", "pin-block-key",
                  value_len=24, extractable=False, sensitive=True),
    # An extractable secret key defeats the point of the HSM. Worth surfacing.
    FakeP11Object("CKK_AES", "ObjectClass.SECRET_KEY", "wrapping-key",
                  value_len=32, extractable=True, sensitive=True),
    FakeP11Object("CKK_ML_DSA", "ObjectClass.PRIVATE_KEY", "pqc-pilot-key",
                  extractable=False, sensitive=True),
]


@pytest.fixture
def hsm_scanner():
    log: list[str] = []
    lib = FakeP11Lib([FakeSlot(FakeToken("partition-01", P11_OBJECTS, log))], log)
    policy = Policy(scan_allowlist=["pkcs11:/usr/lib/softhsm/libsofthsm2.so"])
    scanner = CloudScanner(policy, pkcs11_factory=lambda path: lib)
    return scanner, log


TOKEN = "pkcs11:///usr/lib/softhsm/libsofthsm2.so"


def test_pkcs11_key_types_map_to_algorithms(hsm_scanner):
    scanner, _ = hsm_scanner
    result = scanner.scan(TOKEN)
    found = {(a.algorithm, a.key_size) for a in result.assets}
    assert ("RSA", 4096) in found
    assert ("ECDSA", 256) in found       # curve decoded from CKA_EC_PARAMS
    assert ("3DES", 192) in found        # CKA_VALUE_LEN is bytes, reported as bits
    assert ("AES", 256) in found
    assert ("ML-DSA", None) in found


def test_pkcs11_keys_are_hardware_module_not_key_store(hsm_scanner):
    """The whole point: an HSM key migrates on the vendor's schedule."""
    scanner, _ = hsm_scanner
    result = scanner.scan(TOKEN)
    assert {a.location_class for a in result.assets} == {"hardware-module"}
    assert all(a.evidence[0].detail["hsm_backed"] for a in result.assets)


def test_hardware_keys_carry_the_long_migration_estimate(hsm_scanner):
    """An HSM-resident RSA key must not be scored as a quick library bump."""
    scanner, _ = hsm_scanner
    result = scanner.scan(TOKEN)
    rsa = next(a for a in result.assets if a.algorithm == "RSA")
    software = next(a for a in CloudScanner().scan(f"file://{EXPORT}").assets
                    if a.algorithm == "RSA")
    policy = Policy(z_year=2035)
    hardware_risk = classify_asset(rsa, policy, 2026)
    managed_risk = classify_asset(software, policy, 2026)
    assert hardware_risk.y_years > managed_risk.y_years
    assert hardware_risk.exposure_gap > managed_risk.exposure_gap


def test_pkcs11_never_reads_key_material(hsm_scanner):
    """CKA_VALUE and CKA_PRIVATE_EXPONENT raise if touched; nothing touches them."""
    scanner, _ = hsm_scanner
    result = scanner.scan(TOKEN)
    for asset in result.assets:
        for ev in asset.evidence:
            assert "value" not in ev.detail
            assert not any("exponent" in k.lower() or "modulus" == k.lower()
                           for k in ev.detail)


def test_readable_attribute_set_holds_no_key_material():
    """The allowlist is the constraint; this is the test that keeps it true."""
    assert not (p11.READABLE_ATTRIBUTES & p11.DISALLOWED_ATTRIBUTES)
    p11.assert_no_key_material()


def test_extractable_key_is_flagged(hsm_scanner):
    scanner, _ = hsm_scanner
    result = scanner.scan(TOKEN)
    wrapping = next(a for a in result.assets
                    if a.evidence[0].detail["key_id"] == "wrapping-key")
    assert "extractable" in wrapping.evidence[0].snippet


def test_pkcs11_module_outside_allowlist_is_refused():
    log: list[str] = []
    lib = FakeP11Lib([FakeSlot(FakeToken("partition-01", P11_OBJECTS, log))], log)
    scanner = CloudScanner(Policy(scan_allowlist=["pkcs11:/other.so"]),
                           pkcs11_factory=lambda path: lib)
    result = scanner.scan(TOKEN)
    assert result.assets == []
    assert result.errors and "refused" in result.errors[0].message
    assert log == []


def test_pin_is_never_accepted_inline(monkeypatch, hsm_scanner):
    """A PIN in the target string would land in the store, the CBOM and the log."""
    scanner, log = hsm_scanner
    monkeypatch.setenv("HSM_PIN", "1234")
    scanner.scan(f"{TOKEN}?pin-env=HSM_PIN")
    assert "open(pin=yes)" in log
    assert p11.resolve_pin(None) is None
    assert p11.resolve_pin("NOT_SET_ANYWHERE") is None


def test_public_objects_are_readable_without_a_pin(hsm_scanner):
    scanner, log = hsm_scanner
    result = scanner.scan(TOKEN)
    assert "open(pin=no)" in log
    assert result.assets


def test_ec_params_decoding_handles_oids_and_names():
    assert p11.curve_from_ec_params(bytes.fromhex("06052b81040022")) == "secp384r1"
    assert p11.curve_from_ec_params(bytes.fromhex("06032b6570")) == "ed25519"
    assert p11.curve_from_ec_params("prime256v1") == "secp256r1"
    assert p11.curve_from_ec_params(b"\x13\x0aprime256v1") == "secp256r1"
    assert p11.curve_from_ec_params(None) is None


def test_hsm_export_demonstrates_the_source_type_without_a_token():
    result = CloudScanner().scan(f"file://{HSM_EXPORT}")
    assert len(result.assets) == 6
    assert {a.location_class for a in result.assets} == {"hardware-module"}
    assert all(a.parameters["material"] == "hardware-key" for a in result.assets)


def test_pkcs11_needs_a_module_path():
    result = CloudScanner(Policy(scan_allowlist=["pkcs11:*"])).scan("pkcs11://")
    assert result.assets == []
    assert "module path" in result.errors[0].message
