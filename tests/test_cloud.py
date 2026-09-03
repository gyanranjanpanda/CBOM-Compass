"""Cloud/HSM key-store scanner.

The AWS path is tested against a fake client rather than live credentials, so
the KeySpec mapping and the read-only constraint are both actually covered.
"""

import pytest

from cbom_compass.models import QuantumStatus, SourceType
from cbom_compass.policy import Policy
from cbom_compass.risk import classify_asset
from cbom_compass.scanners.cloud import ALLOWED_AWS_CALLS, CloudScanner

EXPORT = "samples/keystore-export.json"


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
