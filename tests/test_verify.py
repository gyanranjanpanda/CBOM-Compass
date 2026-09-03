"""Independent verification — and, more importantly, that it can fail.

A verifier that confirms everything proves nothing. These tests check both
directions: real findings are confirmed by re-reading the artefact, and
fabricated findings anchored to real files are rejected.
"""

from __future__ import annotations

import copy

import pytest

from cbom_compass.engine import run_scan
from cbom_compass.policy import Policy
from cbom_compass.verify import summarise, verify

APP = "samples/vulnerable-app"
POLICY = f"{APP}/crypto-policy.yaml"


@pytest.fixture(scope="module")
def report():
    return run_scan(
        {"source": [APP], "dependencies": [APP],
         "cloud": ["file://samples/keystore-export.json"]},
        Policy.load(POLICY),
    ).to_dict()


def test_real_findings_are_confirmed_from_disk(report):
    """Nothing is taken from the scan except the location it claimed."""
    result = summarise(verify(report, [APP], sample=0))
    assert result["unconfirmed"] == 0, "a real finding failed re-verification"
    assert result["confirmed"] > 20


def test_fabricated_findings_are_rejected(report):
    """The load-bearing test. Plant algorithms that are NOT at the claimed
    location and confirm the verifier says so — otherwise it is a rubber stamp
    and its 100% figure means nothing."""
    real = next(a for a in report["assets"] if a["source_types"][0] == "source_code"
                and a["algorithm"] in {"ECDH", "ECDSA", "AES"})
    planted = []
    for algorithm in ("RC4", "MD5", "DES", "3DES", "ML-DSA"):
        fake = copy.deepcopy(real)
        fake["algorithm"] = fake["name"] = algorithm
        fake["id"] = f"planted-{algorithm}"
        planted.append(fake)

    checks = verify({**report, "assets": planted}, [APP], sample=0)
    assert all(c.verdict == "unconfirmed" for c in checks), \
        "verifier accepted a fabricated finding"


def test_verifier_quotes_the_actual_source_line(report):
    """A sceptic must be able to repeat the check by hand."""
    checks = [c for c in verify(report, [APP], sample=0) if c.quoted]
    assert checks
    check = next(c for c in checks if ":" in c.detail)
    path, _, lineno = check.detail.rpartition(":")
    from pathlib import Path
    actual = Path(path).read_text().splitlines()[int(lineno) - 1].strip()
    assert check.quoted in actual or actual.startswith(check.quoted[:40])


def test_a_wrong_line_number_is_not_confirmed(report):
    """Anchoring a real algorithm to the wrong place must fail too."""
    real = next(a for a in report["assets"]
                if a["source_types"][0] == "source_code" and a["algorithm"] == "MD5")
    moved = copy.deepcopy(real)
    path = real["location"].rsplit(":", 1)[0]
    moved["location"] = f"{path}:1"
    moved["evidence"] = [{**real["evidence"][0], "location": f"{path}:1"}]
    checks = verify({**report, "assets": [moved]}, [APP], sample=0)
    assert checks[0].verdict == "unconfirmed"


def test_missing_artefact_is_reported_not_silently_passed(report):
    ghost = copy.deepcopy(report["assets"][0])
    ghost["location"] = "no/such/file.py:1"
    ghost["evidence"] = [{**ghost["evidence"][0], "location": "no/such/file.py:1"}]
    checks = verify({**report, "assets": [ghost]}, [APP], sample=0)
    assert checks[0].verdict == "unavailable"


def test_key_store_findings_are_checked_against_the_export(report):
    checks = [c for c in verify(report, [APP], sample=0)
              if "keystore" in c.location or "azure" in c.location]
    assert checks
    assert all(c.verdict == "confirmed" for c in checks)


def test_sampling_spreads_across_source_types(report):
    checks = verify(report, [APP], sample=9, seed=1)
    techniques = {c.technique for c in checks}
    assert len(techniques) > 1, "sample came from a single scanner"


def test_comments_are_not_reported_as_usage():
    """Real code check: a commented-out declaration is dead code, not crypto."""
    from cbom_compass.scanners.source import SourceScanner
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        java = Path(tmp) / "T.java"
        java.write_text(
            "public class T {\n"
            "    // private static final String OID = \"RSA\";\n"
            "    /* MessageDigest.getInstance(\"MD5\"); */\n"
            "    public void real() throws Exception {\n"
            "        MessageDigest d = MessageDigest.getInstance(\"SHA-256\");\n"
            "    }\n"
            "}\n")
        found = {a.display_name for a in SourceScanner().scan(str(java)).assets}
    assert "SHA-256" in found
    assert "MD5" not in found
    assert "RSA" not in found
