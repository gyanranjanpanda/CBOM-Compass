"""CycloneDX 1.7 conformance — PRD v1.1 section 13 success metric."""

from cbom_compass import cbom
from cbom_compass.engine import run_scan
from cbom_compass.policy import Policy

POLICY = "samples/vulnerable-app/crypto-policy.yaml"


def report():
    return run_scan(
        {"source": ["samples/vulnerable-app"], "dependencies": ["samples/vulnerable-app"]},
        Policy.load(POLICY),
    )


def test_emits_cyclonedx_17():
    document = report().cbom()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert document["serialNumber"].startswith("urn:uuid:")


def test_document_validates():
    assert cbom.validate(report().cbom()) == []


def test_components_are_cryptographic_assets():
    for component in report().cbom()["components"]:
        assert component["type"] == "cryptographic-asset"
        assert "assetType" in component["cryptoProperties"]


def test_nist_level_is_a_native_field_not_an_extension():
    """The schema already provides nistQuantumSecurityLevel, so we populate it
    natively rather than duplicating it into our namespace."""
    document = report().cbom()
    rsa = next(
        c for c in document["components"]
        if c["name"].startswith("RSA") and "algorithmProperties" in c["cryptoProperties"]
    )
    assert rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    extension_names = {p["name"] for p in rsa["properties"]}
    assert not any("nistQuantumSecurityLevel" in n for n in extension_names)


def test_extension_data_is_namespaced():
    document = report().cbom()
    for component in document["components"]:
        for prop in component.get("properties", []):
            assert prop["name"].startswith("cbom-compass:")


def test_mosca_provenance_survives_export():
    document = report().cbom()
    props = {p["name"]: p["value"] for c in document["components"] for p in c["properties"]}
    assert props["cbom-compass:mosca.X.source"] in {"tagged", "assumed"}
    assert props["cbom-compass:mosca.Y.source"] in {"tagged", "estimated"}


def test_validator_catches_a_bad_document():
    document = report().cbom()
    document["specVersion"] = "1.6"
    document["components"][0]["cryptoProperties"]["assetType"] = "nonsense"
    errors = cbom.validate(document)
    assert any("specVersion" in e for e in errors)
    assert any("assetType" in e for e in errors)


def test_dependency_refs_resolve_to_components():
    document = report().cbom()
    refs = {c["bom-ref"] for c in document["components"]}
    for dep in document["dependencies"]:
        assert dep["ref"] in refs
        assert all(t in refs for t in dep["dependsOn"])
