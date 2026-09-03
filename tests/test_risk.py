"""Mosca scoring — PRD v1.1 section 6.3."""

from cbom_compass.models import (Asset, AssetType, Confidence, Evidence,
                                 QuantumStatus, SourceType)
from cbom_compass.policy import Policy
from cbom_compass.risk import classify_asset


def asset(algorithm="RSA", key_size=2048, location="src/app.py:1",
          location_class="call-site", **kwargs):
    a = Asset(algorithm=algorithm, key_size=key_size, location_class=location_class, **kwargs)
    a.evidence.append(Evidence(SourceType.SOURCE_CODE, "python-ast", location, Confidence.HIGH))
    return a


def test_worked_example():
    """RSA-2048 on a public endpoint, untagged, scored from 2026 with Z=2031.

        X = 7 (financial default, assumed)   Y = 2 (public-api rule)
        Z_years = 2031 - 2026 = 5            gap = (7 + 2) - 5 = +4, overdue

        urgency    = 4 / 10                     = 0.40
        compliance = (10 - (2030 - 2026)) / 10  = 0.60   NIST deprecation, 4y out
        timing     = max(0.40, 0.60, 0.50)      = 0.60
        risk       = 1.0 (Shor-broken) x 0.60 x 1.0 (harvest-now) = 0.60

    The score is deadline-driven rather than Mosca-driven here, and the UI says
    so: at a +4 year gap the regulator's 2030 date is the nearer pressure.
    """
    policy = Policy(z_year=2031)
    result = classify_asset(asset(location_class="negotiated"), policy, current_year=2026)
    assert (result.x_years, result.x_source) == (7.0, "assumed")
    assert (result.y_years, result.y_source) == (2.0, "estimated")
    assert result.z_years == 5.0
    assert result.exposure_gap == 4.0
    assert result.hndl_flag is True
    assert result.urgency == 0.4
    assert result.compliance_component == 0.6
    assert result.risk == 0.6
    assert result.driver == "compliance"


def test_exposure_gap_is_signed_not_boolean():
    """A boolean times a weight gives two buckets, not a ranking."""
    policy = Policy(z_year=2060)
    result = classify_asset(asset(), policy, current_year=2026)
    assert result.exposure_gap < 0
    assert result.urgency == 0.0


def test_z_conversion_from_year_to_duration():
    policy = Policy(z_year=2040)
    result = classify_asset(asset(), policy, current_year=2026)
    assert result.z_years == 14.0
    assert result.z_year_used == 2040


def test_untagged_inputs_are_marked_assumed():
    result = classify_asset(asset(), Policy(), current_year=2026)
    assert result.x_source == "assumed"
    assert result.y_source == "estimated"


def test_tagged_inputs_come_from_policy(tmp_path):
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "scoring: {z_year: 2031}\n"
        "services:\n"
        "  - name: vault\n    paths: ['src/app.py*']\n"
        "    data_class: defence\n    criticality: high\n    surface: embedded\n"
    )
    policy = Policy.load(policy_file)
    result = classify_asset(asset(), policy, current_year=2026)
    assert (result.x_years, result.x_source) == (25.0, "tagged")
    assert (result.y_years, result.y_source) == (5.0, "tagged")
    assert result.criticality.value == "high"
    assert result.score == 1.0


def test_criticality_orders_equally_broken_assets(tmp_path):
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "scoring: {z_year: 2031}\n"
        "services:\n"
        "  - name: crown-jewels\n    paths: ['high/*']\n    criticality: high\n"
        "  - name: scratch\n    paths: ['low/*']\n    criticality: low\n"
    )
    policy = Policy.load(policy_file)
    high = classify_asset(asset(location="high/a.py:1"), policy, 2026)
    low = classify_asset(asset(location="low/a.py:1"), policy, 2026)
    assert high.score > low.score


def test_score_driver_is_attributed():
    """A regulation-pinned score must say so, or the Z slider looks broken."""
    result = classify_asset(asset(), Policy(z_year=2060), current_year=2026)
    assert result.driver in {"compliance", "quantum"}


def test_adequate_algorithms_never_score(tmp_path):
    """A real scan of paramiko once put its ML-KEM key exchange at 0.60 purely
    because the data it protects is long-lived. Timing modulates a need to
    migrate; it must never create one."""
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "scoring: {z_year: 2031}\n"
        "services:\n  - name: vault\n    paths: ['src/app.py*']\n"
        "    data_class: regulated\n    criticality: high\n")
    policy = Policy.load(policy_file)
    for algorithm, key_size in (("ML-KEM", None), ("AES", 256), ("SHA-256", None)):
        result = classify_asset(asset(algorithm, key_size), policy, 2026)
        assert result.score == 0.0, f"{algorithm} should need no action"
        assert result.driver == "none"


def test_mosca_differentiates_between_equally_broken_assets(tmp_path):
    """The point of Mosca: RSA protecting 25-year data outranks the same RSA
    protecting session data, even though the algorithm is identically broken."""
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "scoring: {z_year: 2031}\n"
        "services:\n"
        "  - {name: long, paths: ['long/*'], data_class: regulated, "
        "criticality: high, surface: public-api}\n"
        "  - {name: short, paths: ['short/*'], data_class: ephemeral, "
        "criticality: high, surface: internal-service}\n")
    policy = Policy.load(policy_file)
    long_lived = classify_asset(asset(location="long/a.py:1"), policy, 2026)
    short_lived = classify_asset(asset(location="short/a.py:1"), policy, 2026)
    assert long_lived.score > short_lived.score
    assert long_lived.driver == "mosca-urgency"
    assert short_lived.driver == "compliance"


def test_weak_crypto_still_scores_without_time_pressure(tmp_path):
    """The timing floor: 3DES protecting session data is still worth replacing."""
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "scoring: {z_year: 2031}\n"
        "services:\n  - {name: s, paths: ['short/*'], data_class: ephemeral, "
        "criticality: high}\n")
    result = classify_asset(asset("3DES", None, "short/a.py:1"), Policy.load(policy_file), 2026)
    assert result.score > 0
    assert result.driver == "baseline"


def test_compliance_pressure_rises_as_the_deadline_approaches():
    """A flat 1.0 from publication pinned every broken asset to one score."""
    policy = Policy(z_year=2031)
    far = classify_asset(asset(), policy, current_year=2026)
    near = classify_asset(asset(), policy, current_year=2029)
    assert near.compliance_component > far.compliance_component


def test_library_rows_do_not_double_count():
    """A library entry carries no risk of its own; its algorithms are separate assets."""
    library = Asset(algorithm="openssl", asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                    library="openssl", library_version="3.0.11", location_class="manifest")
    library.evidence.append(
        Evidence(SourceType.DEPENDENCY, "manifest-parse", "requirements.txt", Confidence.HIGH))
    result = classify_asset(library, Policy(z_year=2031), 2026)
    assert result.quantum_status is QuantumStatus.NOT_APPLICABLE
    assert result.score == 0.0


def test_embedded_private_key_is_urgent_regardless_of_algorithm():
    key = Asset(algorithm="unknown", asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                parameters={"material": "private-key"}, location_class="image-layer")
    key.evidence.append(Evidence(SourceType.CONTAINER, "layer-key-material",
                                 "img!etc/ssl/private/x.key", Confidence.HIGH))
    result = classify_asset(key, Policy(z_year=2031), 2026)
    assert result.quantum_component == 1.0
    assert "embedded_key_material" in result.regulatory_flags
