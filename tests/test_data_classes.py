"""Data classes sourced from regulation rather than from our defaults.

X — how long data must stay confidential — is the input everything else
multiplies through, and the one thing no scanner can discover. These tests are
mostly about provenance: the difference between a number an instrument requires
and a number somebody picked.
"""

from __future__ import annotations

from cbom_compass.models import Asset, Confidence, Evidence, SourceType
from cbom_compass.policy import Policy
from cbom_compass.risk import classify_asset

INDIA = "policies/india-regulated.yaml"


def asset_at(location):
    return Asset(algorithm="RSA", key_size=2048, location_class="call-site",
                 evidence=[Evidence(SourceType.SOURCE_CODE, "python-ast",
                                    location, Confidence.HIGH)])


def test_a_policy_class_overrides_our_default():
    policy = Policy.load(INDIA)
    assert policy.x_for("books-of-account")[0] == 8.0


def test_an_unknown_class_still_falls_back():
    """A policy that defines three classes must not break the other ten."""
    years, provenance, basis = Policy.load(INDIA).x_for("financial")
    assert (years, provenance, basis) == (7.0, "tagged", None)


def test_a_cited_obligation_is_reported_as_regulated():
    years, provenance, basis = Policy.load(INDIA).x_for("aadhaar-linked")
    assert years == 25.0
    assert provenance == "regulated"
    assert "Aadhaar" in basis


def test_an_internal_judgement_is_not_dressed_up_as_regulation():
    """Claiming regulatory backing for a number somebody picked is the one kind
    of dishonesty the source/note split exists to prevent."""
    for name in ("operational", "session", "health-record"):
        years, provenance, basis = Policy.load(INDIA).x_for(name)
        assert provenance == "tagged", name
        assert basis, name          # the explanation is still carried


def test_every_regulated_class_names_its_instrument():
    policy = Policy.load(INDIA)
    for name, entry in policy.data_classes.items():
        if entry.source:
            assert len(entry.source) > 30, f"{name} cites nothing checkable"


def test_regulation_changes_the_score_and_carries_the_citation():
    """The demonstration: the same key, scored under each policy."""
    key = asset_at("src/aadhaar/ekyc.py:10")
    default = classify_asset(key, Policy(), 2026)
    regulated = classify_asset(key, Policy.load(INDIA), 2026)

    assert default.x_source == "assumed" and default.x_basis is None
    assert regulated.x_source == "regulated"
    assert "Aadhaar" in regulated.x_basis
    # 25 years of required confidentiality, not an assumed 7.
    assert regulated.x_years == 25.0 and default.x_years == 7.0
    assert regulated.score > default.score


def test_a_short_lived_class_is_not_made_urgent_by_the_policy():
    """Sourcing X from regulation must be able to lower a score as well as
    raise one, or it is just a way of inflating numbers."""
    session = asset_at("src/session/token.py:4")
    regulated = classify_asset(session, Policy.load(INDIA), 2026)
    assert regulated.x_years == 0.1
    assert regulated.score < classify_asset(session, Policy(), 2026).score


def test_a_malformed_data_class_is_skipped_not_fatal(tmp_path):
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "data_classes:\n"
        "  good: {years: 4, source: An instrument that says four years}\n"
        "  bad: {years: not-a-number}\n"
        "  terse: 6\n")
    policy = Policy.load(policy_file)
    assert policy.x_for("good")[0] == 4.0
    assert policy.x_for("terse") == (6.0, "tagged", None)
    assert "bad" not in policy.data_classes


def test_the_template_carries_its_own_health_warning():
    """These periods have not been through counsel and the file has to say so."""
    text = open(INDIA).read()
    assert "not legal advice" in text
    assert "Confirm every value" in text
