"""X.509 parsing, chain construction and PKI blast radius.

The fixtures in `samples/vulnerable-app/pki/` are a real three-tier PKI built
with OpenSSL — a root, an issuing CA beneath it, two leaves beneath that, plus a
legacy root that should light up. Only the certificates are committed; no
private keys.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cbom_compass.engine import run_scan
from cbom_compass.models import AssetType
from cbom_compass.policy import Policy
from cbom_compass.risk import classify_asset
from cbom_compass.scanners import CertificateScanner
from cbom_compass.scanners.certificates import blast_radius
from cbom_compass.x509 import DERError, parse_any, parse_der, parse_pem_bundle

PKI = Path("samples/vulnerable-app/pki")
APP = "samples/vulnerable-app"
POLICY = f"{APP}/crypto-policy.yaml"


def cert(name):
    return parse_any((PKI / name).read_bytes())[0]


# ---------------------------------------------------------------- parsing
def test_a_certificate_yields_its_subject_and_issuer():
    """The old byte-sniffing could not read a name, which is why there was no
    chain: without a subject there is nothing to match an issuer against."""
    root = cert("acme-root-ca.crt")
    assert "CN=Acme Root CA" in root.subject
    assert root.subject == root.issuer


def test_key_algorithm_and_size_are_parsed_not_guessed():
    """Key size used to be inferred from the length of the whole file."""
    assert (cert("acme-root-ca.crt").public_key_algorithm,
            cert("acme-root-ca.crt").key_size) == ("RSA", 4096)
    assert (cert("acme-issuing-ca.crt").public_key_algorithm,
            cert("acme-issuing-ca.crt").key_size) == ("RSA", 2048)
    leaf = cert("payments.acme.example.crt")
    assert (leaf.public_key_algorithm, leaf.key_size, leaf.curve) == \
        ("ECDSA", 256, "secp256r1")


def test_basic_constraints_separate_authorities_from_leaves():
    assert cert("acme-root-ca.crt").is_ca is True
    assert cert("acme-issuing-ca.crt").is_ca is True
    assert cert("payments.acme.example.crt").is_ca is False


def test_the_signature_over_a_certificate_is_recorded_separately():
    """A certificate's own key can be strong while the signature over it is
    forgeable. They are different findings about different keys."""
    legacy = cert("legacy-root-ca.crt")
    assert legacy.signature_hash == "SHA-1"
    assert cert("acme-root-ca.crt").signature_hash == "SHA-256"


def test_self_signed_is_decided_on_key_id_where_there_is_one():
    assert cert("acme-root-ca.crt").self_signed is True
    assert cert("acme-issuing-ca.crt").self_signed is False


def test_a_pem_bundle_yields_every_certificate_in_it():
    """Chains ship as bundles; reading only the first would lose the root."""
    assert len(parse_pem_bundle((PKI / "acme-chain.pem").read_bytes())) == 2


@pytest.mark.parametrize("payload", [
    b"", b"not a certificate at all", b"\x30", b"\x30\x82\xff\xff",
    b"-----BEGIN CERTIFICATE-----\nbm90IGRlcgo=\n-----END CERTIFICATE-----\n",
])
def test_malformed_input_is_rejected_not_crashed(payload):
    """A scanner walking a filesystem meets every kind of file."""
    try:
        assert parse_any(payload) == []
    except DERError:
        pass          # raising the declared error is equally acceptable


def test_parse_der_rejects_a_truncated_length():
    with pytest.raises(DERError):
        parse_der(b"\x30\x84\x7f\xff\xff\xff")


# ------------------------------------------------------------------ chain
def test_the_chain_is_reconstructed_from_disk():
    result = CertificateScanner().scan(str(PKI))
    by_id = {a.id: a for a in result.assets}
    links = {
        (by_id[r.source_id].certificate["subject"].split("CN=")[-1],
         by_id[r.target_id].certificate["subject"].split("CN=")[-1])
        for r in result.relationships if r.kind == "signed-by"
    }
    assert ("payments.acme.example", "Acme Issuing CA") in links
    assert ("api.acme.example", "Acme Issuing CA") in links
    assert ("Acme Issuing CA", "Acme Root CA") in links


def test_a_root_is_not_linked_to_itself():
    result = CertificateScanner().scan(str(PKI))
    assert all(r.source_id != r.target_id for r in result.relationships)


def test_blast_radius_counts_everything_beneath_a_certificate():
    """The number that orders a PKI migration: re-issuing a leaf under a root
    you have not replaced yet buys nothing."""
    result = CertificateScanner().scan(str(PKI))
    by_subject = {a.certificate["subject"].split("CN=")[-1]: a for a in result.assets}
    radius = blast_radius(result.assets, result.relationships)
    assert radius[by_subject["Acme Root CA"].id] == 3      # intermediate + 2 leaves
    assert radius[by_subject["Acme Issuing CA"].id] == 2
    assert radius.get(by_subject["payments.acme.example"].id, 0) == 0


def test_the_same_certificate_in_two_files_is_one_asset():
    """It appears both standalone and inside the chain bundle."""
    report = run_scan({"certificates": [APP]}, Policy.load(POLICY))
    certificates = [a for a in report.inventory.assets
                    if a.asset_type is AssetType.CERTIFICATE]
    fingerprints = [a.certificate["fingerprint_sha256"] for a in certificates]
    assert len(fingerprints) == len(set(fingerprints))
    root = next(a for a in certificates if "Acme Root CA" in a.certificate["subject"])
    assert len(root.evidence) == 2, "both locations should be kept as evidence"


# ----------------------------------------------------------------- scoring
def test_an_authority_is_a_slower_migration_than_a_leaf():
    """A leaf is re-issued and deployed. A CA's public key is pinned in trust
    stores and baked into firmware, so replacing it is a redistribution
    exercise. Scoring them the same would be the most misleading thing this
    tool could tell a PKI owner."""
    result = CertificateScanner().scan(str(PKI))
    policy = Policy(z_year=2035)
    authority = next(a for a in result.assets
                     if a.location_class == "certificate-authority")
    leaf = next(a for a in result.assets
                if a.location_class == "certificate-store")
    assert classify_asset(authority, policy, 2026).y_years > \
        classify_asset(leaf, policy, 2026).y_years


def test_blast_radius_is_reported_but_does_not_inflate_the_score():
    """Criticality is a human input in this tool. Silently promoting a CA
    because it signs a lot would be the confident guess the scoring model
    refuses to make everywhere else."""
    report = run_scan({"certificates": [APP]}, Policy.load(POLICY))
    rows = {r["name"]: r for r in report.priority_list()}
    assert any(r["blast_radius"] > 0 for r in rows.values())
    # The two 4096-bit and 2048-bit CAs differ in reach but not in score driver.
    wide = max(report.priority_list(), key=lambda r: r["blast_radius"])
    assert wide["blast_radius"] >= 3
    assert wide["score"] <= 1.0


def test_the_weak_legacy_root_outranks_the_strong_one():
    report = run_scan({"certificates": [APP]}, Policy.load(POLICY))
    rows = report.priority_list()
    legacy = next(r for r in rows if r["key_size"] == 1024)
    strong = next(r for r in rows if r["key_size"] == 4096)
    assert legacy["score"] > strong["score"]


def test_kpis_count_authorities_and_the_widest_reach():
    kpis = run_scan({"certificates": [APP]}, Policy.load(POLICY)).kpis()
    assert kpis["certificate_authorities"] == 3
    assert kpis["widest_blast_radius"] == 3


def test_nothing_claims_the_chain_was_verified():
    """No signature is checked and no revocation is fetched. Saying "valid"
    while doing neither would be worse than staying quiet."""
    source = Path("cbom_compass/scanners/certificates.py").read_text()
    assert "verif" in source.lower()          # the limitation is stated
    report = run_scan({"certificates": [APP]}, Policy.load(POLICY))
    for row in report.priority_list():
        assert "valid" not in (row["rationale"] or "").lower()
