"""Asset identity and de-duplication — PRD v1.1 section 6.1.

The failure mode this guards against is visible on stage: Overview KPI totals
that do not reconcile with the Inventory Explorer row count.
"""

from cbom_compass.inventory import merge
from cbom_compass.models import (Asset, Confidence, Evidence, Relationship,
                                 SourceType)


def library_asset(source, method, location, version="3.0.11"):
    a = Asset(algorithm="AES", library="openssl", library_version=version,
              location_class="linked-library")
    a.evidence.append(Evidence(source, method, location, Confidence.HIGH))
    return a


def call_site(location, algorithm="RSA", key_size=2048):
    a = Asset(algorithm=algorithm, key_size=key_size, location_class="call-site")
    a.evidence.append(Evidence(SourceType.SOURCE_CODE, "python-ast", location, Confidence.HIGH))
    return a


def test_same_library_from_three_scanners_collapses_to_one_asset():
    inventory = merge([
        library_asset(SourceType.DEPENDENCY, "manifest-parse", "requirements.txt"),
        library_asset(SourceType.BINARY, "binary-version-string", "usr/lib/libcrypto.so.3"),
        library_asset(SourceType.CONTAINER, "syft-sbom", "img:openssl"),
    ])
    assert len(inventory.assets) == 1
    assert inventory.merged_count == 2
    assert len(inventory.assets[0].evidence) == 3


def test_different_library_versions_stay_separate():
    inventory = merge([
        library_asset(SourceType.DEPENDENCY, "manifest-parse", "a/requirements.txt", "3.0.11"),
        library_asset(SourceType.DEPENDENCY, "manifest-parse", "b/requirements.txt", "1.1.1w"),
    ])
    assert len(inventory.assets) == 2


def test_distinct_call_sites_do_not_merge():
    """RSA-2048 in payments.py and in auth.js are two things to migrate, owned by
    different services with different criticality. Collapsing them would silently
    drop one service's tag."""
    inventory = merge([call_site("src/payments.py:10"), call_site("js/auth.js:21")])
    assert len(inventory.assets) == 2


def test_identical_call_site_reported_twice_merges():
    inventory = merge([call_site("src/payments.py:10"), call_site("src/payments.py:10")])
    assert len(inventory.assets) == 1


def test_unsized_finding_is_absorbed_into_its_sized_twin():
    """generateKeyPairSync('rsa', {modulusLength: 2048}) matches two rules on one
    line — one resolves the key size, one does not."""
    sized = call_site("js/auth.js:21", key_size=2048)
    unsized = call_site("js/auth.js:21", key_size=None)
    inventory = merge([sized, unsized])
    assert len(inventory.assets) == 1
    assert inventory.assets[0].key_size == 2048


def test_confidence_is_promoted_by_independent_corroboration():
    a = library_asset(SourceType.DEPENDENCY, "manifest-parse", "requirements.txt")
    a.evidence[0].confidence = Confidence.MEDIUM
    b = library_asset(SourceType.BINARY, "binary-symbol", "usr/lib/libcrypto.so.3")
    b.evidence[0].confidence = Confidence.MEDIUM
    inventory = merge([a, b])
    assert len(inventory.assets) == 1
    assert inventory.assets[0].confidence is Confidence.HIGH


def test_single_technique_does_not_promote_confidence():
    a = library_asset(SourceType.DEPENDENCY, "manifest-parse", "a/requirements.txt")
    a.evidence[0].confidence = Confidence.MEDIUM
    b = library_asset(SourceType.CONTAINER, "manifest-parse", "img!b/requirements.txt")
    b.evidence[0].confidence = Confidence.MEDIUM
    inventory = merge([a, b])
    assert inventory.assets[0].confidence is Confidence.MEDIUM


def test_relationships_are_rewritten_onto_surviving_assets():
    sized = call_site("js/auth.js:21", key_size=2048)
    unsized = call_site("js/auth.js:21", key_size=None)
    library = library_asset(SourceType.DEPENDENCY, "manifest-parse", "package.json")
    inventory = merge([sized, unsized, library],
                      [Relationship(unsized.id, library.id, "depends-on")])
    assert len(inventory.relationships) == 1
    assert inventory.relationships[0].source_id == sized.id
    assert all(
        r.source_id in {a.id for a in inventory.assets}
        and r.target_id in {a.id for a in inventory.assets}
        for r in inventory.relationships
    )
