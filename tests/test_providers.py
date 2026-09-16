"""Module attribution, and the edges it puts in the asset graph.

The graph draws relationships, and before this the only ones available came from
certificate chains, negotiated protocols, container layers and dependency
manifests. A code repository produces none of those, so a scan of one drew a
field of disconnected points. A call site does know which module it called into,
and that is a real edge.

The risk in recording it is twofold, and both directions are tested here:
attributing the wrong module would draw a false edge in a blast-radius view, and
writing the module into `library` would silently change how call sites are
de-duplicated.
"""

from __future__ import annotations

import pytest

from cbom_compass.engine import attribute_providers, run_scan
from cbom_compass.models import Asset, AssetType, Confidence, Evidence, SourceType
from cbom_compass.policy import Policy
from cbom_compass.scanners.base import ScanResult
from cbom_compass.scanners.source import provider_for
from cbom_compass.verify import summarise, verify

APP = "samples/vulnerable-app"


@pytest.mark.parametrize("call, suffix, expected", [
    # Go: the standard library is rendered under its real import path, which is
    # what makes the node recognisable as something you can go and read.
    ("ecdsa.GenerateKey", ".go", "crypto/ecdsa"),
    ("elliptic.P256", ".go", "crypto/elliptic"),
    ("jose.NewSigner", ".go", "jose"),          # third party keeps its own name
    # Python resolves through import aliases before it reaches us.
    ("hashlib.sha256", ".py", "hashlib"),
    ("cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
     ".py", "cryptography"),
    ("Crypto.Cipher.AES.new", ".py", "Crypto"),
    # Java names the class at the call site, not the package it lives in.
    ("Cipher.getInstance", ".java", "javax.crypto"),
    ("MessageDigest.getInstance", ".java", "java.security"),
    ("crypto.createHash", ".js", "crypto"),
    # C has no namespaces, and spells the same library both ways.
    ("mbedtls_rsa_init", ".c", "mbedtls"),
    ("MBEDTLS_ECP_DP_SECP256R1", ".c", "mbedtls"),
    ("EVP_DigestInit", ".c", "openssl"),
    ("ECDSA_do_sign", ".c", "openssl"),         # not read as the shorter EC_
    ("crypto_box_keypair", ".c", "libsodium"),
])
def test_modules_are_attributed(call, suffix, expected):
    assert provider_for(call, suffix) == expected


@pytest.mark.parametrize("call, suffix", [
    ("sha256", ".py"),              # bare call, no import resolved it
    ("GenerateKey", ".go"),
    ("", ".py"),
    # OpenSSL's allocator is not libsodium, and a bare `crypto_` prefix would
    # have claimed it. An unattributed row is the correct answer.
    ("CRYPTO_malloc", ".c"),
    # Qualified, but by the receiver rather than by a module.
    ("self.cipher.encrypt", ".py"),
    ("cls._digest", ".py"),
    ("this.crypto.subtle.digest", ".js"),
])
def test_unattributable_calls_are_left_alone(call, suffix):
    """A wrong edge in a blast-radius view is worse than a missing one."""
    assert provider_for(call, suffix) is None


def test_call_sites_keep_their_own_identity():
    """`provider` must not behave like `library`.

    `identity_key` drops location for library-backed rows so one OpenSSL seen by
    three scanners collapses to one asset. The same RSA called from two files is
    the opposite case — two things to migrate — so attribution must leave the key
    alone.
    """
    def rsa(location: str) -> Asset:
        return Asset(
            algorithm="RSA", key_size=2048, provider="cryptography",
            location_class="call-site",
            evidence=[Evidence(SourceType.SOURCE_CODE, "python-ast", location,
                               Confidence.HIGH)],
        )

    assert rsa("payments.py:10").id != rsa("auth.py:22").id


def test_attribution_links_call_sites_to_one_module_node():
    combined = ScanResult()
    combined.assets = [
        Asset(algorithm="ECDSA", provider="crypto/ecdsa", location_class="call-site",
              evidence=[Evidence(SourceType.SOURCE_CODE, "pattern-go", "a.go:1",
                                 Confidence.MEDIUM)]),
        Asset(algorithm="ECDSA", provider="crypto/ecdsa", location_class="call-site",
              evidence=[Evidence(SourceType.SOURCE_CODE, "pattern-go", "b.go:2",
                                 Confidence.MEDIUM)]),
    ]

    attribute_providers(combined)

    entries = [a for a in combined.assets
               if a.asset_type == AssetType.RELATED_CRYPTO_MATERIAL]
    assert len(entries) == 1, "one node per module, not one per call site"
    assert entries[0].library == "crypto/ecdsa"
    assert len(combined.relationships) == 2
    assert {r.kind for r in combined.relationships} == {"depends-on"}
    assert all(r.target_id == entries[0].id for r in combined.relationships)


def test_a_declared_library_is_not_duplicated_by_attribution():
    """A dependency both declared and called is one asset with two kinds of
    evidence, not two rows disagreeing about the same library."""
    manifest_row = Asset(
        algorithm="cryptography", asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
        library="cryptography", library_version="42.0.5", location_class="manifest",
        evidence=[Evidence(SourceType.DEPENDENCY, "manifest-parse",
                           "requirements.txt", Confidence.HIGH)],
    )
    combined = ScanResult()
    combined.assets = [
        manifest_row,
        Asset(algorithm="RSA", provider="cryptography", location_class="call-site",
              evidence=[Evidence(SourceType.SOURCE_CODE, "python-ast", "app.py:3",
                                 Confidence.HIGH)]),
    ]

    attribute_providers(combined)

    entries = [a for a in combined.assets
               if a.asset_type == AssetType.RELATED_CRYPTO_MATERIAL]
    assert len(entries) == 1
    assert entries[0].library_version == "42.0.5", "the declared version survived"
    assert combined.relationships[0].target_id == manifest_row.id


def test_a_scanned_repository_has_a_graph_to_draw():
    report = run_scan({"source": [APP], "dependencies": [APP]},
                      Policy.load(f"{APP}/crypto-policy.yaml")).to_dict()
    assert report["relationships"], "a source scan should now produce edges"


def test_attributed_modules_are_verifiable_from_disk():
    """The inference is still held to the same standard as everything else: the
    import has to actually be in the file."""
    report = run_scan({"source": [APP], "dependencies": [APP]},
                      Policy.load(f"{APP}/crypto-policy.yaml")).to_dict()
    attributed = [a for a in report["assets"]
                  if "import-attribution" in a["detection_methods"]]
    assert attributed, "the sample app imports crypto modules"

    result = summarise(verify({**report, "assets": attributed}, [APP], sample=0))
    assert result["unconfirmed"] == 0


def test_a_module_the_file_never_imports_is_rejected():
    report = run_scan({"source": [APP], "dependencies": [APP]},
                      Policy.load(f"{APP}/crypto-policy.yaml")).to_dict()
    attributed = [a for a in report["assets"]
                  if "import-attribution" in a["detection_methods"]]
    fabricated = [{**a, "library": "libsodium", "algorithm": "libsodium"}
                  for a in attributed]

    result = summarise(verify({**report, "assets": fabricated}, [APP], sample=0))
    assert result["confirmed"] == 0, "verification that cannot fail proves nothing"
