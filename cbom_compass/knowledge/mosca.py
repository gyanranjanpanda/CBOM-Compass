"""Mosca input defaults — PRD v1.1 section 6.3.

No static analyser can know that a given AES call protects 25-year defence
secrets. X and criticality are business facts, and Y is an engineering estimate.
This module holds the defaults used when nothing is tagged, and every value it
returns is marked `assumed` / `estimated` so the UI can badge it.
"""

from __future__ import annotations

# X — data lifetime in years, by data classification.
DATA_CLASS_X = {
    "ephemeral": 0.1,
    "operational": 3.0,
    "financial": 7.0,
    "pii": 10.0,
    "health": 20.0,
    "regulated": 25.0,
    "defence": 25.0,
}
DEFAULT_DATA_CLASS = "financial"   # -> 7y, marked assumed

# Data classes whose confidentiality outlives any plausible Q-Day, so recorded
# traffic is worth harvesting today.
HNDL_DATA_CLASSES = {"pii", "health", "regulated", "defence", "financial"}
HNDL_MIN_X_YEARS = 5.0

# Y — migration time in years, keyed by (asset_type, deployment_surface).
# Deliberately not derived from dependency depth: a deeply-nested dependency is
# often *easier* to fix (bump a version) than a shallow one (rewrite in-house
# protocol code), so depth is a poor proxy for effort.
Y_RULE_TABLE = {
    ("algorithm", "internal-service"): 0.5,
    ("algorithm", "containerised"): 0.5,
    ("algorithm", "public-api"): 2.0,
    ("algorithm", "third-party-saas"): 3.0,
    ("algorithm", "embedded"): 5.0,
    ("certificate", "internal-service"): 0.25,
    ("certificate", "containerised"): 0.25,
    ("certificate", "public-api"): 1.0,
    ("certificate", "third-party-saas"): 2.0,
    ("certificate", "embedded"): 5.0,
    ("protocol", "internal-service"): 1.0,
    ("protocol", "containerised"): 1.0,
    ("protocol", "public-api"): 2.5,
    ("protocol", "third-party-saas"): 3.0,
    ("protocol", "embedded"): 5.0,
    # Hardware-resident keys and certificates are listed explicitly rather than
    # falling through to DEFAULT_Y, because the related-crypto-material asset
    # type is what a key object actually is.
    ("related-crypto-material", "internal-service"): 0.5,
    ("related-crypto-material", "containerised"): 0.5,
    ("related-crypto-material", "public-api"): 1.0,
    ("related-crypto-material", "third-party-saas"): 2.0,
    ("related-crypto-material", "embedded"): 5.0,
}
DEFAULT_SURFACE = "internal-service"
DEFAULT_Y = 1.5

# Location classes map onto a default deployment surface when untagged.
#
# `hardware-module` is the one that is not obvious. A key confined to an HSM or
# a TPM cannot be re-issued by an application team: the token must first ship
# firmware that implements ML-KEM or ML-DSA, and that is a vendor release cycle,
# a re-certification, and a physical change window. That is the same shape of
# dependency as embedded firmware, so it shares the embedded estimate — an HSM
# makes a key harder to migrate, not easier, even though it makes it harder to
# steal. Cloud KMS keys are deliberately *not* treated this way: AWS already
# exposes ML-DSA parameter sets, so a managed key rotates on request.
LOCATION_SURFACE = {
    "call-site": "internal-service",
    "manifest": "internal-service",
    "linked-library": "internal-service",
    "image-layer": "containerised",
    "negotiated": "public-api",
    "key-store": "internal-service",
    "hardware-module": "embedded",
    "config": "internal-service",
    # A leaf certificate is re-issued and deployed. A certificate *authority*
    # has its public key pinned in trust stores, baked into firmware and
    # distributed to every relying party, so replacing it is a redistribution
    # exercise, not a deployment. Saying a root CA is as easy to replace as a
    # web server certificate is the most misleading thing this tool could tell
    # a PKI owner.
    "certificate-store": "internal-service",
    "certificate-authority": "embedded",
}


def default_x(data_class: str | None) -> tuple[float, str]:
    """Return (X years, provenance)."""
    if data_class and data_class.lower() in DATA_CLASS_X:
        return DATA_CLASS_X[data_class.lower()], "tagged"
    return DATA_CLASS_X[DEFAULT_DATA_CLASS], "assumed"


def default_y(asset_type: str, location_class: str,
              surface: str | None = None) -> tuple[float, str]:
    """Return (Y years, provenance) from the rule table."""
    if surface:
        key = (asset_type, surface)
        if key in Y_RULE_TABLE:
            return Y_RULE_TABLE[key], "tagged"
    inferred = LOCATION_SURFACE.get(location_class, DEFAULT_SURFACE)
    return Y_RULE_TABLE.get((asset_type, inferred), DEFAULT_Y), "estimated"


def hndl(data_class: str | None, x_years: float) -> bool:
    """Harvest-now-decrypt-later: does this data outlive a plausible Q-Day?"""
    if data_class and data_class.lower() in HNDL_DATA_CLASSES:
        return True
    return x_years >= HNDL_MIN_X_YEARS
