"""Recommendation engine — PRD v1.1 section 6.4.

Names specific standards, never "quantum-safe crypto" generically, and ranks
candidates by the five criteria in the PRD: risk score, latency/bandwidth
budget, library and hardware support maturity, compliance regime, and rotation
cost.

Two things the v1.0 table omitted and this engine does not:
  * SP 800-208 LMS/XMSS is the answer for firmware and code signing, and is what
    CNSA 2.0 actually mandates there.
  * Signature sizes differ by two orders of magnitude between FN-DSA (~666 B),
    ML-DSA (~2420 B) and SLH-DSA (~7856 B), which is what makes the bandwidth
    criterion actually discriminate.
"""

from __future__ import annotations

from .models import (Asset, AssetType, QuantumStatus, Recommendation,
                     Relationship, RiskClassification)
from .policy import Policy

# Sizes in bytes, used by the latency/bandwidth criterion.
SIZES = {
    "ML-KEM-768": {"public_key": 1184, "ciphertext": 1088},
    "ML-KEM-1024": {"public_key": 1568, "ciphertext": 1568},
    "ML-DSA-65": {"public_key": 1952, "signature": 3309},
    "ML-DSA-87": {"public_key": 2592, "signature": 4627},
    "SLH-DSA-SHA2-128s": {"public_key": 32, "signature": 7856},
    "FN-DSA-512": {"public_key": 897, "signature": 666},
    "RSA-2048": {"public_key": 256, "signature": 256},
    "ECDSA-P-256": {"public_key": 64, "signature": 64},
}

SIGNING_HINTS = ("sign", "signature", "jwt", "jws", "cert", "ca", "token", "code", "verify")
FIRMWARE_HINTS = ("firmware", "boot", "image-signing", "ota", "bootloader")
EMBEDDED_HINTS = ("embedded", "iot", "device", "sensor", "field")


def _context(asset: Asset) -> set[str]:
    blob = " ".join(
        [asset.primary_location] + [ev.snippet or "" for ev in asset.evidence]
    ).lower()
    tags = set()
    if any(h in blob for h in SIGNING_HINTS):
        tags.add("signing")
    if any(h in blob for h in FIRMWARE_HINTS):
        tags.add("firmware")
    if any(h in blob for h in EMBEDDED_HINTS):
        tags.add("embedded")
    return tags


def _rotation_cost(asset_id: str, relationships: list[Relationship]) -> tuple[str, list[str]]:
    """Cost of reissuing this key/cert across its dependents — in-edges of the graph."""
    dependents = [r.source_id for r in relationships if r.target_id == asset_id]
    if len(dependents) >= 10:
        return "high", dependents[:10]
    if len(dependents) >= 3:
        return "medium", dependents
    return "low", dependents


def recommend_asset(asset: Asset, risk: RiskClassification,
                    relationships: list[Relationship] | None = None,
                    policy: Policy | None = None) -> Recommendation:
    relationships = relationships or []
    policy = policy or Policy()
    rotation_cost, blocking = _rotation_cost(asset.id, relationships)
    context = _context(asset)
    cnsa = policy.cnsa2_required
    notes: list[str] = []

    if asset.parameters.get("mode") == "ECB":
        notes.append("ECB mode leaks plaintext structure — switch to GCM regardless of PQC.")

    if asset.parameters.get("usedforsecurity") is False:
        return Recommendation(
            asset.id, "no change", asset.algorithm, False, "final",
            risk.rationale, rotation_cost, "production", blocking,
            notes + ["If this digest ever becomes security-relevant, drop the "
                     "usedforsecurity=False flag and it will be scored."])

    if risk.quantum_status == QuantumStatus.NOT_APPLICABLE:
        return Recommendation(
            asset.id, "no change", asset.library or asset.algorithm, False, "final",
            risk.rationale, rotation_cost, "production", blocking, notes)

    if asset.parameters.get("material") == "private-key":
        return Recommendation(
            asset.id, "operational", "rotate and remove from image", False, "final",
            "Private key material must not ship inside a container image. Rotate the key, "
            "remove it from the build context, and inject it at runtime from a secret store.",
            "high", "production", blocking,
            notes + ["Treat any key that has shipped in an image as compromised."])

    # --- already post-quantum ------------------------------------------
    if risk.quantum_status == QuantumStatus.ADEQUATE and asset.algorithm in {
        "ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC", "LMS", "XMSS"
    }:
        return Recommendation(
            asset.id, "no change", asset.algorithm, False, "final",
            "Already a post-quantum standard.", rotation_cost, "production", blocking, notes)

    # --- classically broken / deprecated: not a PQC problem -------------
    if risk.quantum_status in {QuantumStatus.BROKEN_CLASSICAL,
                               QuantumStatus.DEPRECATED_INSUFFICIENT}:
        replacement = {
            "MD5": "SHA-256", "SHA-1": "SHA-256", "DES": "AES-256", "3DES": "AES-256",
            "RC4": "AES-256-GCM", "RC2": "AES-256-GCM", "Blowfish": "AES-256-GCM",
            "SHA-224": "SHA-256",
        }.get(asset.algorithm, "AES-256-GCM")
        return Recommendation(
            asset.id, "FIPS 197 / FIPS 180-4", replacement, False, "final",
            f"{asset.algorithm} is weak on classical grounds. Replace with {replacement} now — "
            f"this is independent of the PQC timeline and should not wait for it.",
            rotation_cost, "production", blocking, notes)

    # --- symmetric and hash: adequate, policy only ----------------------
    if risk.quantum_status == QuantumStatus.ADEQUATE:
        if cnsa and asset.algorithm == "AES" and (asset.key_size or 128) < 256:
            return Recommendation(
                asset.id, "CNSA 2.0", "AES-256", False, "final",
                "AES-128 is not broken and Grover does not practically threaten it. This is a "
                "CNSA 2.0 policy requirement for AES-256, not a quantum remediation.",
                rotation_cost, "production", blocking, notes)
        if cnsa and asset.algorithm.startswith("SHA") and asset.algorithm in {"SHA-256", "SHA3-256"}:
            return Recommendation(
                asset.id, "CNSA 2.0", "SHA-384", False, "final",
                "SHA-256 remains adequate post-quantum. CNSA 2.0 requires SHA-384 as policy.",
                rotation_cost, "production", blocking, notes)
        return Recommendation(
            asset.id, "no change", asset.algorithm, False, "final",
            risk.rationale, rotation_cost, "production", blocking, notes)

    if asset.asset_type == AssetType.PROTOCOL:
        return Recommendation(
            asset.id, "RFC 8996 / TLS 1.3", "TLS 1.3", False, "final",
            "Upgrade to TLS 1.3 and disable the deprecated versions. The post-quantum work "
            "for this endpoint is in its key exchange (hybrid X25519+ML-KEM-768), which is "
            "inventoried as a separate asset.",
            rotation_cost, "production", blocking, notes)

    # --- Shor-broken public key ----------------------------------------
    signing = "signing" in context or asset.algorithm in {"ECDSA", "DSA", "EdDSA"} \
        or asset.asset_type == AssetType.CERTIFICATE

    if signing:
        if "firmware" in context:
            return Recommendation(
                asset.id, "SP 800-208", "LMS (or XMSS)", False, "final",
                "Firmware and code signing is the one case where a stateful hash-based scheme "
                "is the right answer, and it is what CNSA 2.0 mandates there. Note that key "
                "state must never be reused — one-time signature state management is an "
                "operational requirement, not an implementation detail.",
                rotation_cost, "production", blocking,
                notes + ["Requires durable signature-state management."])
        if "embedded" in context:
            return Recommendation(
                asset.id, "FIPS 206 (draft)", "FN-DSA-512", True, "draft",
                f"Bandwidth-constrained signing. FN-DSA signatures are ~{SIZES['FN-DSA-512']['signature']} B "
                f"against ML-DSA-65's ~{SIZES['ML-DSA-65']['signature']} B and SLH-DSA's "
                f"~{SIZES['SLH-DSA-SHA2-128s']['signature']} B. FIPS 206 is not final — do not "
                f"ship this as a sole dependency yet.",
                rotation_cost, "experimental", blocking,
                notes + ["FN-DSA signing needs constant-time floating-point Gaussian sampling; "
                         "implementation risk is real.",
                         "Fall back to ML-DSA-44 if FN-DSA finalisation slips."])
        parameter_set = "ML-DSA-87" if cnsa else "ML-DSA-65"
        return Recommendation(
            asset.id, "FIPS 204", parameter_set, True, "final",
            f"{asset.algorithm} signatures are broken outright by Shor. ML-DSA is the "
            f"general-purpose replacement. Deploy hybrid ({asset.algorithm} + {parameter_set}) so "
            f"a break in either algorithm alone does not compromise the signature."
            + (" CNSA 2.0 requires the ML-DSA-87 parameter set." if cnsa else ""),
            rotation_cost, "production", blocking,
            notes + [f"Signature grows from ~{SIZES.get(f'{asset.algorithm}-P-256', {}).get('signature', 256)} B "
                     f"to ~{SIZES[parameter_set]['signature']} B.",
                     "Consider SLH-DSA (FIPS 205) instead for long-lived roots where a "
                     "conservative hash-based assumption is worth the larger signature."])

    # Key establishment.
    parameter_set = "ML-KEM-1024" if cnsa else "ML-KEM-768"
    return Recommendation(
        asset.id, "FIPS 203", parameter_set, True, "final",
        f"{asset.algorithm} key establishment is broken outright by Shor. ML-KEM is the "
        f"replacement. Default to the hybrid X25519+{parameter_set}, which is what Chrome and "
        f"Cloudflare already run in production TLS 1.3 — a break in either algorithm alone "
        f"leaves the connection intact."
        + (" CNSA 2.0 requires the ML-KEM-1024 parameter set." if cnsa else ""),
        rotation_cost, "production", blocking,
        notes + [f"Public key grows from ~{SIZES['RSA-2048']['public_key']} B to "
                 f"~{SIZES[parameter_set]['public_key']} B; negligible in a datacentre, "
                 f"significant on constrained links.",
                 "HQC is the standardisation-track backup KEM if a lattice break appears; "
                 "it is not final and should not be deployed yet."])


def recommend_all(assets: list[Asset], risks: dict[str, RiskClassification],
                  relationships: list[Relationship] | None = None,
                  policy: Policy | None = None) -> dict[str, Recommendation]:
    return {
        a.id: recommend_asset(a, risks[a.id], relationships, policy)
        for a in assets if a.id in risks
    }
