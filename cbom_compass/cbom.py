"""CycloneDX 1.7 CBOM export — PRD v1.1 sections 6.1 and 9.

Targets CycloneDX 1.7 (ratified as ECMA-424, 2nd Edition, December 2025), not
the 1.6 / 1st Edition the original PRD assumed.

Asset and Relationship serialise into the standard payload. Risk classification
and Recommendation are CBOM Compass extensions carried in `properties` under a
`cbom-compass:` namespace — *except* where the schema already provides a field.
`nistQuantumSecurityLevel` is native to algorithmProperties, so we populate it
natively rather than duplicating it into an extension.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from . import __version__
from .knowledge import algorithms as kb
from .models import (Asset, AssetType, QuantumStatus, Recommendation,
                     Relationship, RiskClassification)

SPEC_VERSION = "1.7"

# Approximate classical security level in bits, for algorithmProperties.
CLASSICAL_BITS = {
    ("RSA", 1024): 80, ("RSA", 2048): 112, ("RSA", 3072): 128, ("RSA", 4096): 152,
    ("AES", 128): 128, ("AES", 192): 192, ("AES", 256): 256,
    ("3DES", None): 112, ("DES", None): 56, ("RC4", None): 40,
    ("SHA-1", None): 63, ("SHA-256", None): 128, ("SHA-384", None): 192,
    ("SHA-512", None): 256, ("MD5", None): 18, ("ChaCha20", None): 256,
}
CURVE_BITS = {"secp192r1": 96, "secp256r1": 128, "secp384r1": 192, "secp521r1": 256}

CRYPTO_FUNCTIONS = {
    "pke": ["keygen", "encrypt", "decrypt", "sign", "verify"],
    "signature": ["keygen", "sign", "verify"],
    "kem": ["keygen", "encapsulate", "decapsulate"],
    "key-agree": ["keygen", "keyderive"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
    "hash": ["digest"],
    "mac": ["tag"],
    "kdf": ["keyderive"],
}

OIDS = {
    "RSA": "1.2.840.113549.1.1.1", "ECDSA": "1.2.840.10045.2.1",
    "DSA": "1.2.840.10040.4.1", "DH": "1.2.840.113549.1.3.1",
    "AES": "2.16.840.1.101.3.4.1", "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2", "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA-1": "1.3.14.3.2.26", "MD5": "1.2.840.113549.2.5",
    "3DES": "1.2.840.113549.3.7", "DES": "1.3.14.3.2.7",
    "ML-KEM": "2.16.840.1.101.3.4.4", "ML-DSA": "2.16.840.1.101.3.4.3.17",
}


def _classical_bits(asset: Asset) -> int | None:
    curve = asset.parameters.get("curve")
    if curve and curve in CURVE_BITS:
        return CURVE_BITS[curve]
    return CLASSICAL_BITS.get((asset.algorithm, asset.key_size)) or \
        CLASSICAL_BITS.get((asset.algorithm, None))


def _props(pairs: dict) -> list[dict]:
    return [{"name": k, "value": str(v)} for k, v in pairs.items() if v not in (None, "", [])]


def _component(asset: Asset, risk: RiskClassification | None,
               reco: Recommendation | None) -> dict:
    cls = kb.classify(asset.algorithm, asset.key_size, asset.parameters)
    component: dict = {
        "type": "cryptographic-asset",
        "bom-ref": asset.id,
        "name": asset.display_name,
        "cryptoProperties": {"assetType": asset.asset_type.value},
    }

    if asset.asset_type == AssetType.ALGORITHM:
        algorithm_props: dict = {
            "primitive": cls.primitive or "other",
            "executionEnvironment": "software-plain-ram",
            "implementationPlatform": "generic",
            "certificationLevel": ["none"],
            "cryptoFunctions": CRYPTO_FUNCTIONS.get(cls.primitive or "", ["other"]),
        }
        param_set = asset.parameters.get("parameter_set") or (
            str(asset.key_size) if asset.key_size else None)
        if param_set:
            algorithm_props["parameterSetIdentifier"] = param_set
        if asset.parameters.get("curve"):
            algorithm_props["curve"] = asset.parameters["curve"]
        if asset.parameters.get("mode"):
            algorithm_props["mode"] = asset.parameters["mode"].lower()
        if asset.parameters.get("padding"):
            algorithm_props["padding"] = asset.parameters["padding"].lower()
        bits = _classical_bits(asset)
        if bits:
            algorithm_props["classicalSecurityLevel"] = bits
        # Native schema field — not duplicated into our extension namespace.
        if cls.nist_quantum_security_level is not None:
            algorithm_props["nistQuantumSecurityLevel"] = cls.nist_quantum_security_level
        component["cryptoProperties"]["algorithmProperties"] = algorithm_props
        if asset.algorithm in OIDS:
            component["cryptoProperties"]["oid"] = OIDS[asset.algorithm]

    elif asset.asset_type == AssetType.CERTIFICATE and asset.certificate:
        cert = asset.certificate
        cert_props = {
            "subjectName": cert.get("subject"),
            "issuerName": cert.get("issuer"),
            "notValidBefore": cert.get("not_before"),
            "notValidAfter": cert.get("not_after"),
            "certificateFormat": "X.509",
            "signatureAlgorithmRef": asset.algorithm,
        }
        component["cryptoProperties"]["certificateProperties"] = {
            k: v for k, v in cert_props.items() if v
        }

    elif asset.asset_type == AssetType.PROTOCOL:
        version = asset.algorithm.replace("TLSv", "").replace("TLS", "").strip()
        protocol_props = {"type": "tls", "version": version or "unknown"}
        suite = asset.parameters.get("cipher_suite")
        if suite:
            protocol_props["cipherSuites"] = [{"name": suite}]
        component["cryptoProperties"]["protocolProperties"] = protocol_props

    elif asset.asset_type == AssetType.RELATED_CRYPTO_MATERIAL:
        material = asset.parameters.get("material", "unknown")
        component["cryptoProperties"]["relatedCryptoMaterialProperties"] = {
            "type": "private-key" if material == "private-key" else "unknown",
        }

    if asset.library:
        component["publisher"] = asset.library
        if asset.library_version:
            component["version"] = asset.library_version

    component["evidence"] = {
        "occurrences": [
            {"location": ev.location,
             "additionalContext": f"[{ev.detection_method}/{ev.confidence.value}] "
                                  f"{ev.snippet or ''}".strip()}
            for ev in asset.evidence
        ]
    }

    # --- CBOM Compass extension namespace -------------------------------
    extension: dict = {
        "cbom-compass:confidence": asset.confidence.value,
        "cbom-compass:detectionMethods": ",".join(asset.detection_methods),
        "cbom-compass:sourceTypes": ",".join(asset.source_types),
        "cbom-compass:locationClass": asset.location_class,
    }
    if risk:
        extension.update({
            "cbom-compass:quantumStatus": risk.quantum_status.value,
            "cbom-compass:rationale": risk.rationale,
            "cbom-compass:harvestNowDecryptLater": str(risk.hndl_flag).lower(),
            "cbom-compass:regulatoryFlags": ",".join(risk.regulatory_flags),
            "cbom-compass:mosca.X": risk.x_years,
            "cbom-compass:mosca.X.source": risk.x_source,
            "cbom-compass:mosca.Y": risk.y_years,
            "cbom-compass:mosca.Y.source": risk.y_source,
            "cbom-compass:mosca.Z.year": risk.z_year_used,
            "cbom-compass:mosca.exposureGap": risk.exposure_gap,
            "cbom-compass:criticality": risk.criticality.value,
            "cbom-compass:priorityScore": risk.score,
            "cbom-compass:urgencyBand": risk.urgency_band,
        })
    if reco:
        extension.update({
            "cbom-compass:recommendation.standard": reco.standard,
            "cbom-compass:recommendation.algorithm": reco.algorithm,
            "cbom-compass:recommendation.hybrid": str(reco.hybrid).lower(),
            "cbom-compass:recommendation.maturity": reco.maturity,
            "cbom-compass:recommendation.rotationCost": reco.rotation_cost,
        })
    component["properties"] = _props(extension)
    return component


def build(assets: list[Asset], relationships: list[Relationship],
          risks: dict[str, RiskClassification] | None = None,
          recommendations: dict[str, Recommendation] | None = None,
          target_scope: list[str] | None = None,
          label: str = "") -> dict:
    risks = risks or {}
    recommendations = recommendations or {}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    components = [_component(a, risks.get(a.id), recommendations.get(a.id)) for a in assets]

    dependencies: dict[str, set[str]] = {a.id: set() for a in assets}
    for rel in relationships:
        dependencies.setdefault(rel.source_id, set()).add(rel.target_id)

    counts: dict[str, int] = {}
    for risk in risks.values():
        counts[risk.quantum_status.value] = counts.get(risk.quantum_status.value, 0) + 1

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "CBOM Compass",
                    "version": __version__,
                    "description": "Cryptographic inventory and post-quantum readiness platform",
                }]
            },
            "component": {
                # What was scanned, as a reader would name it. Falls back to the
                # raw scope for local paths, which are already meaningful.
                "type": "application",
                "bom-ref": "target",
                "name": label or ", ".join(target_scope or ["scan-target"]),
            },
            "properties": _props({
                "cbom-compass:assetCount": len(assets),
                "cbom-compass:statusCounts": ";".join(f"{k}={v}" for k, v in sorted(counts.items())),
            }),
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(deps)}
            for ref, deps in sorted(dependencies.items()) if deps
        ],
    }


def validate(document: dict) -> list[str]:
    """Structural conformance check — PRD section 13 success metric.

    Not a full JSON-Schema validation (that needs the published schema as a data
    dependency); it checks the required fields and the enumerated values this
    tool emits.
    """
    errors: list[str] = []
    if document.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    if document.get("specVersion") != SPEC_VERSION:
        errors.append(f"specVersion must be '{SPEC_VERSION}'")
    if not str(document.get("serialNumber", "")).startswith("urn:uuid:"):
        errors.append("serialNumber must be a urn:uuid")
    if not isinstance(document.get("version"), int):
        errors.append("version must be an integer")
    if "timestamp" not in document.get("metadata", {}):
        errors.append("metadata.timestamp is required")

    valid_asset_types = {t.value for t in AssetType}
    valid_primitives = {
        "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
        "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
    }
    refs = set()
    for i, component in enumerate(document.get("components", [])):
        where = f"components[{i}]"
        if component.get("type") != "cryptographic-asset":
            errors.append(f"{where}.type must be 'cryptographic-asset'")
        ref = component.get("bom-ref")
        if not ref:
            errors.append(f"{where}.bom-ref is required")
        elif ref in refs:
            errors.append(f"{where}.bom-ref '{ref}' is not unique")
        refs.add(ref)
        crypto = component.get("cryptoProperties", {})
        if crypto.get("assetType") not in valid_asset_types:
            errors.append(f"{where}.cryptoProperties.assetType invalid: {crypto.get('assetType')}")
        algorithm_props = crypto.get("algorithmProperties")
        if algorithm_props:
            if algorithm_props.get("primitive") not in valid_primitives:
                errors.append(f"{where} primitive invalid: {algorithm_props.get('primitive')}")
            level = algorithm_props.get("nistQuantumSecurityLevel")
            if level is not None and level not in range(0, 7):
                errors.append(f"{where} nistQuantumSecurityLevel out of range: {level}")

    for i, dep in enumerate(document.get("dependencies", [])):
        if dep.get("ref") not in refs:
            errors.append(f"dependencies[{i}].ref '{dep.get('ref')}' has no component")
        for target in dep.get("dependsOn", []):
            if target not in refs:
                errors.append(f"dependencies[{i}].dependsOn '{target}' has no component")
    return errors
