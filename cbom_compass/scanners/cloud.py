"""Cloud and HSM key-store scanner — PRD v1.1 section 6.1, source type six.

Two providers:

  ``aws://<region>``        AWS KMS via boto3, using read-only APIs only.
  ``file://<path>``         A key-store export as JSON. This is the sample
                            environment mode PRD section 13 asks for: judges
                            will not hand over production cloud credentials, and
                            the tool must still demonstrate this source type.

Section 10 constrains what this may do. It calls ``ListKeys``, ``DescribeKey``
and ``GetKeyRotationStatus`` — metadata only. It never calls ``Decrypt``,
``Sign``, ``GetPublicKey`` or anything else that touches key material, and it
records no key material of any kind. If a connector needs more than describe
permissions, that is a bug in the connector, not a missing IAM grant.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Asset, AssetType, Confidence, Evidence, SourceType
from .base import ScanError, ScanResult, Scanner

# The read-only API surface this scanner is allowed to use. Kept as data so the
# constraint is testable rather than a comment nobody checks.
ALLOWED_AWS_CALLS = {"list_keys", "describe_key", "get_key_rotation_status", "list_aliases"}

# AWS KMS KeySpec -> (algorithm, key size, parameters)
AWS_KEY_SPECS: dict[str, tuple[str, int | None, dict[str, Any]]] = {
    "SYMMETRIC_DEFAULT": ("AES", 256, {"mode": "GCM"}),
    "RSA_2048": ("RSA", 2048, {}),
    "RSA_3072": ("RSA", 3072, {}),
    "RSA_4096": ("RSA", 4096, {}),
    "ECC_NIST_P256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "ECC_NIST_P384": ("ECDSA", 384, {"curve": "secp384r1"}),
    "ECC_NIST_P521": ("ECDSA", 521, {"curve": "secp521r1"}),
    "ECC_SECG_P256K1": ("ECDSA", 256, {"curve": "secp256k1"}),
    "HMAC_224": ("HMAC", 224, {}),
    "HMAC_256": ("HMAC", 256, {}),
    "HMAC_384": ("HMAC", 384, {}),
    "HMAC_512": ("HMAC", 512, {}),
    "SM2": ("ECDSA", 256, {"curve": "sm2p256v1"}),
    "ML_DSA_44": ("ML-DSA", None, {"parameter_set": "ML-DSA-44"}),
    "ML_DSA_65": ("ML-DSA", None, {"parameter_set": "ML-DSA-65"}),
    "ML_DSA_87": ("ML-DSA", None, {"parameter_set": "ML-DSA-87"}),
}

# Azure Key Vault / GCP KMS spellings, for the file provider.
GENERIC_KEY_SPECS: dict[str, tuple[str, int | None, dict[str, Any]]] = {
    **AWS_KEY_SPECS,
    "RSA-HSM": ("RSA", 2048, {}), "RSA": ("RSA", 2048, {}),
    "EC-HSM": ("ECDSA", 256, {}), "EC": ("ECDSA", 256, {}),
    "oct-HSM": ("AES", 256, {}), "oct": ("AES", 256, {}),
    "GOOGLE_SYMMETRIC_ENCRYPTION": ("AES", 256, {"mode": "GCM"}),
    "RSA_SIGN_PKCS1_2048_SHA256": ("RSA", 2048, {"padding": "PKCS1v15"}),
    "RSA_SIGN_PSS_3072_SHA256": ("RSA", 3072, {"padding": "PSS"}),
    "EC_SIGN_P256_SHA256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "EC_SIGN_P384_SHA384": ("ECDSA", 384, {"curve": "secp384r1"}),
}


class CloudScanner(Scanner):
    source_type = SourceType.CLOUD_KMS
    name = "cloud"

    def __init__(self, policy=None, client_factory=None) -> None:
        super().__init__(policy)
        # Injectable so the AWS mapping is testable without credentials.
        self._client_factory = client_factory

    def scan(self, target: str) -> ScanResult:
        if target.startswith("aws://"):
            return self._scan_aws(target[len("aws://"):] or "us-east-1", target)
        if target.startswith("file://"):
            return self._scan_file(target[len("file://"):], target)
        path = Path(target)
        if path.exists() and path.suffix == ".json":
            return self._scan_file(target, target)
        result = ScanResult()
        result.errors.append(ScanError(
            "cloud_kms", target,
            "unrecognised key store. Use aws://<region> or file://<path-to-export.json>"))
        return result

    # ------------------------------------------------------------------- AWS
    def _scan_aws(self, region: str, target: str) -> ScanResult:
        result = ScanResult()
        if not self.policy.target_allowed(f"aws:{region}") and \
                not self.policy.target_allowed(region):
            result.errors.append(ScanError(
                "cloud_kms", target,
                f"refused: aws:{region} is not in the scan allowlist. Add it to "
                f"crypto-policy.yaml under scanning.allowlist with a recorded "
                f"authorization attestation before connecting."))
            return result
        try:
            client = self._client(region)
        except Exception as exc:
            result.errors.append(ScanError("cloud_kms", target, f"could not connect: {exc}"))
            return result

        try:
            keys: list[dict] = []
            paginator_keys = client.list_keys()
            keys.extend(paginator_keys.get("Keys", []))
            while paginator_keys.get("NextMarker"):
                paginator_keys = client.list_keys(Marker=paginator_keys["NextMarker"])
                keys.extend(paginator_keys.get("Keys", []))
        except Exception as exc:
            result.errors.append(ScanError("cloud_kms", target, f"list_keys failed: {exc}"))
            return result

        for entry in keys:
            key_id = entry.get("KeyId")
            try:
                metadata = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
            except Exception as exc:
                result.errors.append(ScanError("cloud_kms", str(key_id), f"describe_key: {exc}"))
                continue
            rotation = None
            try:
                rotation = client.get_key_rotation_status(
                    KeyId=key_id).get("KeyRotationEnabled")
            except Exception:
                rotation = None       # not permitted on every key type; not fatal
            asset = self._key_asset(
                metadata, provider="aws", region=region, rotation_enabled=rotation,
                specs=AWS_KEY_SPECS)
            if asset is not None:
                result.assets.append(asset)
        return result

    def _client(self, region: str):
        if self._client_factory is not None:
            return self._client_factory(region)
        import boto3      # imported lazily so boto3 stays an optional dependency

        return boto3.client("kms", region_name=region)

    # ------------------------------------------------------------------ file
    def _scan_file(self, path_str: str, target: str) -> ScanResult:
        """A key-store export. Shape:

            {"provider": "azure", "location": "vault-prod",
             "keys": [{"KeyId": ..., "KeySpec": ..., "KeyUsage": ...,
                       "Enabled": true, "RotationEnabled": false}]}
        """
        result = ScanResult()
        path = Path(path_str)
        if not path.exists():
            result.errors.append(ScanError("cloud_kms", target, "export file not found"))
            return result
        try:
            document = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            result.errors.append(ScanError("cloud_kms", target, f"invalid JSON: {exc}"))
            return result

        provider = document.get("provider", "unknown")
        location = document.get("location", path.name)
        for entry in document.get("keys", []):
            asset = self._key_asset(
                entry, provider=provider, region=location,
                rotation_enabled=entry.get("RotationEnabled"), specs=GENERIC_KEY_SPECS)
            if asset is not None:
                # Record where this came from so the finding can be re-verified
                # against the export rather than taken on trust.
                asset.evidence[0].detail["source_path"] = str(path)
                result.assets.append(asset)
        return result

    # ---------------------------------------------------------------- shared
    def _key_asset(self, metadata: dict, provider: str, region: str,
                   rotation_enabled: bool | None,
                   specs: dict[str, tuple]) -> Asset | None:
        spec = metadata.get("KeySpec") or metadata.get("CustomerMasterKeySpec")
        key_id = metadata.get("KeyId") or metadata.get("Arn") or "unknown"
        if not spec:
            return None
        mapped = specs.get(spec)
        if mapped is None:
            algorithm, key_size, parameters = spec, None, {}
        else:
            algorithm, key_size, parameters = mapped
            parameters = dict(parameters)

        origin = metadata.get("Origin", "")
        hsm_backed = origin in {"AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"} or "HSM" in str(spec)
        location = f"{provider}:{region}/{key_id}"

        detail = {
            "key_id": key_id,
            "key_usage": metadata.get("KeyUsage"),
            "origin": origin or None,
            "enabled": metadata.get("Enabled"),
            "rotation_enabled": rotation_enabled,
            "hsm_backed": hsm_backed,
            "key_spec": spec,
        }
        notes = []
        if rotation_enabled is False:
            notes.append("automatic key rotation is disabled")
        if metadata.get("Enabled") is False:
            notes.append("key is disabled but still present")
        if notes:
            detail["notes"] = notes

        return Asset(
            algorithm=algorithm, asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            key_size=key_size, parameters={**parameters, "material": "managed-key"},
            location_class="key-store",
            evidence=[Evidence(
                self.source_type, f"{provider}-kms-describe", location, Confidence.HIGH,
                f"{spec} ({metadata.get('KeyUsage', 'unknown usage')})"
                + (", HSM-backed" if hsm_backed else "")
                + (f" — {'; '.join(notes)}" if notes else ""),
                detail,
            )],
        )
