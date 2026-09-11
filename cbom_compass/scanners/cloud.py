"""Key-store scanner: cloud KMS and hardware modules — PRD v1.1 section 6.1.

Providers:

  ``aws://<region>``            AWS KMS via boto3.
  ``azure://<vault>``           Azure Key Vault via azure-keyvault-keys.
  ``gcp://<project>/<location>`` Google Cloud KMS via google-cloud-kms.
  ``pkcs11://<module.so>``      Any PKCS#11 hardware module — SoftHSM, Luna,
                                nCipher, Utimaco, YubiHSM, CloudHSM, tpm2-pkcs11.
  ``file://<path>``             A key-store export as JSON. The sample
                                environment mode PRD section 13 asks for: judges
                                will not hand over production cloud credentials
                                or plug in an HSM, and the tool must still
                                demonstrate this source type.

Every SDK is imported lazily, so none of them is a hard dependency and a machine
with only `pip install -e .` still runs the file provider.

Section 10 constrains what this may do, and the constraint is data rather than a
comment: `ALLOWED_AWS_CALLS`, `ALLOWED_AZURE_CALLS` and `ALLOWED_GCP_CALLS`
enumerate the complete read-only API surface, and the PKCS#11 reader carries its
own `READABLE_ATTRIBUTES` allowlist. Nothing here calls Decrypt, Sign, Unwrap or
GetSecret, and no key material of any kind is recorded. If a connector needs
more than describe permissions, that is a bug in the connector, not a missing
IAM grant.

One modelling decision is worth stating. A PKCS#11 key lands with
`location_class` ``hardware-module`` rather than ``key-store``, which routes it
to the long migration estimate in `knowledge/mosca.py`. That is deliberate: the
key cannot leave the token, so replacing it waits on vendor firmware shipping
PQC, which is a multi-year dependency and nothing an application team can
schedule. Cloud KMS keys stay on ``key-store`` — AWS already exposes ML-DSA
parameter sets, so a managed key is a fast migration, not a slow one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..models import Asset, AssetType, Confidence, Evidence, SourceType
from . import pkcs11 as p11
from .base import ScanError, ScanResult, Scanner

# The read-only API surface each connector is allowed to use. Kept as data so
# the constraint is testable rather than a comment nobody checks.
ALLOWED_AWS_CALLS = {"list_keys", "describe_key", "get_key_rotation_status", "list_aliases"}
ALLOWED_AZURE_CALLS = {"list_properties_of_keys", "get_key"}
ALLOWED_GCP_CALLS = {"list_key_rings", "list_crypto_keys", "list_crypto_key_versions"}

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

# Azure Key Vault key types and GCP KMS algorithm enums. Also used by the file
# provider so an export from any provider reads correctly.
GENERIC_KEY_SPECS: dict[str, tuple[str, int | None, dict[str, Any]]] = {
    **AWS_KEY_SPECS,
    # --- Azure Key Vault (JsonWebKeyType). The -HSM suffix is how Azure says
    # the key is confined to an HSM partition rather than software-protected.
    "RSA-HSM": ("RSA", 2048, {}), "RSA": ("RSA", 2048, {}),
    "EC-HSM": ("ECDSA", 256, {}), "EC": ("ECDSA", 256, {}),
    "oct-HSM": ("AES", 256, {}), "oct": ("AES", 256, {}),
    # --- GCP Cloud KMS (CryptoKeyVersionAlgorithm)
    "GOOGLE_SYMMETRIC_ENCRYPTION": ("AES", 256, {"mode": "GCM"}),
    "AES_128_GCM": ("AES", 128, {"mode": "GCM"}),
    "AES_256_GCM": ("AES", 256, {"mode": "GCM"}),
    "AES_128_CBC": ("AES", 128, {"mode": "CBC"}),
    "AES_256_CBC": ("AES", 256, {"mode": "CBC"}),
    "RSA_SIGN_PKCS1_2048_SHA256": ("RSA", 2048, {"padding": "PKCS1v15"}),
    "RSA_SIGN_PKCS1_3072_SHA256": ("RSA", 3072, {"padding": "PKCS1v15"}),
    "RSA_SIGN_PKCS1_4096_SHA256": ("RSA", 4096, {"padding": "PKCS1v15"}),
    "RSA_SIGN_PKCS1_4096_SHA512": ("RSA", 4096, {"padding": "PKCS1v15"}),
    "RSA_SIGN_PSS_2048_SHA256": ("RSA", 2048, {"padding": "PSS"}),
    "RSA_SIGN_PSS_3072_SHA256": ("RSA", 3072, {"padding": "PSS"}),
    "RSA_SIGN_PSS_4096_SHA256": ("RSA", 4096, {"padding": "PSS"}),
    "RSA_SIGN_RAW_PKCS1_2048": ("RSA", 2048, {"padding": "PKCS1v15"}),
    "RSA_DECRYPT_OAEP_2048_SHA256": ("RSA", 2048, {"padding": "OAEP"}),
    "RSA_DECRYPT_OAEP_3072_SHA256": ("RSA", 3072, {"padding": "OAEP"}),
    "RSA_DECRYPT_OAEP_4096_SHA256": ("RSA", 4096, {"padding": "OAEP"}),
    "EC_SIGN_P256_SHA256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "EC_SIGN_P384_SHA384": ("ECDSA", 384, {"curve": "secp384r1"}),
    "EC_SIGN_SECP256K1_SHA256": ("ECDSA", 256, {"curve": "secp256k1"}),
    "EC_SIGN_ED25519": ("EdDSA", None, {"curve": "ed25519"}),
    "HMAC_SHA1": ("HMAC", 160, {"hash": "SHA-1"}),
    "HMAC_SHA256": ("HMAC", 256, {"hash": "SHA-256"}),
    "HMAC_SHA512": ("HMAC", 512, {"hash": "SHA-512"}),
    "PQ_SIGN_ML_DSA_65": ("ML-DSA", None, {"parameter_set": "ML-DSA-65"}),
    "PQ_SIGN_SLH_DSA_SHA2_128S": ("SLH-DSA", None,
                                  {"parameter_set": "SLH-DSA-SHA2-128s"}),
    # --- PKCS#11 spellings, for hardware-module exports. Listed explicitly so
    # the key size is carried rather than inferred from the name by the alias
    # table, which knows the algorithm but not how many bits were stored.
    "DES3": ("3DES", 168, {}),
    "DES2": ("3DES", 112, {"keying_option": 2}),
    "DES": ("DES", 56, {}),
    "AES_128": ("AES", 128, {}),
    "AES_192": ("AES", 192, {}),
    "AES_256": ("AES", 256, {}),
    "RSA_1024": ("RSA", 1024, {}),
    "ECC_NIST_P224": ("ECDSA", 224, {"curve": "secp224r1"}),
    "ML_KEM_512": ("ML-KEM", None, {"parameter_set": "ML-KEM-512"}),
    "ML_KEM_768": ("ML-KEM", None, {"parameter_set": "ML-KEM-768"}),
    "ML_KEM_1024": ("ML-KEM", None, {"parameter_set": "ML-KEM-1024"}),
}

# GCP and Azure both say, in their own vocabulary, "this key lives in hardware".
HSM_PROTECTION_LEVELS = {"HSM", "EXTERNAL", "EXTERNAL_VPC"}
HSM_ORIGINS = {"AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"}

# A named curve pins the key size exactly. Azure's key type is only "EC" — the
# curve arrives separately — so without this the table's placeholder size wins
# and every Azure P-384 key is reported as a P-256 key.
CURVE_SIZES = {
    "secp192r1": 192, "secp224r1": 224, "secp256r1": 256, "secp256k1": 256,
    "secp384r1": 384, "secp521r1": 521, "sm2p256v1": 256,
}


class CloudScanner(Scanner):
    source_type = SourceType.CLOUD_KMS
    name = "cloud"

    def __init__(self, policy=None, client_factory=None, azure_factory=None,
                 gcp_factory=None, pkcs11_factory=None) -> None:
        super().__init__(policy)
        # Injectable so every provider mapping is testable without credentials
        # or a physical token.
        self._client_factory = client_factory
        self._azure_factory = azure_factory
        self._gcp_factory = gcp_factory
        self._pkcs11_factory = pkcs11_factory

    def scan(self, target: str) -> ScanResult:
        if target.startswith("aws://"):
            return self._scan_aws(target[len("aws://"):] or "us-east-1", target)
        if target.startswith("azure://"):
            return self._scan_azure(target[len("azure://"):], target)
        if target.startswith("gcp://"):
            return self._scan_gcp(target[len("gcp://"):], target)
        if target.startswith("pkcs11://"):
            return self._scan_pkcs11(target, target)
        if target.startswith("file://"):
            return self._scan_file(target[len("file://"):], target)
        path = Path(target)
        if path.exists() and path.suffix == ".json":
            return self._scan_file(target, target)
        result = ScanResult()
        result.errors.append(ScanError(
            "cloud_kms", target,
            "unrecognised key store. Use aws://<region>, azure://<vault>, "
            "gcp://<project>/<location>, pkcs11://<module.so> or "
            "file://<path-to-export.json>"))
        return result

    # ------------------------------------------------------------------ gate
    def _refused(self, handle: str, target: str, result: ScanResult) -> bool:
        """Section 10: refuse, don't warn. Shared by every live connector."""
        if self.policy.target_allowed(handle):
            return False
        result.errors.append(ScanError(
            "cloud_kms", target,
            f"refused: {handle} is not in the scan allowlist. Add it to "
            f"crypto-policy.yaml under scanning.allowlist with a recorded "
            f"authorization attestation before connecting."))
        return True

    # ------------------------------------------------------------------- AWS
    def _scan_aws(self, region: str, target: str) -> ScanResult:
        result = ScanResult()
        if not self.policy.target_allowed(f"aws:{region}") and \
                not self.policy.target_allowed(region):
            self._refused(f"aws:{region}", target, result)
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

    # ----------------------------------------------------------------- Azure
    def _scan_azure(self, vault: str, target: str) -> ScanResult:
        """Azure Key Vault.

        `list_properties_of_keys` then `get_key` — both read-only. `get_key`
        returns the *public* half of an asymmetric key, which is where the
        modulus size comes from; the private half never leaves the vault and is
        not requested. Secrets and certificates have their own clients, and
        neither is touched.
        """
        result = ScanResult()
        vault = vault.strip("/")
        if not vault:
            result.errors.append(ScanError(
                "cloud_kms", target, "azure:// needs a vault name, e.g. azure://vault-prod"))
            return result
        if self._refused(f"azure:{vault}", target, result):
            return result
        try:
            client = self._azure_client(vault)
        except Exception as exc:
            result.errors.append(ScanError("cloud_kms", target, f"could not connect: {exc}"))
            return result

        try:
            properties = list(client.list_properties_of_keys())
        except Exception as exc:
            result.errors.append(ScanError(
                "cloud_kms", target, f"list_properties_of_keys failed: {exc}"))
            return result

        for prop in properties:
            name = getattr(prop, "name", None)
            try:
                key = client.get_key(name)
            except Exception as exc:
                result.errors.append(ScanError("cloud_kms", str(name), f"get_key: {exc}"))
                continue
            metadata = _azure_metadata(key, prop, name)
            asset = self._key_asset(
                metadata, provider="azure", region=vault,
                rotation_enabled=metadata.pop("_rotation", None),
                specs=GENERIC_KEY_SPECS)
            if asset is not None:
                result.assets.append(asset)
        return result

    def _azure_client(self, vault: str):
        if self._azure_factory is not None:
            return self._azure_factory(vault)
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient

        return KeyClient(vault_url=f"https://{vault}.vault.azure.net",
                         credential=DefaultAzureCredential())

    # ------------------------------------------------------------------- GCP
    def _scan_gcp(self, locator: str, target: str) -> ScanResult:
        """Google Cloud KMS.

        Walks key rings -> crypto keys -> key versions. The version is the unit
        that carries the algorithm and the protection level, and a key with an
        old enabled version alongside a new one is exactly the kind of residual
        exposure an inventory is supposed to surface, so every enabled version
        is reported rather than only the primary.
        """
        result = ScanResult()
        parts = [p for p in locator.strip("/").split("/") if p]
        if len(parts) < 2:
            result.errors.append(ScanError(
                "cloud_kms", target,
                "gcp:// needs project and location, e.g. gcp://my-project/global"))
            return result
        project, location = parts[0], parts[1]
        handle = f"gcp:{project}/{location}"
        if self._refused(handle, target, result):
            return result
        try:
            client = self._gcp_client()
        except Exception as exc:
            result.errors.append(ScanError("cloud_kms", target, f"could not connect: {exc}"))
            return result

        parent = f"projects/{project}/locations/{location}"
        try:
            rings = list(client.list_key_rings(request={"parent": parent}))
        except Exception as exc:
            result.errors.append(ScanError("cloud_kms", target, f"list_key_rings failed: {exc}"))
            return result

        for ring in rings:
            ring_name = getattr(ring, "name", "")
            try:
                keys = list(client.list_crypto_keys(request={"parent": ring_name}))
            except Exception as exc:
                result.errors.append(ScanError("cloud_kms", ring_name,
                                               f"list_crypto_keys: {exc}"))
                continue
            for key in keys:
                key_name = getattr(key, "name", "")
                rotation = getattr(key, "rotation_period", None)
                try:
                    versions = list(client.list_crypto_key_versions(
                        request={"parent": key_name}))
                except Exception as exc:
                    result.errors.append(ScanError("cloud_kms", key_name,
                                                   f"list_crypto_key_versions: {exc}"))
                    continue
                for version in versions:
                    metadata = _gcp_metadata(key, version, project, location)
                    if metadata is None:
                        continue
                    asset = self._key_asset(
                        metadata, provider="gcp", region=f"{project}/{location}",
                        rotation_enabled=bool(rotation) if rotation is not None else None,
                        specs=GENERIC_KEY_SPECS)
                    if asset is not None:
                        result.assets.append(asset)
        return result

    def _gcp_client(self):
        if self._gcp_factory is not None:
            return self._gcp_factory()
        from google.cloud import kms

        return kms.KeyManagementServiceClient()

    # --------------------------------------------------------------- PKCS#11
    def _scan_pkcs11(self, target: str, original: str) -> ScanResult:
        """Any PKCS#11 hardware module.

            pkcs11:///usr/lib/softhsm/libsofthsm2.so
            pkcs11:///usr/lib/libCryptoki2_64.so?slot=0&pin-env=HSM_PIN

        Public objects are readable without authenticating, so an unauthenticated
        scan still yields an inventory. A PIN, supplied only as the *name* of an
        environment variable, adds private-key objects. The PIN is never accepted
        inline: the target string is written to the scan store, the CBOM and the
        audit log, and a credential there would outlive the scan.
        """
        result = ScanResult()
        parsed = urlparse(target)
        module_path = f"{parsed.netloc}{parsed.path}" or parsed.path
        if not module_path:
            result.errors.append(ScanError(
                "cloud_kms", original,
                "pkcs11:// needs a module path, e.g. "
                "pkcs11:///usr/lib/softhsm/libsofthsm2.so"))
            return result
        options = parse_qs(parsed.query)
        wanted_slot = options.get("slot", [None])[0]
        pin = p11.resolve_pin(options.get("pin-env", [None])[0])

        if self._refused(f"pkcs11:{module_path}", original, result):
            return result

        try:
            lib = self._pkcs11_lib(module_path)
        except Exception as exc:
            result.errors.append(ScanError(
                "cloud_kms", original, f"could not load PKCS#11 module: {exc}"))
            return result

        try:
            slots = list(lib.get_slots(token_present=True))
        except Exception as exc:
            result.errors.append(ScanError("cloud_kms", original, f"get_slots failed: {exc}"))
            return result

        for index, slot in enumerate(slots):
            if wanted_slot is not None and str(index) != str(wanted_slot) and \
                    str(getattr(slot, "slot_id", index)) != str(wanted_slot):
                continue
            try:
                token = slot.get_token()
            except Exception as exc:
                result.errors.append(ScanError("cloud_kms", f"slot {index}",
                                               f"get_token: {exc}"))
                continue
            label = str(getattr(token, "label", "") or f"slot-{index}").strip()
            try:
                result.extend(self._read_token(token, label, module_path, pin, original))
            except Exception as exc:
                result.errors.append(ScanError("cloud_kms", f"token {label}", str(exc)))
        return result

    def _pkcs11_lib(self, module_path: str):
        if self._pkcs11_factory is not None:
            return self._pkcs11_factory(module_path)
        import pkcs11 as pkcs11_lib     # python-pkcs11, an optional dependency

        return pkcs11_lib.lib(module_path)

    def _read_token(self, token, label: str, module_path: str,
                    pin: str | None, target: str) -> ScanResult:
        result = ScanResult()
        session = token.open(user_pin=pin) if pin else token.open()
        try:
            objects = list(session.get_objects())
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()

        model = str(getattr(token, "model", "") or "").strip()
        manufacturer = str(getattr(token, "manufacturer_id", "") or "").strip()
        for obj in objects:
            asset = self._pkcs11_asset(obj, label, model, manufacturer,
                                       module_path, target)
            if asset is not None:
                result.assets.append(asset)
        return result

    def _pkcs11_asset(self, obj, token_label: str, model: str, manufacturer: str,
                      module_path: str, target: str) -> Asset | None:
        key_type = p11.normalise_key_type(getattr(obj, "key_type", None))
        if key_type is None:
            return None
        mapped = p11.KEY_TYPES.get(key_type)
        if mapped is None:
            return None
        algorithm, parameters = mapped
        parameters = dict(parameters)

        key_size = p11.key_size_for(
            algorithm, getattr(obj, "modulus_bits", None), getattr(obj, "value_len", None))
        curve = p11.curve_from_ec_params(getattr(obj, "ec_params", None))
        if curve:
            parameters["curve"] = curve
            # A named curve pins the strength; the stored size does not.
            key_size = key_size or {"secp256r1": 256, "secp384r1": 384,
                                    "secp521r1": 521, "secp256k1": 256,
                                    "secp224r1": 224, "secp192r1": 192}.get(curve)

        object_class = str(getattr(obj, "object_class", "") or "").rsplit(".", 1)[-1].upper()
        obj_label = str(getattr(obj, "label", "") or "").strip() or "(unlabelled)"
        extractable = getattr(obj, "extractable", None)
        sensitive = getattr(obj, "sensitive", None)

        location = f"pkcs11:{token_label}/{obj_label}"
        detail = {
            "key_id": obj_label,
            "object_class": object_class or None,
            "token_label": token_label,
            "token_model": model or None,
            "token_manufacturer": manufacturer or None,
            "module": module_path,
            "key_type": key_type,
            "hsm_backed": True,
            "extractable": extractable,
            "sensitive": sensitive,
        }

        notes = []
        # An extractable private key in an HSM undermines the reason the HSM is
        # there, and it is also the one case where migration is *easier* — the
        # key can be moved. Worth saying either way.
        if extractable is True and object_class in {"PRIVATE_KEY", "SECRET_KEY"}:
            notes.append("key is marked extractable, so hardware confinement is not enforced")
        if sensitive is False and object_class in {"PRIVATE_KEY", "SECRET_KEY"}:
            notes.append("key is not marked sensitive")
        if notes:
            detail["notes"] = notes

        snippet = (f"{key_type} {object_class.lower().replace('_', ' ') or 'object'} "
                   f"on {model or 'PKCS#11 token'} '{token_label}'"
                   + (f" — {'; '.join(notes)}" if notes else ""))

        return Asset(
            algorithm=algorithm,
            asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            key_size=key_size,
            parameters={**parameters, "material": "hardware-key"},
            # Not "key-store": see the module docstring. A key confined to a
            # token migrates on the vendor's firmware schedule, not the
            # application team's.
            location_class="hardware-module",
            evidence=[Evidence(self.source_type, "pkcs11-object-enumeration",
                               location, Confidence.HIGH, snippet, detail)],
        )

    # ------------------------------------------------------------------ file
    def _scan_file(self, path_str: str, target: str) -> ScanResult:
        """A key-store export. Shape:

            {"provider": "azure", "location": "vault-prod",
             "keys": [{"KeyId": ..., "KeySpec": ..., "KeyUsage": ...,
                       "Enabled": true, "RotationEnabled": false,
                       "Origin": "AWS_CLOUDHSM" | "HSM", "Extractable": false}]}

        `provider: "pkcs11"` marks the whole export as hardware-resident, which
        is how the HSM source type is demonstrated without a physical token.
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
        for extra in ("curve", "parameter_set"):
            if metadata.get(extra):
                parameters[extra] = metadata[extra]
        # The curve is more specific than the key type, so it overrides the
        # placeholder size the spec table carries for a bare "EC".
        if parameters.get("curve") in CURVE_SIZES:
            key_size = CURVE_SIZES[parameters["curve"]]
        if metadata.get("KeySize"):
            try:
                key_size = int(metadata["KeySize"])
            except (TypeError, ValueError):
                pass

        origin = metadata.get("Origin", "")
        protection = str(metadata.get("ProtectionLevel", "")).upper()
        hsm_backed = (origin in HSM_ORIGINS or "HSM" in str(spec)
                      or protection in HSM_PROTECTION_LEVELS
                      or provider == "pkcs11")
        location = f"{provider}:{region}/{key_id}"

        detail = {
            "key_id": key_id,
            "key_usage": metadata.get("KeyUsage"),
            "origin": origin or None,
            "protection_level": protection or None,
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
        if metadata.get("Extractable") is True:
            notes.append("key is marked extractable")
        if metadata.get("ExpiresOn"):
            detail["expires_on"] = metadata["ExpiresOn"]
        if notes:
            detail["notes"] = notes

        material = "hardware-key" if provider == "pkcs11" else "managed-key"
        return Asset(
            algorithm=algorithm, asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            key_size=key_size, parameters={**parameters, "material": material},
            location_class="hardware-module" if provider == "pkcs11" else "key-store",
            evidence=[Evidence(
                self.source_type, f"{provider}-kms-describe", location, Confidence.HIGH,
                f"{spec} ({metadata.get('KeyUsage', 'unknown usage')})"
                + (", HSM-backed" if hsm_backed else "")
                + (f" — {'; '.join(notes)}" if notes else ""),
                detail,
            )],
        )


# --------------------------------------------------------------- adapters
def _azure_metadata(key, prop, name) -> dict:
    """Flatten an Azure `KeyVaultKey` into the shared metadata shape.

    Azure reports RSA size only implicitly, as the length of the public modulus
    `n`. That is public material and the only place the key size appears.
    """
    jwk = getattr(key, "key", None)
    key_type = str(getattr(jwk, "kty", None) or getattr(key, "key_type", "") or "")
    properties = getattr(key, "properties", None) or prop

    metadata: dict[str, Any] = {
        "KeyId": name or getattr(properties, "name", "unknown"),
        "KeySpec": key_type,
        "KeyUsage": ", ".join(getattr(jwk, "key_ops", None) or []) or None,
        "Enabled": getattr(properties, "enabled", None),
        "Origin": "HSM" if key_type.upper().endswith("-HSM") else "",
    }
    modulus = getattr(jwk, "n", None)
    if modulus:
        metadata["KeySize"] = len(modulus) * 8
    curve = getattr(jwk, "crv", None)
    if curve:
        metadata["curve"] = {"P-256": "secp256r1", "P-384": "secp384r1",
                             "P-521": "secp521r1", "P-256K": "secp256k1",
                             "SECP256K1": "secp256k1"}.get(str(curve), str(curve))
    expires = getattr(properties, "expires_on", None)
    if expires is not None:
        metadata["ExpiresOn"] = str(expires)
    # Azure exposes rotation policy through a separate call that needs an extra
    # permission; absent rather than guessed.
    metadata["_rotation"] = None
    return metadata


def _gcp_metadata(key, version, project: str, location: str) -> dict | None:
    """Flatten a GCP `CryptoKeyVersion` into the shared metadata shape.

    Destroyed and pending-destruction versions are dropped: they hold no
    material and cannot be attacked, so counting them would inflate every KPI.
    """
    state = str(getattr(version, "state", "") or "").rsplit(".", 1)[-1].upper()
    if state in {"DESTROYED", "DESTROY_SCHEDULED", "PENDING_IMPORT", "IMPORT_FAILED"}:
        return None
    algorithm = str(getattr(version, "algorithm", "") or "").rsplit(".", 1)[-1].upper()
    if not algorithm:
        return None
    return {
        "KeyId": getattr(version, "name", "") or getattr(key, "name", "unknown"),
        "KeySpec": algorithm,
        "KeyUsage": str(getattr(key, "purpose", "") or "").rsplit(".", 1)[-1] or None,
        "Enabled": state == "ENABLED",
        "ProtectionLevel": str(
            getattr(version, "protection_level", "") or "").rsplit(".", 1)[-1].upper(),
        "Origin": "",
    }
