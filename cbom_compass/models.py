"""Core data model.

Mirrors PRD v1.1 section 9. The two things worth reading closely are
`Asset.identity_key` (section 6.1, cross-source de-duplication) and
`RiskClassification` (section 6.3, the provenance fields that let the UI badge
an assumed input as assumed).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class SourceType(str, Enum):
    SOURCE_CODE = "source_code"
    # Protocol cryptography configured rather than called: sshd_config, IKE
    # proposals, nginx cipher lists. Its own source type because "which
    # technique found this" is what the Inventory Explorer filters on, and a
    # cipher list is not a call site.
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    BINARY = "binary"
    CONTAINER = "container"
    ENDPOINT = "endpoint"
    CLOUD_KMS = "cloud_kms"


class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    @classmethod
    def from_rank(cls, rank: int) -> "Confidence":
        return [cls.LOW, cls.MEDIUM, cls.HIGH][max(0, min(2, rank))]


class QuantumStatus(str, Enum):
    """PRD section 6.2. Note ADEQUATE covers AES-128 and SHA-256 deliberately."""

    BROKEN = "broken"                              # Shor solves it outright
    DEPRECATED_INSUFFICIENT = "deprecated_insufficient"  # RSA-1024, 3DES, SHA-1
    BROKEN_CLASSICAL = "broken_classical"          # MD5, DES, RC4
    ADEQUATE = "adequate"
    UNKNOWN = "unknown"
    # Inventory-only rows (a library entry). Risk is carried by the algorithms
    # the library exposes, which are separate assets; scoring the library too
    # would double-count it in every KPI.
    NOT_APPLICABLE = "not_applicable"


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Evidence:
    """One observation of an asset by one technique.

    A merged asset carries several of these; the UI shows them all so an
    engineer can see *why* we think a thing is there.
    """

    source_type: SourceType
    detection_method: str
    location: str
    confidence: Confidence
    snippet: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Asset:
    """A single cryptographic artefact."""

    algorithm: str                      # registry-normalised name, e.g. "RSA"
    asset_type: AssetType = AssetType.ALGORITHM
    key_size: int | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    library: str | None = None
    library_version: str | None = None
    location_class: str = "unknown"     # call-site | config | linked-library | negotiated |
                                        # manifest | image-layer | key-store | hardware-module
    primitive: str | None = None        # signature | kem | hash | block-cipher | ...
    evidence: list[Evidence] = field(default_factory=list)
    # Certificate subtype fields (PRD section 9) — populated only for asset_type == CERTIFICATE
    certificate: dict[str, Any] | None = None
    service: str | None = None          # owning service, used to resolve policy tags

    @property
    def identity_key(self) -> str:
        """PRD section 6.1 — asset identity, and the basis for de-duplication.

        Two different populations need opposite treatment, so the key is not the
        same shape for both:

        * **Library-backed** findings (`library` set). The same OpenSSL 3.0.11 is
          legitimately reported by the dependency, binary and container scanners
          at three different locations. These must collapse to one row, so
          location is deliberately *excluded* from the key.

        * **Call sites and live endpoints** (`library` unset). `RSA-2048` in
          `payments.py` and `RSA-2048` in `auth.js` are two separate things to
          migrate, owned by different services and carrying different business
          criticality. Collapsing them would silently drop one service's tag, so
          location is *included*.
        """
        params = ",".join(f"{k}={self.parameters[k]}" for k in sorted(self.parameters))
        parts = [self.algorithm.upper(), str(self.key_size or ""), params]
        if self.library:
            parts.append(f"{self.library}@{self.library_version or ''}")
        else:
            parts.append(self.location_class)
            parts.append(self.primary_location)
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @property
    def id(self) -> str:
        return self.identity_key

    @property
    def confidence(self) -> Confidence:
        """Max across evidence, promoted one level by independent corroboration."""
        if not self.evidence:
            return Confidence.LOW
        best = max(e.confidence.rank for e in self.evidence)
        techniques = {e.detection_method for e in self.evidence}
        if len(techniques) > 1:
            best += 1
        return Confidence.from_rank(best)

    @property
    def detection_methods(self) -> list[str]:
        return sorted({e.detection_method for e in self.evidence})

    @property
    def source_types(self) -> list[str]:
        return sorted({e.source_type.value for e in self.evidence})

    @property
    def primary_location(self) -> str:
        return self.evidence[0].location if self.evidence else ""

    @classmethod
    def from_row(cls, row: dict) -> "Asset":
        """Rebuild from a serialised report row.

        Lets the dashboard's Z-slider rescore a stored scan without re-running
        the scanners — PRD section 8.2, "recompute live as the estimate changes".
        """
        return cls(
            algorithm=row["algorithm"],
            asset_type=AssetType(row.get("asset_type", "algorithm")),
            key_size=row.get("key_size"),
            parameters=row.get("parameters") or {},
            library=row.get("library"),
            library_version=row.get("library_version"),
            location_class=row.get("location_class", "unknown"),
            certificate=row.get("certificate"),
            service=row.get("service"),
            evidence=[
                Evidence(
                    source_type=SourceType(e["source_type"]),
                    detection_method=e["detection_method"],
                    location=e["location"],
                    confidence=Confidence(e["confidence"]),
                    snippet=e.get("snippet"),
                    detail=e.get("detail") or {},
                )
                for e in row.get("evidence", [])
            ],
        )

    @property
    def display_name(self) -> str:
        bits = [self.algorithm]
        if self.key_size:
            bits.append(str(self.key_size))
        if self.parameters.get("curve"):
            bits.append(self.parameters["curve"])
        if self.parameters.get("mode"):
            bits.append(self.parameters["mode"])
        return "-".join(bits)


@dataclass
class Relationship:
    source_id: str
    target_id: str
    kind: str  # signed-by | depends-on | negotiated-by | bundled-in


@dataclass
class RiskClassification:
    """PRD section 6.3. Every input carries its provenance so the UI can badge it."""

    asset_id: str
    quantum_status: QuantumStatus
    rationale: str
    hndl_flag: bool
    regulatory_flags: list[str]
    nist_quantum_security_level: int | None
    x_years: float
    x_source: str          # "tagged" | "assumed"
    y_years: float
    y_source: str          # "tagged" | "estimated"
    z_year_used: int
    z_years: float
    exposure_gap: float    # (X + Y) - Z_years; positive means already overdue
    urgency: float
    compliance_component: float
    quantum_component: float
    criticality: Criticality
    criticality_weight: float
    risk: float
    score: float
    # Which axis produced `risk`. An asset pinned by "compliance" does not move
    # when Z changes -- NIST IR 8547's dates are fixed - and the UI says so rather
    # than leaving the slider looking broken.
    driver: str = "none"

    @property
    def overdue(self) -> bool:
        return self.exposure_gap > 0

    @property
    def urgency_band(self) -> str:
        if self.score >= 0.66:
            return "high"
        if self.score >= 0.33:
            return "medium"
        return "low"


@dataclass
class Recommendation:
    asset_id: str
    standard: str            # "FIPS 203" | ... | "SP 800-208" | "no change"
    algorithm: str
    hybrid: bool
    maturity: str            # "final" | "draft" | "selected"
    rationale: str
    rotation_cost: str       # low | medium | high
    support_maturity: str    # production | emerging | experimental
    blocking_dependencies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanRun:
    scan_id: str
    started_at: str
    finished_at: str | None
    sources_covered: list[str]
    target_scope: list[str]
    initiated_by: str
    asset_count: int = 0
    errors: list[dict[str, str]] = field(default_factory=list)
    # Human-readable origin ("github.com/psf/requests", "payments.zip"). The
    # workspace path in target_scope is real and is what `verify` re-reads, but
    # it is not what anyone wants to see on a report. Defaulted so scans stored
    # before this field existed still load.
    label: str = ""


def to_dict(obj: Any) -> Any:
    """dataclass -> JSON-safe dict, resolving Enums and computed properties."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, list):
        return [to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    return obj
