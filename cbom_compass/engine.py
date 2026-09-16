"""Scan orchestration — PRD v1.1 section 7.

Runs the scanners, merges findings into one de-duplicated inventory, scores
them, recommends replacements, and emits the CBOM. One scanner failing degrades
to a per-source error and never blocks the other five (PRD section 8.3).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import cbom, recommend, risk
from .inventory import Inventory, merge
from .scanners.certificates import blast_radius
from .models import (Asset, AssetType, Confidence, Evidence, Recommendation,
                     Relationship, RiskClassification, ScanRun, SourceType, to_dict)
from .policy import Policy
from .scanners import (BinaryScanner, CertificateScanner, CloudScanner,
                       ConfigScanner,
                       ContainerScanner, DependencyScanner, SourceScanner,
                       SSHScanner, TLSScanner)
from .scanners.base import ScanError, ScanResult

SCANNERS = {
    "source": SourceScanner,
    "config": ConfigScanner,
    "certificates": CertificateScanner,
    "dependencies": DependencyScanner,
    "binary": BinaryScanner,
    "container": ContainerScanner,
    "tls": TLSScanner,
    "ssh": SSHScanner,
    "cloud": CloudScanner,
}
# Scanners that take a filesystem path vs. a network/image target.
PATH_SCANNERS = {"source", "config", "certificates", "dependencies", "binary"}


@dataclass
class ScanReport:
    run: ScanRun
    inventory: Inventory
    risks: dict[str, RiskClassification]
    recommendations: dict[str, Recommendation]
    policy: Policy
    raw_asset_count: int = 0
    errors: list[ScanError] = field(default_factory=list)

    @property
    def blast(self) -> dict[str, int]:
        """How many certificates each certificate transitively vouches for.

        Deliberately *not* folded into the score. Criticality is a human input
        in this tool — "business context cannot be read out of code" — and
        silently promoting a CA because it signs a lot would be exactly the kind
        of confident guess the scoring model refuses to make elsewhere. It
        breaks ties in the priority list and it is shown, so a PKI owner can set
        the criticality themselves with the number in front of them.
        """
        if not hasattr(self, "_blast"):
            self._blast = blast_radius(self.inventory.assets,
                                       self.inventory.relationships)
        return self._blast

    # ------------------------------------------------------------ summaries
    def kpis(self) -> dict:
        """Overview KPIs. These counts are of *merged* assets, so they reconcile
        with the Inventory Explorer row count (PRD section 13)."""
        status: dict[str, int] = {}
        band: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
        confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        hndl = deprecated_2030 = disallowed_2035 = 0
        drivers: dict[str, int] = {}
        for asset in self.inventory.assets:
            confidence[asset.confidence.value] += 1
        for r in self.risks.values():
            status[r.quantum_status.value] = status.get(r.quantum_status.value, 0) + 1
            band[r.urgency_band] += 1
            hndl += r.hndl_flag
            deprecated_2030 += "nist8547_deprecated_2030" in r.regulatory_flags
            disallowed_2035 += "nist8547_disallowed_2035" in r.regulatory_flags
            drivers[r.driver] = drivers.get(r.driver, 0) + 1
        return {
            "total_assets": len(self.inventory.assets),
            "raw_findings": self.raw_asset_count,
            "collapsed_by_dedup": self.inventory.merged_count,
            "by_status": status,
            "by_urgency": band,
            "by_confidence": confidence,
            "by_driver": drivers,
            "z_sensitive": drivers.get("mosca-urgency", 0),
            "hndl_flagged": hndl,
            "nist_deprecated_2030": deprecated_2030,
            "nist_disallowed_2035": disallowed_2035,
            "relationships": len(self.inventory.relationships),
            "certificate_authorities": sum(
                1 for a in self.inventory.assets
                if a.location_class == "certificate-authority"),
            "widest_blast_radius": max(self.blast.values(), default=0),
            "z_year": self.policy.z_year,
            "sources_covered": self.run.sources_covered,
            "errors": len(self.errors),
        }

    def heat_map(self) -> dict:
        return risk.heat_map(self.risks)

    def priority_list(self, limit: int | None = None) -> list[dict]:
        # Score first, then how badly Mosca fails, then how sure we are, so a
        # block of equal scores still lands in a defensible order.
        confidence_rank = {"high": 2, "medium": 1, "low": 0}
        rows = sorted(
            (self.row(a) for a in self.inventory.assets),
            key=lambda r: (
                -r["score"],
                -r["blast_radius"],
                -(r["mosca"]["exposure_gap"] if r["mosca"] else 0),
                -confidence_rank.get(r["confidence"], 0),
                -len(r["evidence"]),
                r["algorithm"],
            ),
        )
        return rows[:limit] if limit else rows

    def row(self, asset: Asset) -> dict:
        r = self.risks.get(asset.id)
        rec = self.recommendations.get(asset.id)
        return {
            "id": asset.id,
            "name": asset.display_name,
            "algorithm": asset.algorithm,
            "key_size": asset.key_size,
            "asset_type": asset.asset_type.value,
            "parameters": asset.parameters,
            "library": asset.library,
            "library_version": asset.library_version,
            "provider": asset.provider,
            "location": asset.primary_location,
            "location_class": asset.location_class,
            "source_types": asset.source_types,
            "detection_methods": asset.detection_methods,
            "confidence": asset.confidence.value,
            "evidence": [to_dict(e) for e in asset.evidence],
            "certificate": asset.certificate,
            "blast_radius": self.blast.get(asset.id, 0),
            "quantum_status": r.quantum_status.value if r else "unknown",
            "rationale": r.rationale if r else "",
            "hndl": r.hndl_flag if r else False,
            "regulatory_flags": r.regulatory_flags if r else [],
            "criticality": r.criticality.value if r else "medium",
            "urgency_band": r.urgency_band if r else "low",
            "score": r.score if r else 0.0,
            "mosca": {
                "x": r.x_years, "x_source": r.x_source, "x_basis": r.x_basis,
                "y": r.y_years, "y_source": r.y_source,
                "z_year": r.z_year_used, "z_years": r.z_years,
                "exposure_gap": r.exposure_gap, "overdue": r.overdue,
                "urgency": r.urgency, "compliance": r.compliance_component,
                "quantum": r.quantum_component,
                "criticality_weight": r.criticality_weight, "risk": r.risk,
                "driver": r.driver,
            } if r else None,
            "recommendation": to_dict(rec) if rec else None,
        }

    def cbom(self) -> dict:
        return cbom.build(
            self.inventory.assets, self.inventory.relationships,
            self.risks, self.recommendations, self.run.target_scope,
            label=self.run.label,
        )

    def to_dict(self) -> dict:
        return {
            "run": to_dict(self.run),
            "kpis": self.kpis(),
            "heat_map": self.heat_map(),
            "assets": self.priority_list(),
            "relationships": [to_dict(r) for r in self.inventory.relationships],
            "errors": [to_dict(e) for e in self.errors],
            "policy": {
                "z_year": self.policy.z_year,
                "urgency_scale": self.policy.urgency_scale,
                "cnsa2_required": self.policy.cnsa2_required,
                "criticality_weights": self.policy.criticality_weights,
            },
        }


def attribute_providers(combined: ScanResult) -> None:
    """Link call sites to the module they reach cryptography through.

    Relationships are what the asset graph draws, and they only ever came from
    certificate chains, negotiated protocols, container layers and dependency
    manifests. A scan of a code repository produces none of those, so the graph
    was a field of disconnected points: accurate, and useless. A call site does
    know one real thing about its surroundings — which module it called into —
    and `crypto/ecdsa` with twelve ECDSA findings hanging off it is a blast
    radius a reader can act on.

    A library already named by a manifest is reused rather than duplicated, so a
    dependency that is both declared and called stays one asset carrying both
    kinds of evidence instead of two rows that disagree about the same library.
    """
    existing: dict[str, Asset] = {}
    for asset in combined.assets:
        if asset.library and asset.asset_type == AssetType.RELATED_CRYPTO_MATERIAL:
            existing.setdefault(asset.library.lower(), asset)

    by_provider: dict[str, list[Asset]] = {}
    for asset in combined.assets:
        if asset.provider:
            by_provider.setdefault(asset.provider, []).append(asset)

    for provider, users in sorted(by_provider.items()):
        entry = existing.get(provider.lower())
        if entry is None:
            entry = Asset(
                algorithm=provider,
                asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                library=provider,
                location_class="linked-library",
                evidence=[Evidence(
                    SourceType.SOURCE_CODE, "import-attribution",
                    users[0].primary_location, Confidence.HIGH,
                    f"{len(users)} call site(s) reach cryptography through {provider}",
                )],
            )
            combined.assets.append(entry)
            existing[provider.lower()] = entry
        for user in users:
            combined.relationships.append(
                Relationship(user.id, entry.id, "depends-on"))


def run_scan(targets: dict[str, list[str]], policy: Policy | None = None,
             initiated_by: str = "cli", label: str = "") -> ScanReport:
    """targets maps scanner name -> list of targets, e.g. {"source": ["./repo"]}.

    `label` names the origin for display when the paths themselves are not
    meaningful — an uploaded archive lands in a workspace directory whose name
    tells a reader nothing.
    """
    policy = policy or Policy()
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    combined = ScanResult()
    covered: list[str] = []
    scope: list[str] = []

    for name, target_list in targets.items():
        scanner_cls = SCANNERS.get(name)
        if scanner_cls is None:
            combined.errors.append(ScanError(name, "", f"unknown scanner '{name}'"))
            continue
        scanner = scanner_cls(policy)
        produced = False
        for target in target_list:
            scope.append(f"{name}:{target}")
            try:
                result = scanner.scan(target)
            except Exception as exc:      # a scanner blowing up never kills the run
                combined.errors.append(ScanError(name, target, f"scanner crashed: {exc}"))
                continue
            combined.extend(result)
            produced = True
        if produced:
            covered.append(name)

    # Before the merge, so the library rows it creates are de-duplicated against
    # manifest rows for the same library and its edges are remapped with the rest.
    attribute_providers(combined)

    raw_count = len(combined.assets)
    inventory = merge(combined.assets, combined.relationships)
    risks = risk.classify_all(inventory.assets, policy)
    recommendations = recommend.recommend_all(
        inventory.assets, risks, inventory.relationships, policy)

    run = ScanRun(
        scan_id=str(uuid.uuid4())[:8],
        started_at=started,
        finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sources_covered=covered,
        target_scope=scope,
        initiated_by=initiated_by,
        asset_count=len(inventory.assets),
        errors=[to_dict(e) for e in combined.errors],
        label=label,
    )
    return ScanReport(run, inventory, risks, recommendations, policy,
                      raw_asset_count=raw_count, errors=combined.errors)


def diff(previous: dict, current: dict) -> dict:
    """Drift between two scan snapshots — PRD section 8.4.

    Re-scans are diffed against the previous snapshot so new/changed/removed
    assets are flagged rather than presented as an undifferentiated fresh list.
    """
    before = {a["id"]: a for a in previous.get("assets", [])}
    after = {a["id"]: a for a in current.get("assets", [])}
    added = [after[i] for i in after.keys() - before.keys()]
    removed = [before[i] for i in before.keys() - after.keys()]
    changed = []
    for asset_id in before.keys() & after.keys():
        old, new = before[asset_id], after[asset_id]
        deltas = {
            field: {"from": old.get(field), "to": new.get(field)}
            for field in ("score", "quantum_status", "confidence", "criticality", "urgency_band")
            if old.get(field) != new.get(field)
        }
        if deltas:
            changed.append({"id": asset_id, "name": new["name"], "changes": deltas})
    return {
        "added": sorted(added, key=lambda a: -a["score"]),
        "removed": removed,
        "changed": sorted(changed, key=lambda c: c["name"]),
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)},
    }
