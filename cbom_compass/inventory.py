"""Inventory merge — PRD v1.1 section 6.1, asset identity and de-duplication.

The same OpenSSL 3.0.11 is legitimately found by the dependency scanner, the
binary scanner and the container scanner. Without a merge rule the inventory
triple-counts, and the Overview KPI totals will not reconcile with the Inventory
Explorer row count — live, on stage.

Two passes:
  1. Exact identity-key merge (algorithm, params, library@version, location-class).
  2. Unsized absorption: `crypto.generateKeyPairSync('rsa', {modulusLength: 2048})`
     legitimately matches two rules on one line, one of which resolves the key
     size and one of which does not. The unsized finding is the same asset.

Confidence is the max across merged evidence, promoted one level when more than
one independent technique saw it (models.Asset.confidence).
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Asset, Relationship


@dataclass
class Inventory:
    assets: list[Asset]
    relationships: list[Relationship]
    merged_count: int = 0

    def by_id(self) -> dict[str, Asset]:
        return {a.id: a for a in self.assets}


def _absorption_key(asset: Asset) -> tuple:
    """Identity ignoring key size, used only for pass 2."""
    return (
        asset.algorithm.upper(),
        asset.location_class,
        asset.primary_location,
        asset.library or "",
        asset.library_version or "",
    )


def merge(assets: list[Asset], relationships: list[Relationship] | None = None) -> Inventory:
    relationships = relationships or []
    raw_count = len(assets)

    # --- pass 1: exact identity key -------------------------------------
    merged: dict[str, Asset] = {}
    remap: dict[str, str] = {}
    for asset in assets:
        key = asset.identity_key
        if key in merged:
            existing = merged[key]
            for ev in asset.evidence:
                if not any(
                    e.location == ev.location and e.detection_method == ev.detection_method
                    for e in existing.evidence
                ):
                    existing.evidence.append(ev)
            if asset.certificate and not existing.certificate:
                existing.certificate = asset.certificate
            existing.service = existing.service or asset.service
        else:
            merged[key] = asset
        remap[asset.id] = key

    # --- pass 2: absorb unsized findings into their sized twin -----------
    sized: dict[tuple, Asset] = {
        _absorption_key(a): a for a in merged.values() if a.key_size is not None
    }
    survivors: dict[str, Asset] = {}
    for key, asset in merged.items():
        if asset.key_size is None and not asset.parameters:
            twin = sized.get(_absorption_key(asset))
            if twin is not None and twin.id != asset.id:
                for ev in asset.evidence:
                    if not any(
                        e.location == ev.location and e.detection_method == ev.detection_method
                        for e in twin.evidence
                    ):
                        twin.evidence.append(ev)
                remap[key] = twin.id
                for old, new in list(remap.items()):
                    if new == key:
                        remap[old] = twin.id
                continue
        survivors[key] = asset

    # --- rewrite relationship endpoints onto surviving assets -----------
    seen: set[tuple[str, str, str]] = set()
    rewritten: list[Relationship] = []
    for rel in relationships:
        src = remap.get(rel.source_id, rel.source_id)
        tgt = remap.get(rel.target_id, rel.target_id)
        if src == tgt or src not in survivors or tgt not in survivors:
            continue
        triple = (src, tgt, rel.kind)
        if triple in seen:
            continue
        seen.add(triple)
        rewritten.append(Relationship(src, tgt, rel.kind))

    assets_out = sorted(survivors.values(), key=lambda a: (a.algorithm, a.key_size or 0))
    return Inventory(assets_out, rewritten, merged_count=raw_count - len(assets_out))
