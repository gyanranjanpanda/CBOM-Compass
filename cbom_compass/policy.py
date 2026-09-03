"""Scan and scoring policy — the human-owned inputs from PRD v1.1 section 6.3,
plus the scan-authorization gate from section 10.

Lives in a checked-in `crypto-policy.yaml` so tagging is reviewable in the same
way code is, rather than trapped in a database.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Criticality

CRITICALITY_WEIGHT = {Criticality.LOW: 0.4, Criticality.MEDIUM: 0.7, Criticality.HIGH: 1.0}


@dataclass
class ServiceTag:
    """A business tag applied to everything matching `paths`."""

    name: str
    paths: list[str] = field(default_factory=list)
    data_class: str | None = None
    criticality: Criticality = Criticality.MEDIUM
    surface: str | None = None

    def matches(self, location: str) -> bool:
        return any(fnmatch.fnmatch(location, p) for p in self.paths)


@dataclass
class Policy:
    z_year: int = 2035
    urgency_scale: float = 10.0
    criticality_weights: dict[str, float] = field(
        default_factory=lambda: {k.value: v for k, v in CRITICALITY_WEIGHT.items()}
    )
    hndl_multiplier: float = 0.4          # risk *= (0.6 + 0.4 * hndl)
    default_criticality: Criticality = Criticality.MEDIUM
    # Compliance regime the *organisation* is subject to. An asset carrying
    # `cnsa2_noncompliant` only says the algorithm is outside the suite; it does
    # not mean this org must follow CNSA 2.0. Parameter-set selection keys off
    # this setting, not off the asset flag.
    cnsa2_required: bool = False
    services: list[ServiceTag] = field(default_factory=list)
    # PRD section 10: live probing is refused outside this list, not warned.
    scan_allowlist: list[str] = field(default_factory=list)
    authorization_attestation: str | None = None

    @classmethod
    def load(cls, path: str | Path | None) -> "Policy":
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            return cls()
        raw: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
        scoring = raw.get("scoring", {})
        services = [
            ServiceTag(
                name=s.get("name", "unnamed"),
                paths=s.get("paths", []),
                data_class=s.get("data_class"),
                criticality=Criticality(s.get("criticality", "medium")),
                surface=s.get("surface"),
            )
            for s in raw.get("services", [])
        ]
        scanning = raw.get("scanning", {})
        return cls(
            z_year=int(scoring.get("z_year", 2035)),
            urgency_scale=float(scoring.get("urgency_scale", 10.0)),
            criticality_weights={
                **{k.value: v for k, v in CRITICALITY_WEIGHT.items()},
                **scoring.get("criticality_weights", {}),
            },
            hndl_multiplier=float(scoring.get("hndl_multiplier", 0.4)),
            default_criticality=Criticality(scoring.get("default_criticality", "medium")),
            cnsa2_required=bool(raw.get("compliance", {}).get("cnsa2_required", False)),
            services=services,
            scan_allowlist=scanning.get("allowlist", []),
            authorization_attestation=scanning.get("authorization_attestation"),
        )

    def tag_for(self, location: str, service: str | None = None) -> ServiceTag | None:
        if service:
            for s in self.services:
                if s.name == service:
                    return s
        for s in self.services:
            if s.matches(location):
                return s
        return None

    def weight(self, criticality: Criticality) -> float:
        return float(self.criticality_weights.get(criticality.value, 0.7))

    def target_allowed(self, host: str) -> bool:
        """Section 10: refuse, don't warn."""
        return any(fnmatch.fnmatch(host, pattern) for pattern in self.scan_allowlist)
