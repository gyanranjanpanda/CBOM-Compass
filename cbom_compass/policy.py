"""Scan and scoring policy — the human-owned inputs from PRD v1.1 section 6.3,
plus the scan-authorization gate from section 10.

Lives in a checked-in `crypto-policy.yaml` so tagging is reviewable in the same
way code is, rather than trapped in a database.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Criticality

CRITICALITY_WEIGHT = {Criticality.LOW: 0.4, Criticality.MEDIUM: 0.7, Criticality.HIGH: 1.0}


@dataclass
class DataClass:
    """A data lifetime the organisation has decided on, and where it came from.

    X is the input everything else multiplies through, and our defaults in
    `knowledge/mosca.py` are generic guesses. An organisation subject to a
    retention regime does not have to guess: the obligation states how long the
    data must stay confidential. `source` records which instrument the number
    came from, so a score can be defended to the regulator that set it rather
    than to whoever wrote the scanner.
    """

    name: str
    years: float
    # The instrument the figure comes from. Its presence is what makes the
    # provenance `regulated`, so a class with no external obligation must use
    # `note` instead — claiming regulatory backing for an internal number would
    # be the one kind of dishonesty this field exists to prevent.
    source: str | None = None
    note: str | None = None

    @property
    def basis(self) -> str | None:
        return self.source or self.note


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
    data_classes: dict[str, DataClass] = field(default_factory=dict)
    # PRD section 10: live probing is refused outside this list, not warned.
    scan_allowlist: list[str] = field(default_factory=list)
    authorization_attestation: str | None = None

    @classmethod
    def load(cls, path: str | Path | None) -> "Policy":
        # A hosted deployment has no command line to pass `--policy` on — the
        # start command is configuration held by the platform, not something a
        # risk owner edits. CBOM_POLICY lets the deployment name its policy file
        # the same way it names everything else. An explicit path still wins,
        # and nothing is picked up implicitly from the working directory: an
        # untagged scan should say so rather than silently adopt whichever
        # policy happened to be lying next to it.
        if not path:
            path = os.environ.get("CBOM_POLICY")
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
        data_classes = {}
        for name, entry in (raw.get("data_classes") or {}).items():
            if isinstance(entry, dict):
                years = entry.get("years")
                source, note = entry.get("source"), entry.get("note")
            else:
                years, source, note = entry, None, None
            try:
                data_classes[str(name).lower()] = DataClass(
                    str(name).lower(), float(years), source, note)
            except (TypeError, ValueError):
                continue

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
            data_classes=data_classes,
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

    def x_for(self, data_class: str | None) -> tuple[float, str, str | None]:
        """Data lifetime in years, its provenance, and the instrument behind it.

        An organisation's own definition wins over ours. Where it carries a
        `source`, the provenance is reported as `regulated` rather than merely
        `tagged`, because "25 years, because the Aadhaar Act says so" and
        "25 years, because someone typed it" are not the same claim.
        """
        from .knowledge import mosca

        key = (data_class or "").lower()
        own = self.data_classes.get(key)
        if own is not None:
            return own.years, ("regulated" if own.source else "tagged"), own.basis
        years, provenance = mosca.default_x(data_class)
        return years, provenance, None

    def weight(self, criticality: Criticality) -> float:
        return float(self.criticality_weights.get(criticality.value, 0.7))

    def target_allowed(self, host: str) -> bool:
        """Section 10: refuse, don't warn."""
        return any(fnmatch.fnmatch(host, pattern) for pattern in self.scan_allowlist)
