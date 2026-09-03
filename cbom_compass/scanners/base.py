from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Asset, Relationship, SourceType
from ..policy import Policy


@dataclass
class ScanError:
    source_type: str
    target: str
    message: str


@dataclass
class ScanResult:
    assets: list[Asset] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    def extend(self, other: "ScanResult") -> None:
        self.assets.extend(other.assets)
        self.relationships.extend(other.relationships)
        self.errors.extend(other.errors)


class Scanner:
    """Base scanner. A scanner that raises never blocks the other five —
    the orchestrator degrades to a per-source error banner (PRD section 8.3)."""

    source_type: SourceType
    name: str = "scanner"

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or Policy()

    def scan(self, target: str) -> ScanResult:  # pragma: no cover - interface
        raise NotImplementedError
