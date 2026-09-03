"""Dependency scanner — manifest parsing cross-referenced against the crypto
library knowledge base (PRD v1.1 section 6.1).

Yields high confidence on the library version and medium on algorithm *usage*:
a manifest tells you OpenSSL is present, not that the RSA code path is reached.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..knowledge.libraries import LIBRARY_ALGORITHMS, algorithms_for, is_abandoned
from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from .base import ScanError, ScanResult, Scanner

# Directories skipped *relative to the scan root*. Matching against the
# absolute path would skip everything when the root is itself inside one of
# these (e.g. scanning a virtualenv's site-packages on purpose).
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
MANIFESTS = {"requirements.txt", "package.json", "pom.xml", "go.mod", "Pipfile", "pyproject.toml"}


class DependencyScanner(Scanner):
    source_type = SourceType.DEPENDENCY
    name = "dependencies"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        root = Path(target)
        if not root.exists():
            result.errors.append(ScanError("dependency", target, "path does not exist"))
            return result
        manifests = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.name in MANIFESTS
            and not any(d in p.relative_to(root).parts for d in SKIP_DIRS)
        ]
        for path in manifests:
            try:
                result.extend(self._parse(path, root))
            except Exception as exc:
                result.errors.append(ScanError("dependency", str(path), str(exc)))
        return result

    def _parse(self, path: Path, root: Path) -> ScanResult:
        text = path.read_text(encoding="utf-8", errors="replace")
        loc = str(path.relative_to(root)) if root != path else path.name
        if path.name == "requirements.txt":
            deps = self._requirements(text)
        elif path.name == "package.json":
            deps = self._package_json(text)
        elif path.name == "pom.xml":
            deps = self._pom(text)
        elif path.name == "go.mod":
            deps = self._go_mod(text)
        else:
            deps = self._requirements(text)
        return self._to_assets(deps, loc)

    @staticmethod
    def _requirements(text: str) -> list[tuple[str, str | None]]:
        deps = []
        for line in text.splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=<>~!]=?\s*([0-9][\w.\-]*))?", line)
            if match:
                deps.append((match.group(1), match.group(2)))
        return deps

    @staticmethod
    def _package_json(text: str) -> list[tuple[str, str | None]]:
        data = json.loads(text)
        deps = []
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                deps.append((name, str(ver).lstrip("^~>=< ")))
        return deps

    @staticmethod
    def _pom(text: str) -> list[tuple[str, str | None]]:
        deps = []
        for block in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
            body = block.group(1)
            artifact = re.search(r"<artifactId>([^<]+)</artifactId>", body)
            version = re.search(r"<version>([^<]+)</version>", body)
            if artifact:
                deps.append((artifact.group(1), version.group(1) if version else None))
        return deps

    @staticmethod
    def _go_mod(text: str) -> list[tuple[str, str | None]]:
        deps = []
        for match in re.finditer(r"^\s*([\w./\-]+)\s+v([\w.\-+]+)", text, re.M):
            deps.append((match.group(1), match.group(2)))
        return deps

    def _to_assets(self, deps: list[tuple[str, str | None]], loc: str) -> ScanResult:
        result = ScanResult()
        for name, version in deps:
            key = name.lower()
            known = key in LIBRARY_ALGORITHMS or any(
                key.endswith(k) or k in key for k in LIBRARY_ALGORITHMS
            )
            if not known:
                continue
            resolved = next(
                (k for k in LIBRARY_ALGORITHMS if k == key or key.endswith(k) or k in key), key
            )
            notes = []
            if is_abandoned(resolved):
                notes.append("library is unmaintained")
            library_asset = Asset(
                algorithm=resolved,
                asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                library=resolved,
                library_version=version,
                location_class="manifest",
                evidence=[Evidence(
                    self.source_type, "manifest-parse", loc, Confidence.HIGH,
                    f"{name}=={version or 'unpinned'}",
                    {"notes": notes},
                )],
            )
            result.assets.append(library_asset)
            for algorithm in algorithms_for(resolved):
                result.assets.append(Asset(
                    algorithm=algorithm,
                    asset_type=AssetType.ALGORITHM,
                    library=resolved,
                    library_version=version,
                    location_class="manifest",
                    evidence=[Evidence(
                        self.source_type, "manifest-parse", loc, Confidence.MEDIUM,
                        f"{name}=={version or 'unpinned'} exposes {algorithm}",
                    )],
                ))
                result.relationships.append(Relationship(
                    source_id=result.assets[-1].id, target_id=library_asset.id, kind="depends-on"
                ))
        return result
