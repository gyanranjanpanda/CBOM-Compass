"""Container scanner — PRD v1.1 section 6.1.

The differentiator is *not* the base image's OpenSSL version — that overlaps
what the dependency scanner already reports. It is embedded key material and
certificates baked into layers, which nothing else finds.

Uses `syft` for the SBOM when available, and otherwise falls back to walking the
extracted layers directly, so the product still works on a machine without it.
Accepts an image reference (pulled via `docker save`) or an already-extracted
directory / tarball.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from ..knowledge.libraries import algorithms_for
from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from .base import ScanError, ScanResult, Scanner
from .binary import BinaryScanner
from .dependencies import DependencyScanner

PEM_PATTERNS = [
    (re.compile(rb"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
     "private-key", Confidence.HIGH),
    (re.compile(rb"-----BEGIN CERTIFICATE-----"), "certificate", Confidence.HIGH),
]
KEY_FILE_HINTS = (".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks")
MAX_FILE = 8 * 1024 * 1024


class ContainerScanner(Scanner):
    source_type = SourceType.CONTAINER
    name = "container"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        path = Path(target)
        if path.is_dir():
            return self._scan_tree(path, target)
        if path.is_file() and tarfile.is_tarfile(path):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    self._extract(path, Path(tmp))
                except Exception as exc:
                    result.errors.append(ScanError("container", target, f"extract failed: {exc}"))
                    return result
                return self._scan_tree(Path(tmp), target)
        # Treat as an image reference.
        return self._scan_image(target)

    # --------------------------------------------------------------- image ref
    def _scan_image(self, image: str) -> ScanResult:
        result = ScanResult()
        if shutil.which("syft"):
            result.extend(self._syft(image))
        if not shutil.which("docker"):
            if not result.assets:
                result.errors.append(ScanError(
                    "container", image,
                    "neither syft nor docker available; pass an extracted directory or tarball instead",
                ))
            return result
        with tempfile.TemporaryDirectory() as tmp:
            tar = Path(tmp) / "image.tar"
            try:
                subprocess.run(["docker", "save", "-o", str(tar), image],
                               capture_output=True, check=True, timeout=600)
                self._extract(tar, Path(tmp) / "fs")
            except subprocess.CalledProcessError as exc:
                result.errors.append(ScanError(
                    "container", image, f"docker save failed: {exc.stderr.decode()[:200]}"))
                return result
            except Exception as exc:
                result.errors.append(ScanError("container", image, str(exc)))
                return result
            result.extend(self._scan_tree(Path(tmp) / "fs", image))
        return result

    @staticmethod
    def _extract(tar_path: Path, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path) as tf:
            tf.extractall(dest, filter="data")
        # Docker image tarballs contain nested layer tarballs.
        for layer in list(dest.rglob("*.tar")) + list(dest.rglob("layer.tar")):
            try:
                out = layer.parent / f"{layer.stem}_extracted"
                out.mkdir(exist_ok=True)
                with tarfile.open(layer) as lf:
                    lf.extractall(out, filter="data")
            except Exception:
                continue

    def _syft(self, image: str) -> ScanResult:
        result = ScanResult()
        try:
            proc = subprocess.run(["syft", image, "-o", "json"],
                                  capture_output=True, text=True, timeout=600)
            data = json.loads(proc.stdout or "{}")
        except Exception as exc:
            result.errors.append(ScanError("container", image, f"syft: {exc}"))
            return result
        for artifact in data.get("artifacts", []):
            name, version = artifact.get("name", ""), artifact.get("version")
            algorithms = algorithms_for(name)
            if not algorithms:
                continue
            lib = Asset(
                algorithm=name, asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                library=name, library_version=version, location_class="image-layer",
                evidence=[Evidence(self.source_type, "syft-sbom", f"{image}:{name}",
                                   Confidence.HIGH, f"{name} {version}")],
            )
            result.assets.append(lib)
            for algorithm in algorithms:
                result.assets.append(Asset(
                    algorithm=algorithm, library=name, library_version=version,
                    location_class="image-layer",
                    evidence=[Evidence(self.source_type, "syft-sbom", f"{image}:{name}",
                                       Confidence.MEDIUM, f"{name} {version} exposes {algorithm}")],
                ))
                result.relationships.append(Relationship(result.assets[-1].id, lib.id, "bundled-in"))
        return result

    # ------------------------------------------------------------------- tree
    def _scan_tree(self, root: Path, label: str) -> ScanResult:
        """Run the source and binary scanners over the layer filesystem, then do
        the thing only a container scanner can: find baked-in key material."""
        result = ScanResult()
        try:
            dep = DependencyScanner(self.policy).scan(str(root))
            binr = BinaryScanner(self.policy).scan(str(root))
            for asset in dep.assets + binr.assets:
                for ev in asset.evidence:
                    ev.source_type = self.source_type
                    ev.location = f"{label}!{ev.location}"
                asset.location_class = "image-layer"
            result.extend(dep)
            result.extend(binr)
            result.errors = [e for e in result.errors if "does not exist" not in e.message]
        except Exception as exc:
            result.errors.append(ScanError("container", label, str(exc)))
        result.extend(self._key_material(root, label))
        return result

    def _key_material(self, root: Path, label: str) -> ScanResult:
        """Embedded private keys and certificates — the differentiated find.

        Section 10: we record a fingerprint and location, never the key bytes.
        """
        result = ScanResult()
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                if path.stat().st_size > MAX_FILE:
                    continue
                if path.suffix.lower() not in KEY_FILE_HINTS and path.stat().st_size > 512 * 1024:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            for pattern, kind, confidence in PEM_PATTERNS:
                match = pattern.search(data)
                if not match:
                    continue
                import hashlib
                fingerprint = hashlib.sha256(data).hexdigest()[:32]
                rel = path.relative_to(root)
                is_key = kind == "private-key"
                result.assets.append(Asset(
                    algorithm="RSA" if b"RSA PRIVATE" in match.group(0) else "unknown",
                    asset_type=(AssetType.RELATED_CRYPTO_MATERIAL if is_key
                                else AssetType.CERTIFICATE),
                    location_class="image-layer",
                    parameters={"material": kind},
                    certificate=None if is_key else {"fingerprint_sha256": fingerprint},
                    evidence=[Evidence(
                        self.source_type, "layer-key-material", f"{label}!{rel}",
                        confidence,
                        f"{kind} embedded in image layer "
                        f"(fingerprint {fingerprint[:16]}…, key bytes not stored)",
                        {"fingerprint_sha256": fingerprint, "material": kind},
                    )],
                ))
                break
        return result
