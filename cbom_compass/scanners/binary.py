"""Binary scanner — PRD v1.1 section 6.1.

Rescoped twice. v1.0 proposed YARA constant matching; a hit on an AES S-box
tells you a constant table is present but not the key size, the mode, or whether
the code path is reachable, so the finding cannot be assigned an X, a Y or a
criticality and becomes an unscoreable dead-end row.

This version parses the binary properly. LIEF reads the **import table**
(ELF `DT_NEEDED` and dynamic symbols, Mach-O `LOAD_DYLIB` and imported
functions, PE import descriptors), which yields two structural facts:

  * which crypto libraries are linked, by name and version;
  * which crypto functions are actually imported, which names the algorithm and
    sometimes the key size and mode (`EVP_aes_128_gcm`).

That is genuinely high-confidence evidence and it feeds the same knowledge base
as the dependency scanner. Byte scanning remains as a fallback for binaries LIEF
cannot parse, and constant matching stays a low-confidence supplementary signal
that never stands alone.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..knowledge.libraries import (BINARY_SIGNATURES, LINKED_LIBRARY_HINTS,
                                   SYMBOL_ALGORITHMS, SYMBOL_KEY_SIZE,
                                   SYMBOL_PARAMETERS, algorithms_for)
from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from .base import ScanError, ScanResult, Scanner

try:  # LIEF is optional; the byte-scan fallback covers its absence.
    import lief

    lief.logging.disable()
    HAVE_LIEF = True
except Exception:  # pragma: no cover - exercised only on installs without LIEF
    HAVE_LIEF = False

MAGIC = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O-fat",
}

# Supplementary low-confidence signal only (see module docstring).
CONSTANTS = {
    "AES": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),   # S-box head
    "SHA-256": bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa5"),     # H0..H1 LE
    "MD5": bytes.fromhex("0123456789abcdeffedcba9876543210"),
}
MAX_BYTES = 128 * 1024 * 1024
VERSION_IN_SONAME = re.compile(r"(\d+(?:\.\d+){1,3}[a-z]?)")


def _strip_symbol(name: str) -> str:
    """Mach-O prefixes imported symbols with an underscore; PE may suffix @N."""
    return name.lstrip("_").split("@")[0]


class BinaryScanner(Scanner):
    source_type = SourceType.BINARY
    name = "binary"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        root = Path(target)
        if not root.exists():
            result.errors.append(ScanError("binary", target, "path does not exist"))
            return result
        candidates = [root] if root.is_file() else [
            p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts
        ]
        for path in candidates:
            try:
                fmt = self._format(path)
                if not fmt:
                    continue
                parsed = self._scan_with_lief(path, root, fmt) if HAVE_LIEF else None
                if parsed is None:
                    result.extend(self._scan_bytes(path, root, fmt))
                    continue
                result.extend(parsed)
                if not self._has_import_evidence(parsed):
                    # A statically-linked or stripped binary has no import table
                    # by construction, so a clean structural parse that yields
                    # nothing is exactly the case byte scanning exists for.
                    # Its findings carry lower confidence and say why.
                    result.extend(self._scan_bytes(path, root, fmt))
            except Exception as exc:
                result.errors.append(ScanError("binary", str(path), str(exc)))
        return result

    @staticmethod
    def _has_import_evidence(result: ScanResult) -> bool:
        return any(
            ev.detection_method == "binary-import-table"
            for asset in result.assets for ev in asset.evidence
        )

    @staticmethod
    def _format(path: Path) -> str | None:
        try:
            head = path.open("rb").read(4)
        except OSError:
            return None
        for magic, fmt in MAGIC.items():
            if head.startswith(magic):
                return fmt
        return None

    # ------------------------------------------------------------------ LIEF
    def _scan_with_lief(self, path: Path, root: Path, fmt: str) -> ScanResult | None:
        """Structural parse. Returns None if LIEF cannot read the file, so the
        caller can fall back to byte scanning."""
        try:
            binary = lief.parse(str(path))
        except Exception:
            return None
        if binary is None:
            return None

        result = ScanResult()
        loc = str(path.relative_to(root)) if root != path else str(path)

        # --- linked crypto libraries, from the import table -----------------
        library_assets: dict[str, Asset] = {}
        for entry in getattr(binary, "libraries", []) or []:
            soname = getattr(entry, "name", None) or str(entry)
            if "\n" in soname:                       # a LOAD_DYLIB command repr
                continue
            base = Path(soname).name.lower()
            match = next((lib for frag, lib in LINKED_LIBRARY_HINTS if frag in base), None)
            if match is None:
                continue
            version_match = VERSION_IN_SONAME.search(base)
            version = version_match.group(1) if version_match else None
            asset = Asset(
                algorithm=match, asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                library=match, library_version=version, location_class="linked-library",
                evidence=[Evidence(
                    self.source_type, "binary-import-table", loc, Confidence.HIGH,
                    f"{fmt}: links {soname}",
                    {"soname": soname},
                )],
            )
            library_assets[match] = asset
            result.assets.append(asset)
            for algorithm in algorithms_for(match):
                result.assets.append(Asset(
                    algorithm=algorithm, library=match, library_version=version,
                    location_class="linked-library",
                    evidence=[Evidence(
                        self.source_type, "binary-import-table", loc, Confidence.MEDIUM,
                        f"linked {match} exposes {algorithm}")],
                ))
                result.relationships.append(
                    Relationship(result.assets[-1].id, asset.id, "depends-on"))

        # --- imported crypto functions, which name the algorithm ------------
        imported = set()
        for symbol in getattr(binary, "imported_functions", []) or []:
            name = getattr(symbol, "name", None) or str(symbol)
            imported.add(_strip_symbol(name))
        for symbol in getattr(binary, "imported_symbols", []) or []:
            name = getattr(symbol, "name", None) or str(symbol)
            imported.add(_strip_symbol(name))

        seen: set[tuple] = set()
        for raw, algorithm in SYMBOL_ALGORITHMS.items():
            symbol = raw.decode()
            if symbol not in imported or algorithm == "unknown":
                continue
            key_size, mode = SYMBOL_PARAMETERS.get(raw, (SYMBOL_KEY_SIZE.get(raw), None))
            identity = (algorithm, key_size, mode)
            if identity in seen:
                continue
            seen.add(identity)
            result.assets.append(Asset(
                algorithm=algorithm, key_size=key_size,
                parameters={"mode": mode} if mode else {},
                location_class="linked-library",
                evidence=[Evidence(
                    self.source_type, "binary-import-table", loc, Confidence.HIGH,
                    f"{fmt}: imports {symbol}", {"symbol": symbol})],
            ))

        # --- version strings, which the import table does not carry ----------
        result.extend(self._version_strings(path, root, fmt, skip=set(library_assets)))
        return result

    def _version_strings(self, path: Path, root: Path, fmt: str,
                         skip: set[str]) -> ScanResult:
        """Library version banners live in .rodata, not in any table."""
        result = ScanResult()
        loc = str(path.relative_to(root)) if root != path else str(path)
        try:
            data = path.read_bytes()[:MAX_BYTES]
        except OSError:
            return result
        for pattern, library in BINARY_SIGNATURES:
            match = re.search(pattern, data)
            if not match:
                continue
            version = None
            if match.groups():
                try:
                    version = match.group(1).decode("ascii", "replace")
                except Exception:
                    version = None
            if library in skip and version is None:
                continue
            result.assets.append(Asset(
                algorithm=library, asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                library=library, library_version=version, location_class="linked-library",
                evidence=[Evidence(
                    self.source_type, "binary-version-string", loc, Confidence.HIGH,
                    f"{fmt}: {library} {version or '(version not resolved)'}")],
            ))
        return result

    # ------------------------------------------------------- byte fallback
    def _scan_bytes(self, path: Path, root: Path, fmt: str) -> ScanResult:
        """Used when LIEF is absent or the file is too damaged to parse.

        Everything here is weaker than the structural parse: a symbol name
        appearing in the file is not proof it is imported, so confidence drops
        one level accordingly.
        """
        result = ScanResult()
        data = path.read_bytes()[:MAX_BYTES]
        loc = str(path.relative_to(root)) if root != path else str(path)

        result.extend(self._version_strings(path, root, fmt, skip=set()))
        for library in {lib for _, lib in BINARY_SIGNATURES if re.search(
                next(p for p, l in BINARY_SIGNATURES if l == lib), data)}:
            for algorithm in algorithms_for(library):
                result.assets.append(Asset(
                    algorithm=algorithm, library=library, location_class="linked-library",
                    evidence=[Evidence(
                        self.source_type, "binary-version-string", loc, Confidence.MEDIUM,
                        f"linked {library} exposes {algorithm}")],
                ))

        seen: set[tuple] = set()
        for raw, algorithm in SYMBOL_ALGORITHMS.items():
            if raw not in data or algorithm == "unknown":
                continue
            key_size, mode = SYMBOL_PARAMETERS.get(raw, (SYMBOL_KEY_SIZE.get(raw), None))
            identity = (algorithm, key_size, mode)
            if identity in seen:
                continue
            seen.add(identity)
            result.assets.append(Asset(
                algorithm=algorithm, key_size=key_size,
                parameters={"mode": mode} if mode else {},
                location_class="linked-library",
                evidence=[Evidence(
                    self.source_type, "binary-symbol-string", loc, Confidence.MEDIUM,
                    f"{fmt}: symbol name {raw.decode()} present "
                    f"(not confirmed imported — LIEF could not parse this file)")],
            ))

        for algorithm, blob in CONSTANTS.items():
            if blob in data:
                result.assets.append(Asset(
                    algorithm=algorithm, location_class="linked-library",
                    evidence=[Evidence(
                        self.source_type, "binary-constant", loc, Confidence.LOW,
                        f"{fmt}: {algorithm} constant table present (presence only — "
                        f"no key size, mode or reachability)")],
                ))
        return result
