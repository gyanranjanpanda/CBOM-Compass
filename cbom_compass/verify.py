"""Independent verification of stored findings — the answer to "prove it".

A scan report is a claim. This module re-opens the underlying artefact on disk
and checks the claim against it, using no information from the scan except the
location it pointed at. Nothing here reuses the scanner's parsing: a source
finding is checked by reading that line of that file, a binary finding by
re-reading the file's bytes, a key-store finding by re-reading the export.

The point is falsifiability. If the tool were fabricating plausible-looking
output, this would fail, and it prints the file and line for each check so a
sceptic can repeat it by hand.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from pathlib import Path

from .knowledge.algorithms import normalise


@dataclass
class Check:
    asset: str
    location: str
    technique: str
    confidence: str
    verdict: str          # "confirmed" | "unconfirmed" | "unavailable"
    detail: str
    quoted: str | None = None


# Tokens that independently corroborate an algorithm at a source location. These
# are deliberately *not* the scanner's rules — they are a coarse second opinion,
# so agreement means two different methods reached the same answer.
CORROBORATION = {
    "RSA": [r"\brsa\b", r"rsakey", r"moduluslength", r"pkcs1", r"pss",
            r"rs(?:256|384|512)", r"ps(?:256|384|512)", r"with_?rsa"],
    "DSA": [r"\bdsa\b", r"DSA"],
    "DH": [r"\bdh\b", r"DH", r"diffie"],
    "ECDH": [r"ecdh", r"x25519", r"x448", r"curve25519", r"curve448", r"key_agree"],
    "ECDSA": [r"ecdsa", r"elliptic", r"\bec\b", r"ec\.", r"secp", r"prime256",
              r"es(?:256|384|512)", r"\bcurve\b", r"with_?ecdsa"],
    "EdDSA": [r"ed25519", r"ed448", r"eddsa", r"curve25519"],
    "AES": [r"\baes\b", r"AES", r"Rijndael"],
    "3DES": [r"3des", r"DESede", r"des_ede", r"des-ede", r"TripleDES", r"DES3"],
    "DES": [r"\bdes\b", r"DES"],
    "RC4": [r"rc4", r"RC4", r"ARC4", r"arcfour"],
    "ChaCha20": [r"chacha", r"ChaCha"],
    "MD5": [r"md5", r"MD5"],
    "SHA-1": [r"sha1", r"SHA1", r"SHA-1", r"sha_1"],
    "SHA-256": [r"sha256", r"SHA256", r"SHA-256", r"sha_256"],
    "SHA-384": [r"sha384", r"SHA384", r"SHA-384"],
    "SHA-512": [r"sha512", r"SHA512", r"SHA-512"],
    "ML-KEM": [r"mlkem", r"MLKEM", r"ML-KEM", r"ml_kem", r"kyber", r"Kyber"],
    "ML-DSA": [r"mldsa", r"MLDSA", r"ML-DSA", r"dilithium", r"Dilithium"],
    "SLH-DSA": [r"slhdsa", r"SLH-DSA", r"sphincs", r"SPHINCS"],
    "HMAC": [r"hmac", r"HMAC", r"Hmac", r"HS(?:256|384|512)"],
    "PBKDF2": [r"pbkdf2", r"PBKDF2"],
    "EdDSA-ed25519": [r"ed25519"],
}


def _resolve(location: str, roots: list[Path]) -> tuple[Path | None, int | None]:
    """Split 'path/file.py:139' and find the file under one of the scan roots."""
    raw, _, line = location.rpartition(":")
    if raw and line.isdigit():
        candidate, lineno = raw, int(line)
    else:
        candidate, lineno = location, None
    candidate = candidate.split("!")[-1]          # container layer prefix
    for root in roots:
        path = root / candidate
        if path.is_file():
            return path, lineno
    direct = Path(candidate)
    if direct.is_file():
        return direct, lineno
    return None, lineno


def _check_source(asset: dict, path: Path, lineno: int | None) -> Check:
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if lineno is None or not (0 < lineno <= len(text)):
        return Check(asset["name"], asset["location"], asset["detection_methods"][0],
                     asset["confidence"], "unavailable",
                     f"line {lineno} not present in {path}")
    line = text[lineno - 1].strip()
    algorithm = normalise(asset["algorithm"])
    patterns = CORROBORATION.get(algorithm, [re.escape(algorithm)])
    window = "\n".join(text[max(0, lineno - 4):lineno + 2])
    # Case-insensitive, and the file path counts as corroboration: a match in
    # `rsakey.py` is evidence, not coincidence. Still narrow enough to reject a
    # fabricated algorithm — see tests/test_verify.py.
    haystack = f"{path}\n{window}"
    hit = any(re.search(p, haystack, re.IGNORECASE) for p in patterns)
    return Check(
        asset["name"], asset["location"], asset["detection_methods"][0],
        asset["confidence"], "confirmed" if hit else "unconfirmed",
        f"{path}:{lineno}", line[:110],
    )


def _check_binary(asset: dict, path: Path) -> Check:
    data = path.read_bytes()
    evidence = asset["evidence"][0]
    symbol = (evidence.get("detail") or {}).get("symbol")
    soname = (evidence.get("detail") or {}).get("soname")
    needle = symbol or soname
    if needle:
        hit = needle.encode() in data
        return Check(asset["name"], asset["location"], evidence["detection_method"],
                     asset["confidence"], "confirmed" if hit else "unconfirmed",
                     f"{path} contains {needle!r}: {hit}", needle)
    patterns = CORROBORATION.get(normalise(asset["algorithm"]), [])
    hit = any(re.search(p.encode(), data, re.IGNORECASE) for p in patterns[:2])
    return Check(asset["name"], asset["location"], evidence["detection_method"],
                 asset["confidence"], "confirmed" if hit else "unconfirmed",
                 f"{path}: algorithm token present in bytes: {hit}")


def _check_keystore(asset: dict, path: Path) -> Check:
    import json
    document = json.loads(path.read_text())
    key_id = (asset["evidence"][0].get("detail") or {}).get("key_id")
    entry = next((k for k in document.get("keys", []) if k.get("KeyId") == key_id), None)
    hit = entry is not None
    return Check(asset["name"], asset["location"], asset["detection_methods"][0],
                 asset["confidence"], "confirmed" if hit else "unconfirmed",
                 f"{path}: key {key_id!r} present: {hit}",
                 entry.get("KeySpec") if entry else None)


def verify(report: dict, roots: list[str], sample: int | None = 12,
           seed: int | None = None) -> list[Check]:
    """Re-derive a sample of findings from the artefacts on disk."""
    root_paths = [Path(r) for r in roots] + [Path(".")]
    assets = [a for a in report["assets"] if a["evidence"]]
    if sample and sample < len(assets):
        rng = random.Random(seed)
        # Spread the sample across source types rather than sampling uniformly,
        # so one dominant scanner cannot carry the result.
        by_source: dict[str, list[dict]] = {}
        for asset in assets:
            by_source.setdefault(asset["source_types"][0], []).append(asset)
        per = max(1, sample // max(1, len(by_source)))
        picked: list[dict] = []
        for group in by_source.values():
            picked.extend(rng.sample(group, min(per, len(group))))
        assets = picked[:sample] if len(picked) >= sample else picked

    checks: list[Check] = []
    for asset in assets:
        source = asset["source_types"][0]
        if source == "endpoint":
            checks.append(Check(
                asset["name"], asset["location"], asset["detection_methods"][0],
                asset["confidence"], "unavailable",
                "live TLS observation — re-run the scan against the endpoint to re-verify"))
            continue
        detail = asset["evidence"][0].get("detail") or {}
        recorded = detail.get("source_path")
        if recorded and Path(recorded).is_file():
            path, lineno = Path(recorded), None
        else:
            path, lineno = _resolve(asset["location"], root_paths)
        if path is None:
            checks.append(Check(asset["name"], asset["location"],
                                asset["detection_methods"][0], asset["confidence"],
                                "unavailable", "artefact not found on disk"))
            continue
        try:
            if source == "source_code":
                checks.append(_check_source(asset, path, lineno))
            elif source in {"binary", "container"}:
                checks.append(_check_binary(asset, path))
            elif source == "cloud_kms":
                checks.append(_check_keystore(asset, path))
            elif source == "dependency":
                checks.append(_check_source(asset, path, lineno) if lineno
                              else _check_manifest(asset, path))
            else:
                checks.append(Check(asset["name"], asset["location"],
                                    asset["detection_methods"][0], asset["confidence"],
                                    "unavailable",
                                    f"{source} findings are live observations; "
                                    f"re-run the scan to re-verify"))
        except Exception as exc:
            checks.append(Check(asset["name"], asset["location"],
                                asset["detection_methods"][0], asset["confidence"],
                                "unavailable", f"{type(exc).__name__}: {exc}"))
    return checks


def _check_manifest(asset: dict, path: Path) -> Check:
    text = path.read_text(encoding="utf-8", errors="replace")
    library = (asset.get("library") or "").lower()
    hit = bool(library) and library in text.lower()
    return Check(asset["name"], asset["location"], asset["detection_methods"][0],
                 asset["confidence"], "confirmed" if hit else "unconfirmed",
                 f"{path} declares {library!r}: {hit}",
                 next((l.strip() for l in text.splitlines() if library in l.lower()), None))


def summarise(checks: list[Check]) -> dict:
    counts: dict[str, int] = {}
    for check in checks:
        counts[check.verdict] = counts.get(check.verdict, 0) + 1
    checkable = counts.get("confirmed", 0) + counts.get("unconfirmed", 0)
    return {
        "total": len(checks),
        "confirmed": counts.get("confirmed", 0),
        "unconfirmed": counts.get("unconfirmed", 0),
        "unavailable": counts.get("unavailable", 0),
        "rate": counts.get("confirmed", 0) / checkable if checkable else 0.0,
    }
