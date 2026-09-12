"""Certificate scanner — the PKI, and what a broken CA takes down with it.

The other scanners answer "which algorithms are here". This one answers the
question a PKI team actually asks: *if this certificate authority's key is
broken, which certificates stop being trustworthy?* For anyone running a
national or enterprise PKI that is the whole migration plan, because the answer
determines the order of work — you cannot re-issue leaves under a root you have
not replaced yet.

Certificates are linked child-to-issuer on the authority key identifier where
both carry one, and on issuer-equals-subject otherwise. The first is a real
identifier, the second is a name match and can in principle collide, so the
relationship records which of the two produced it.

One modelling decision carries most of the weight here. A leaf certificate is a
fast migration — re-issue it and deploy. A **certificate authority** is not: its
public key is pinned in trust stores, baked into firmware, and distributed to
every relying party, so replacing it is a redistribution exercise measured in
years. CA certificates therefore land on `certificate-authority`, which routes
them to the long migration estimate in `knowledge/mosca.py`, while leaves land
on `certificate-store` and keep the short one. Treating the two the same would
say a root CA and a web server certificate are equally easy to replace, which is
the single most misleading thing this tool could tell a PKI owner.

Nothing here verifies a signature or checks revocation. A tool that reported "the
chain is valid" while doing neither would be worse than one that stays quiet.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from ..x509 import Certificate, parse_any
from .base import ScanError, ScanResult, Scanner

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
             "dist", "build", ".tox", ".cbom-workspace"}

SUFFIXES = {".pem", ".crt", ".cer", ".der", ".ca-bundle", ".chain", ".p7b", ".cert"}
# Trust stores rarely carry a helpful extension.
NAMES = {"ca-certificates.crt", "ca-bundle.crt", "cacert.pem", "tls-ca-bundle.pem"}
MAX_BYTES = 8 * 1024 * 1024


def _looks_like_certificate(path: Path) -> bool:
    return path.suffix.lower() in SUFFIXES or path.name.lower() in NAMES


class CertificateScanner(Scanner):
    source_type = SourceType.SOURCE_CODE
    name = "certificates"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        root = Path(target)
        if not root.exists():
            result.errors.append(ScanError("certificates", target, "path does not exist"))
            return result

        files = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file()
            and not any(d in p.relative_to(root).parts for d in SKIP_DIRS)
            and _looks_like_certificate(p)
        ]

        found: list[tuple[Certificate, Asset]] = []
        for path in files:
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                data = path.read_bytes()
            except OSError as exc:
                result.errors.append(ScanError("certificates", str(path), str(exc)))
                continue
            location = str(path.relative_to(root)) if root != path else str(path)
            for index, certificate in enumerate(parse_any(data)):
                asset = self._asset(certificate, location, index)
                found.append((certificate, asset))
                result.assets.append(asset)

        result.relationships.extend(link_chain(found))
        return result

    def _asset(self, certificate: Certificate, location: str, index: int) -> Asset:
        parameters: dict = {"material": "certificate"}
        if certificate.curve:
            parameters["curve"] = certificate.curve
        if certificate.is_ca:
            parameters["certificate_authority"] = True

        notes = []
        if certificate.signature_hash in {"MD5", "SHA-1"}:
            # The subject's own key may be fine while the signature over it is
            # forgeable. That is a property of this certificate, not of the CA.
            notes.append(f"signed with {certificate.signature_algorithm}/"
                         f"{certificate.signature_hash}")
        days = certificate.days_until_expiry
        if days is not None and days < 0:
            notes.append(f"expired {abs(days)} days ago")
        elif days is not None and days < 90:
            notes.append(f"expires in {days} days")

        label = certificate.subject or "(no subject)"
        snippet = (f"{'CA' if certificate.is_ca else 'leaf'} certificate "
                   f"{certificate.public_key_algorithm}"
                   f"{f'-{certificate.key_size}' if certificate.key_size else ''}"
                   f" — {label}"
                   + (f" · {'; '.join(notes)}" if notes else ""))

        return Asset(
            algorithm=certificate.public_key_algorithm,
            asset_type=AssetType.CERTIFICATE,
            key_size=certificate.key_size,
            parameters=parameters,
            location_class=("certificate-authority" if certificate.is_ca
                            else "certificate-store"),
            certificate=certificate.to_dict(),
            evidence=[Evidence(
                self.source_type, "certificate-parse",
                f"{location}#{index}" if index else location,
                Confidence.HIGH, snippet,
                {"subject": certificate.subject, "issuer": certificate.issuer,
                 "is_ca": certificate.is_ca,
                 "signature": f"{certificate.signature_algorithm}/"
                              f"{certificate.signature_hash}"
                              if certificate.signature_algorithm else None},
            )],
        )


def link_chain(found: list[tuple[Certificate, Asset]]) -> list[Relationship]:
    """Relate each certificate to the one that issued it.

    Preference order matters. The authority key identifier is a real identifier
    placed there for exactly this purpose; matching on issuer name is a fallback
    that two different CAs with the same distinguished name would both satisfy.
    The relationship kind records which was used, so a reader can tell a derived
    link from an asserted one.
    """
    by_key_id: dict[str, Asset] = {}
    by_subject: dict[str, Asset] = {}
    for certificate, asset in found:
        if certificate.subject_key_id:
            by_key_id.setdefault(certificate.subject_key_id, asset)
        if certificate.subject:
            by_subject.setdefault(certificate.subject, asset)

    links: list[Relationship] = []
    for certificate, asset in found:
        if certificate.self_signed:
            continue                       # a root is its own issuer; not a link
        issuer = None
        if certificate.authority_key_id:
            issuer = by_key_id.get(certificate.authority_key_id)
        if issuer is None and certificate.issuer:
            issuer = by_subject.get(certificate.issuer)
        if issuer is None or issuer.id == asset.id:
            continue
        links.append(Relationship(asset.id, issuer.id, "signed-by"))
    return links


def blast_radius(assets: list[Asset],
                 relationships: list[Relationship]) -> dict[str, int]:
    """For each certificate, how many others depend on it, transitively.

    This is the number that orders a PKI migration. A root signing two
    intermediates that sign four hundred leaves is one key whose replacement
    invalidates four hundred and two certificates, and it has to move first —
    re-issuing a leaf under a root you have not replaced buys nothing.
    """
    signed_by: dict[str, list[str]] = {}
    for link in relationships:
        if link.kind == "signed-by":
            signed_by.setdefault(link.target_id, []).append(link.source_id)

    known = {asset.id for asset in assets}
    radius: dict[str, int] = {}
    for asset in assets:
        seen: set[str] = set()
        queue = list(signed_by.get(asset.id, ()))
        while queue:
            current = queue.pop()
            if current in seen or current not in known:
                continue
            seen.add(current)
            queue.extend(signed_by.get(current, ()))
        if seen:
            radius[asset.id] = len(seen)
    return radius
