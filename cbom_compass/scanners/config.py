"""Configuration scanner — protocol cryptography that lives outside code.

The source scanner reads what an application *calls*. A very large share of an
organisation's cryptography is never called by application code at all: it is a
cipher list in `sshd_config`, an IKE proposal in `ipsec.conf`, an
`ssl_ciphers` line in nginx. None of that appears in a dependency manifest and
none of it is reachable by an AST walk, so without this module those protocols
are invisible no matter how good the other five scanners are.

Covered here:

  * **SSH** — `sshd_config`, `ssh_config`. Reuses the algorithm tables in
    `ssh.py`, so a configured algorithm and a live-offered one resolve to the
    same asset and merge.
  * **IPsec / IKE** — strongSwan `ipsec.conf` and `swanctl.conf`, Libreswan.
    Proposal strings like `aes256-sha256-modp2048` are decomposed into their
    encryption, integrity and key-agreement parts, because those are three
    different migration problems with three different answers.
  * **OpenVPN** — `cipher`, `auth`, `tls-cipher`.
  * **Web server TLS** — nginx and Apache protocol and cipher directives.
  * **S/MIME** — signing and encryption algorithms in mail configuration and in
    the CMS APIs that implement it.

Findings are `location_class: config`, which is deliberate. A configured
algorithm is a *permitted* algorithm, not necessarily one in use, so these carry
MEDIUM confidence and say so — except where the configuration is the whole
story, as with a disabled protocol version.

Everything here reads files. Nothing connects anywhere; `ssh.py` and `tls.py`
own live probing and carry the allowlist gate that goes with it.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Asset, AssetType, Confidence, Evidence, Relationship, SourceType
from .base import ScanError, ScanResult, Scanner
from .ssh import CIPHERS as SSH_CIPHERS
from .ssh import _declare_hybrid
from .ssh import HOST_KEYS as SSH_HOST_KEYS
from .ssh import KEX as SSH_KEX
from .ssh import MACS as SSH_MACS
from .ssh import _strip_etm

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".cbom-workspace"}
# Post-quantum KEMs, for recognising a hybrid IKE proposal.
PQC_KEMS = {"ML-KEM", "sntrup761", "FrodoKEM", "NTRU", "HQC"}
MAX_BYTES = 2 * 1024 * 1024        # a config file larger than this is not a config file

# --- Which files are configuration, and for which protocol -----------------
FILE_KINDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^sshd?_config$|^sshd_config\.d/|\.sshd?_config$"), "ssh"),
    (re.compile(r"^ssh_config$|^sshd_config$"), "ssh"),
    (re.compile(r"^ipsec\.conf$|^swanctl\.conf$|^strongswan\.conf$|\.swanctl$"), "ipsec"),
    (re.compile(r"^ipsec\.secrets$"), "ipsec"),
    (re.compile(r"\.ovpn$|^openvpn\.conf$|^server\.conf$|^client\.conf$"), "openvpn"),
    (re.compile(r"^nginx\.conf$|\.nginx$|^ssl\.conf$|^default\.conf$"), "webtls"),
    (re.compile(r"^httpd\.conf$|^apache2?\.conf$|^ssl-params\.conf$"), "webtls"),
    (re.compile(r"^openssl\.cnf$|^openssl\.conf$"), "smime"),
]

# --- IPsec / IKE proposal tokens -------------------------------------------
# strongSwan writes proposals as hyphen-joined tokens: aes256-sha256-modp2048.
IKE_TOKENS: dict[str, tuple[str, int | None, dict]] = {
    "des": ("DES", 56, {"mode": "CBC"}),
    "3des": ("3DES", 168, {"mode": "CBC"}),
    "cast128": ("CAST5", 128, {"mode": "CBC"}),
    "blowfish": ("Blowfish", None, {"mode": "CBC"}),
    "aes128": ("AES", 128, {"mode": "CBC"}),
    "aes192": ("AES", 192, {"mode": "CBC"}),
    "aes256": ("AES", 256, {"mode": "CBC"}),
    "aes128ctr": ("AES", 128, {"mode": "CTR"}),
    "aes256ctr": ("AES", 256, {"mode": "CTR"}),
    "aes128gcm16": ("AES", 128, {"mode": "GCM"}),
    "aes192gcm16": ("AES", 192, {"mode": "GCM"}),
    "aes256gcm16": ("AES", 256, {"mode": "GCM"}),
    "aes128gcm128": ("AES", 128, {"mode": "GCM"}),
    "aes256gcm128": ("AES", 256, {"mode": "GCM"}),
    "chacha20poly1305": ("ChaCha20", 256, {"mode": "POLY1305"}),
    "md5": ("HMAC", None, {"hash": "MD5"}),
    "sha1": ("HMAC", None, {"hash": "SHA-1"}),
    "sha": ("HMAC", None, {"hash": "SHA-1"}),
    "sha256": ("HMAC", None, {"hash": "SHA-256"}),
    "sha384": ("HMAC", None, {"hash": "SHA-384"}),
    "sha512": ("HMAC", None, {"hash": "SHA-512"}),
    "aesxcbc": ("AES", 128, {"mode": "XCBC"}),
    "modp768": ("DH", 768, {}),
    "modp1024": ("DH", 1024, {}),
    "modp1536": ("DH", 1536, {}),
    "modp2048": ("DH", 2048, {}),
    "modp3072": ("DH", 3072, {}),
    "modp4096": ("DH", 4096, {}),
    "modp6144": ("DH", 6144, {}),
    "modp8192": ("DH", 8192, {}),
    "ecp256": ("ECDH", 256, {"curve": "secp256r1"}),
    "ecp384": ("ECDH", 384, {"curve": "secp384r1"}),
    "ecp521": ("ECDH", 521, {"curve": "secp521r1"}),
    "curve25519": ("ECDH", None, {"curve": "x25519"}),
    "curve448": ("ECDH", None, {"curve": "x448"}),
    # strongSwan 6 exposes post-quantum key encapsulation as additional key
    # exchange rounds. A proposal carrying one of these is already hybrid.
    "ke1_mlkem512": ("ML-KEM", None, {"parameter_set": "ML-KEM-512"}),
    "ke1_mlkem768": ("ML-KEM", None, {"parameter_set": "ML-KEM-768"}),
    "ke1_mlkem1024": ("ML-KEM", None, {"parameter_set": "ML-KEM-1024"}),
    "mlkem512": ("ML-KEM", None, {"parameter_set": "ML-KEM-512"}),
    "mlkem768": ("ML-KEM", None, {"parameter_set": "ML-KEM-768"}),
    "mlkem1024": ("ML-KEM", None, {"parameter_set": "ML-KEM-1024"}),
    "ke1_frodoa128": ("FrodoKEM", None, {}),
    "ke1_ntru128": ("NTRU", None, {}),
}

# --- OpenVPN / OpenSSL cipher names ----------------------------------------
OPENSSL_CIPHERS: dict[str, tuple[str, int | None, dict]] = {
    "aes-128-cbc": ("AES", 128, {"mode": "CBC"}),
    "aes-192-cbc": ("AES", 192, {"mode": "CBC"}),
    "aes-256-cbc": ("AES", 256, {"mode": "CBC"}),
    "aes-128-gcm": ("AES", 128, {"mode": "GCM"}),
    "aes-256-gcm": ("AES", 256, {"mode": "GCM"}),
    "aes-128-ctr": ("AES", 128, {"mode": "CTR"}),
    "aes-256-ctr": ("AES", 256, {"mode": "CTR"}),
    "chacha20-poly1305": ("ChaCha20", 256, {"mode": "POLY1305"}),
    "des-ede3-cbc": ("3DES", 168, {"mode": "CBC"}),
    "des-cbc": ("DES", 56, {"mode": "CBC"}),
    "bf-cbc": ("Blowfish", None, {"mode": "CBC"}),
    "rc2-cbc": ("RC2", None, {"mode": "CBC"}),
    "rc4": ("RC4", 128, {}),
}
OPENVPN_AUTH: dict[str, tuple[str, int | None, dict]] = {
    "md5": ("HMAC", None, {"hash": "MD5"}),
    "sha1": ("HMAC", None, {"hash": "SHA-1"}),
    "sha256": ("HMAC", None, {"hash": "SHA-256"}),
    "sha384": ("HMAC", None, {"hash": "SHA-384"}),
    "sha512": ("HMAC", None, {"hash": "SHA-512"}),
    "none": ("none", None, {}),
}

# --- S/MIME ----------------------------------------------------------------
# S/MIME is CMS, and the algorithm is named either as an OpenSSL flag, a
# BouncyCastle CMSAlgorithm constant, or a capability OID.
SMIME_MARKERS = re.compile(
    r"application/pkcs7-(?:signature|mime)|SMIMECapabilit|"
    r"SMIMEEnvelopedGenerator|SMIMESignedGenerator|CMSAlgorithm\.|"
    r"openssl\s+smime|MimeMultipart\(\s*[\"']signed", re.I)
SMIME_ALGORITHMS: dict[str, tuple[str, int | None, dict]] = {
    "des_ede3_cbc": ("3DES", 168, {"mode": "CBC"}),
    "des3": ("3DES", 168, {"mode": "CBC"}),
    "rc2_cbc": ("RC2", None, {"mode": "CBC"}),
    "aes128_cbc": ("AES", 128, {"mode": "CBC"}),
    "aes192_cbc": ("AES", 192, {"mode": "CBC"}),
    "aes256_cbc": ("AES", 256, {"mode": "CBC"}),
    "aes128_gcm": ("AES", 128, {"mode": "GCM"}),
    "aes256_gcm": ("AES", 256, {"mode": "GCM"}),
}
# `openssl smime -des3` and friends.
SMIME_FLAGS = re.compile(r"openssl\s+smime[^\n]*?-(des3|des|rc2-40|rc2-64|rc2-128|"
                         r"aes128|aes192|aes256)\b", re.I)

# --- Web server TLS --------------------------------------------------------
TLS_VERSIONS = {
    "sslv2": "SSLv2", "sslv3": "SSLv3", "tlsv1": "TLSv1.0", "tlsv1.0": "TLSv1.0",
    "tlsv1.1": "TLSv1.1", "tlsv1.2": "TLSv1.2", "tlsv1.3": "TLSv1.3",
}
# OpenSSL suite names, e.g. ECDHE-RSA-AES128-GCM-SHA256.
SUITE_PART = {
    "ECDHE": ("ECDH", None, {}), "DHE": ("DH", None, {}), "ECDH": ("ECDH", None, {}),
    "RSA": ("RSA", None, {}), "ECDSA": ("ECDSA", None, {}), "DSS": ("DSA", None, {}),
    "AES128": ("AES", 128, {}), "AES256": ("AES", 256, {}),
    "3DES": ("3DES", 168, {}), "DES": ("DES", 56, {}), "RC4": ("RC4", 128, {}),
    "CHACHA20": ("ChaCha20", 256, {}), "SEED": ("SEED", 128, {}),
    "CAMELLIA128": ("Camellia", 128, {}), "CAMELLIA256": ("Camellia", 256, {}),
}


def parse_ike_proposal(proposal: str) -> list[tuple[str, int | None, dict]]:
    """Decompose `aes256-sha256-modp2048!` into its parts.

    Encryption, integrity and key agreement are three separate migration
    problems — AES-256 needs nothing, SHA-256 needs nothing, and modp2048 is
    Shor-broken — so collapsing a proposal into one asset would hide the only
    part that matters.
    """
    found = []
    for token in re.split(r"[-]", proposal.strip().rstrip("!").lower()):
        token = token.strip()
        mapped = IKE_TOKENS.get(token)
        if mapped:
            found.append(mapped)
    return found


def parse_openssl_suite(suite: str) -> list[tuple[str, int | None, dict]]:
    """Decompose an OpenSSL cipher-suite name into its algorithms."""
    found = []
    upper = suite.upper().strip()
    if upper.startswith("TLS_"):                 # TLS 1.3 suite, bulk cipher only
        for token, mapped in (("AES_128", ("AES", 128, {})), ("AES_256", ("AES", 256, {})),
                              ("CHACHA20", ("ChaCha20", 256, {}))):
            if token in upper:
                found.append(mapped)
        return found
    for part in upper.split("-"):
        mapped = SUITE_PART.get(part)
        if mapped:
            found.append(mapped)
    return found


def config_kind(path: Path, root: Path | None = None) -> str | None:
    """Which protocol's configuration this file is, or None if it is not one.

    Module-level rather than a scanner method because `verify.py` re-derives a
    protocol-container finding through it, and the two must not drift apart.
    """
    relative = str(path.relative_to(root)) if root and root != path else path.name
    for pattern, kind in FILE_KINDS:
        if pattern.search(path.name) or pattern.search(relative):
            return kind
    return None


class ConfigScanner(Scanner):
    source_type = SourceType.CONFIGURATION
    name = "config"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        root = Path(target)
        if not root.exists():
            result.errors.append(ScanError("config", target, "path does not exist"))
            return result
        files = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file() and not any(d in p.relative_to(root).parts for d in SKIP_DIRS)
        ]
        for path in files:
            kind = self._classify_file(path, root)
            if kind is None:
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                result.errors.append(ScanError("config", str(path), str(exc)))
                continue
            location = str(path.relative_to(root)) if root != path else str(path)
            try:
                handler = {
                    "ssh": self._scan_ssh_config,
                    "ipsec": self._scan_ipsec,
                    "openvpn": self._scan_openvpn,
                    "webtls": self._scan_web_tls,
                    "smime": self._scan_smime,
                }[kind]
                result.extend(handler(text, location))
            except Exception as exc:       # one bad file never kills the scan
                result.errors.append(ScanError("config", str(path), str(exc)))
            # S/MIME markers can appear in any file kind, and in source too.
            if kind != "smime":
                result.extend(self._scan_smime(text, location))
        return result

    @staticmethod
    def _classify_file(path: Path, root: Path) -> str | None:
        return config_kind(path, root)

    # ------------------------------------------------------------------- SSH
    def _scan_ssh_config(self, text: str, location: str) -> ScanResult:
        """`sshd_config` directives naming algorithm lists.

        A leading `+`, `-` or `^` modifies the built-in default rather than
        replacing it. `-` *removes* algorithms, so treating it as a list of
        configured algorithms would report exactly the ones an administrator
        just disabled — the opposite of the truth.
        """
        result = ScanResult()
        protocol = None
        directives = {
            "kexalgorithms": (SSH_KEX, "kex"),
            "hostkeyalgorithms": (SSH_HOST_KEYS, "host-key"),
            "pubkeyacceptedalgorithms": (SSH_HOST_KEYS, "host-key"),
            "pubkeyacceptedkeytypes": (SSH_HOST_KEYS, "host-key"),
            "ciphers": (SSH_CIPHERS, "cipher"),
            "macs": (SSH_MACS, "mac"),
        }
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, value = line.partition(" ")
            key = key.strip().lower().rstrip("=")
            value = value.strip().lstrip("=").strip()
            if key not in directives or not value:
                continue
            if value[0] == "-":
                continue                    # a removal list, not a configuration
            value = value.lstrip("+^")
            table, category = directives[key]
            if protocol is None:
                protocol = Asset(
                    algorithm="SSH-2.0", asset_type=AssetType.PROTOCOL,
                    location_class="config",
                    evidence=[Evidence(self.source_type, "config-sshd", location,
                                       Confidence.HIGH,
                                       "SSH server configuration")],
                )
                result.assets.append(protocol)
            for name in (n.strip() for n in value.split(",") if n.strip()):
                entry = table.get(_strip_etm(name)) or table.get(name)
                if entry is None:
                    continue
                # The kex table holds tuples-of-tuples because of hybrids.
                candidates = entry if isinstance(entry[0], tuple) else (entry,)
                for algorithm, key_size, parameters in candidates:
                    result.extend(self._emit(
                        algorithm, key_size,
                        _declare_hybrid(parameters, candidates, algorithm),
                        location, lineno, raw,
                        "config-sshd", f"{category} {name}", protocol))
        return result

    # ----------------------------------------------------------------- IPsec
    def _scan_ipsec(self, text: str, location: str) -> ScanResult:
        result = ScanResult()
        protocol = None
        pattern = re.compile(
            r"^\s*(ike|esp|ah|proposals|esp_proposals|ah_proposals)\s*=\s*(.+?)\s*$",
            re.I | re.M)
        for match in pattern.finditer(text):
            keyword, value = match.group(1).lower(), match.group(2)
            lineno = text[: match.start()].count("\n") + 1
            if protocol is None:
                protocol = Asset(
                    algorithm="IPsec", asset_type=AssetType.PROTOCOL,
                    location_class="config",
                    evidence=[Evidence(self.source_type, "config-ipsec", location,
                                       Confidence.HIGH,
                                       "IPsec/IKE proposal configuration")],
                )
                result.assets.append(protocol)
            for proposal in re.split(r"[,\s]+", value.strip()):
                if not proposal:
                    continue
                parts = parse_ike_proposal(proposal)
                # A proposal carrying a PQC key encapsulation round makes every
                # key-agreement token in the same proposal a hybrid half.
                pqc = next((a for a, _, _ in parts if a in PQC_KEMS), None)
                for algorithm, key_size, parameters in parts:
                    if pqc and algorithm in {"DH", "ECDH"}:
                        parameters = {**parameters, "hybrid_with": pqc}
                    result.extend(self._emit(
                        algorithm, key_size, parameters, location, lineno,
                        match.group(0), "config-ipsec",
                        f"{keyword} proposal {proposal}", protocol))
        return result

    # --------------------------------------------------------------- OpenVPN
    def _scan_openvpn(self, text: str, location: str) -> ScanResult:
        result = ScanResult()
        protocol = None
        pattern = re.compile(
            r"^\s*(cipher|auth|data-ciphers(?:-fallback)?|tls-cipher)\s+(.+?)\s*$", re.M)
        for match in pattern.finditer(text):
            keyword, value = match.group(1).lower(), match.group(2).split("#")[0].strip()
            lineno = text[: match.start()].count("\n") + 1
            if protocol is None:
                protocol = Asset(
                    algorithm="OpenVPN", asset_type=AssetType.PROTOCOL,
                    location_class="config",
                    evidence=[Evidence(self.source_type, "config-openvpn", location,
                                       Confidence.HIGH, "OpenVPN configuration")],
                )
                result.assets.append(protocol)
            for token in re.split(r"[:,\s]+", value):
                if not token:
                    continue
                low = token.lower()
                mapped = None
                if keyword == "auth":
                    mapped = OPENVPN_AUTH.get(low)
                    if mapped and mapped[0] == "none":
                        continue
                elif keyword == "tls-cipher":
                    for algorithm, key_size, parameters in parse_openssl_suite(token):
                        result.extend(self._emit(
                            algorithm, key_size, parameters, location, lineno,
                            match.group(0), "config-openvpn",
                            f"tls-cipher {token}", protocol))
                    continue
                else:
                    mapped = OPENSSL_CIPHERS.get(low)
                if mapped:
                    algorithm, key_size, parameters = mapped
                    result.extend(self._emit(
                        algorithm, key_size, parameters, location, lineno,
                        match.group(0), "config-openvpn",
                        f"{keyword} {token}", protocol))
        return result

    # ------------------------------------------------------------- Web / TLS
    def _scan_web_tls(self, text: str, location: str) -> ScanResult:
        result = ScanResult()
        protocols: dict[str, Asset] = {}
        version_pattern = re.compile(
            r"^\s*(?:ssl_protocols|SSLProtocol|SSLProxyProtocol)\s+(.+?);?\s*$",
            re.I | re.M)
        for match in version_pattern.finditer(text):
            lineno = text[: match.start()].count("\n") + 1
            for token in re.split(r"[\s+]+", match.group(1)):
                cleaned = token.strip().lstrip("+").rstrip(";").lower()
                # Apache writes `-SSLv3` to *disable* it. A disabled protocol is
                # not part of the inventory.
                if token.strip().startswith("-") or cleaned in {"all", ""}:
                    continue
                version = TLS_VERSIONS.get(cleaned)
                if version and version not in protocols:
                    asset = Asset(
                        algorithm=version, asset_type=AssetType.PROTOCOL,
                        location_class="config",
                        evidence=[Evidence(
                            self.source_type, "config-webserver",
                            f"{location}:{lineno}", Confidence.HIGH,
                            match.group(0).strip())],
                    )
                    protocols[version] = asset
                    result.assets.append(asset)

        anchor = next(iter(protocols.values()), None)
        suite_pattern = re.compile(
            r"^\s*(?:ssl_ciphers|SSLCipherSuite|ssl_conf_command\s+Ciphersuites)\s+(.+?);?\s*$",
            re.I | re.M)
        for match in suite_pattern.finditer(text):
            lineno = text[: match.start()].count("\n") + 1
            for suite in re.split(r"[:,\s]+", match.group(1).strip().strip('"\'')):
                if not suite or suite.startswith("!"):
                    continue          # `!aNULL` is an exclusion, not a suite
                for algorithm, key_size, parameters in parse_openssl_suite(suite):
                    result.extend(self._emit(
                        algorithm, key_size, parameters, location, lineno,
                        match.group(0).strip(), "config-webserver",
                        f"cipher suite {suite}", anchor))
        return result

    # ---------------------------------------------------------------- S/MIME
    def _scan_smime(self, text: str, location: str) -> ScanResult:
        """S/MIME, detected by its CMS markers and the algorithm each names."""
        result = ScanResult()
        if not SMIME_MARKERS.search(text):
            return result
        marker = SMIME_MARKERS.search(text)
        lineno = text[: marker.start()].count("\n") + 1
        protocol = Asset(
            algorithm="S/MIME", asset_type=AssetType.PROTOCOL, location_class="config",
            evidence=[Evidence(self.source_type, "config-smime",
                               f"{location}:{lineno}", Confidence.MEDIUM,
                               marker.group(0).strip())],
        )
        result.assets.append(protocol)

        for match in re.finditer(r"CMSAlgorithm\.([A-Z0-9_]+)", text):
            mapped = SMIME_ALGORITHMS.get(match.group(1).lower())
            if mapped:
                algorithm, key_size, parameters = mapped
                line = text[: match.start()].count("\n") + 1
                result.extend(self._emit(
                    algorithm, key_size, parameters, location, line,
                    match.group(0), "config-smime",
                    f"CMS content encryption {match.group(1)}", protocol))
        for match in SMIME_FLAGS.finditer(text):
            flag = match.group(1).lower().replace("-", "")
            mapped = SMIME_ALGORITHMS.get(
                {"des3": "des_ede3_cbc", "des": "des_ede3_cbc",
                 "aes128": "aes128_cbc", "aes192": "aes192_cbc",
                 "aes256": "aes256_cbc"}.get(flag, "rc2_cbc"))
            if mapped:
                algorithm, key_size, parameters = mapped
                line = text[: match.start()].count("\n") + 1
                result.extend(self._emit(
                    algorithm, key_size, parameters, location, line,
                    match.group(0), "config-smime",
                    f"openssl smime -{match.group(1)}", protocol))
        return result

    # ---------------------------------------------------------------- helper
    def _emit(self, algorithm: str, key_size: int | None, parameters: dict,
              location: str, lineno: int, snippet: str, method: str,
              because: str, protocol: Asset | None) -> ScanResult:
        """One configured algorithm, related back to the protocol that names it.

        MEDIUM confidence throughout: a configuration lists what is *permitted*,
        and a permitted algorithm is not proof of a negotiated one. The live
        probes in `ssh.py` and `tls.py` are what upgrade that to observed, and
        because both resolve to the same normalised asset, an algorithm seen in
        both places is corroborated by two independent techniques and promoted
        automatically.
        """
        from ..knowledge.algorithms import classify, normalise
        from ..models import QuantumStatus

        result = ScanResult()
        if classify(algorithm).quantum_status is QuantumStatus.UNKNOWN:
            return result
        asset = Asset(
            algorithm=normalise(algorithm), asset_type=AssetType.ALGORITHM,
            key_size=key_size, parameters=dict(parameters),
            location_class="config",
            evidence=[Evidence(self.source_type, method, f"{location}:{lineno}",
                               Confidence.MEDIUM, snippet.strip()[:200],
                               {"configured_as": because})],
        )
        result.assets.append(asset)
        if protocol is not None:
            result.relationships.append(Relationship(asset.id, protocol.id, "negotiated-by"))
        return result
