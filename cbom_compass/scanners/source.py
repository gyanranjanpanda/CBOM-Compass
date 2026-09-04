"""Source-code scanner — PRD v1.1 section 6.1.

Python is scanned with the stdlib `ast` module: we walk Call nodes, resolve the
dotted callee, and pull key sizes and curves out of the actual arguments. That
gives high confidence when an argument is a literal and medium when it is a
variable, which is exactly the confidence distinction the UI needs.

Java/JS/Go use pattern rules, which is why their findings carry medium
confidence while Python's carry high.

KNOWN LIMITATION: no semgrep integration. Semgrep would add cross-procedural
matching and a maintained rule corpus, but wiring it in means authoring real
crypto rules, not reusing an off-the-shelf ruleset — `p/secrets` finds hardcoded
credentials, not algorithm selection. That is Phase 2. Measured accuracy for
what is implemented here is in `corpus/` (run `cbom-compass eval`).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..knowledge.algorithms import ALIASES
from ..models import Asset, AssetType, Confidence, Evidence, SourceType
from .base import ScanError, ScanResult, Scanner

# Directories skipped *relative to the scan root*. Matching against the
# absolute path would skip everything when the root is itself inside one of
# these (e.g. scanning a virtualenv's site-packages on purpose).
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}

# --- Python: dotted call suffix -> (algorithm, extra params) ---------------
PY_CALL_RULES: dict[str, tuple[str, dict]] = {
    "hashlib.md5": ("MD5", {}), "hashlib.sha1": ("SHA-1", {}),
    "hashlib.sha256": ("SHA-256", {}), "hashlib.sha384": ("SHA-384", {}),
    "hashlib.sha512": ("SHA-512", {}), "hashlib.new": ("unknown", {}),
    "rsa.generate_private_key": ("RSA", {}),
    "dsa.generate_private_key": ("DSA", {}),
    "ec.generate_private_key": ("ECDSA", {}),
    "dh.generate_parameters": ("DH", {}),
    "ed25519.Ed25519PrivateKey.generate": ("EdDSA", {"curve": "ed25519"}),
    "x25519.X25519PrivateKey.generate": ("ECDH", {"curve": "x25519"}),
    "RSA.generate": ("RSA", {}), "DSA.generate": ("DSA", {}),
    "AES.new": ("AES", {}), "DES.new": ("DES", {}), "DES3.new": ("3DES", {}),
    "ARC4.new": ("RC4", {}), "Blowfish.new": ("Blowfish", {}),
    "algorithms.AES": ("AES", {}), "algorithms.TripleDES": ("3DES", {}),
    "algorithms.ARC4": ("RC4", {}), "algorithms.ChaCha20": ("ChaCha20", {}),
    "algorithms.Blowfish": ("Blowfish", {}),
    "hashes.SHA1": ("SHA-1", {}), "hashes.MD5": ("MD5", {}),
    "hashes.SHA256": ("SHA-256", {}), "hashes.SHA384": ("SHA-384", {}),
    "padding.PKCS1v15": ("RSA", {"padding": "PKCS1v15"}),
    "Cipher.new": ("unknown", {}),
    "oqs.KeyEncapsulation": ("unknown", {}), "KeyEncapsulation": ("unknown", {}),
    "oqs.Signature": ("unknown", {}), "Signature": ("unknown", {}),
}
# Which *positional* argument carries the key size, for callees where it is not
# simply the first integer. `rsa.generate_private_key(65537, 2048)` is the one
# that matters most: the public exponent comes first, so the naive "first int"
# reading reports RSA-65537 and the key size never reaches the risk engine.
KEY_SIZE_ARG_INDEX = {
    "rsa.generate_private_key": 1,      # (public_exponent, key_size)
    "dh.generate_parameters": 1,        # (generator, key_size)
    "dsa.generate_private_key": 0,
    "RSA.generate": 0,
    "DSA.generate": 0,
}

PY_MODE_RULES = {
    "modes.ECB": "ECB", "modes.CBC": "CBC", "modes.GCM": "GCM", "modes.CTR": "CTR",
    "AES.MODE_ECB": "ECB", "AES.MODE_CBC": "CBC", "AES.MODE_GCM": "GCM",
}
PY_CURVES = {
    "SECP192R1": "secp192r1", "SECP224R1": "secp224r1", "SECP256R1": "secp256r1",
    "SECP256K1": "secp256k1", "SECP384R1": "secp384r1", "SECP521R1": "secp521r1",
}

# --- Pattern rules for the other languages --------------------------------
# (regex, algorithm, group index for key size or None, group index for mode or None)
PATTERN_RULES: dict[str, list[tuple[str, str, int | None, int | None]]] = {
    ".java": [
        (r'Cipher\.getInstance\(\s*"([A-Za-z0-9]+)(?:/([A-Za-z0-9]+))?', "@1", None, 2),
        (r'MessageDigest\.getInstance\(\s*"([A-Za-z0-9\-]+)"', "@1", None, None),
        (r'KeyPairGenerator\.getInstance\(\s*"([A-Za-z0-9]+)"', "@1", None, None),
        (r'KeyGenerator\.getInstance\(\s*"([A-Za-z0-9]+)"', "@1", None, None),
        (r'Signature\.getInstance\(\s*"(?:[A-Za-z0-9\-]+?)with([A-Za-z0-9]+)"', "@1", None, None),
        # Whole-literal JCA algorithm specs, e.g. "AES/GCM/NoPadding", "HmacSHA256".
        (r'"([A-Za-z][A-Za-z0-9]{1,12}(?:/[A-Za-z0-9]{1,12}){0,2})"', "@1", None, 2),
        (r'\.initialize\(\s*(\d{3,5})\s*\)', "RSA", 1, None),
        (r"(?i)\\b(ML[_-]?KEM|Kyber|ML[_-]?DSA|Dilithium|SLH[_-]?DSA|SPHINCS)[_-]?(\\d{2,4})?\\b", "@1", None, None),
    ],
    ".js": [
        (r"createHash\(\s*['\"]([a-z0-9\-]+)['\"]", "@1", None, None),
        (r"createCipheriv\(\s*['\"]([a-z0-9\-]+)['\"]", "@1", None, None),
        (r"createCipher\(\s*['\"]([a-z0-9\-]+)['\"]", "@1", None, None),
        (r"generateKeyPairSync\(\s*['\"](rsa|ec|ed25519)['\"]", "@1", None, None),
        (r"modulusLength\s*:\s*(\d{3,5})", "RSA", 1, None),
        (r"algorithm\s*:\s*['\"](RS256|RS512|ES256|HS256|none)['\"]", "@1", None, None),
        (r"CryptoJS\.(MD5|SHA1|SHA256|AES|TripleDES|RC4)", "@1", None, None),
        (r"(?i)\b(ml[_-]?kem|kyber|ml[_-]?dsa|dilithium|slh[_-]?dsa|sphincs)[_-]?(\d{2,4})?\b", "@1", None, None),
    ],
    ".go": [
        (r'crypto/(md5|sha1|sha256|sha512|rc4|aes)"', "@1", None, None),
        (r"(?i)\b(ml[_-]?kem|kyber|ml[_-]?dsa|dilithium|slh[_-]?dsa|sphincs)[_-]?(\d{2,4})?\b", "@1", None, None),
        (r"rsa\.GenerateKey\([^,]+,\s*(\d{3,5})\)", "RSA", 1, None),
        (r"elliptic\.(P224|P256|P384|P521)\(\)", "ECDSA", None, None),
        (r"des\.NewTripleDESCipher", "3DES", None, None),
        (r"des\.NewCipher\(", "DES", None, None),
    ],
}
# elliptic.P256() names a curve; without it we cannot tell P-256 from P-521.
GO_CURVES = {"P224": "secp224r1", "P256": "secp256r1",
             "P384": "secp384r1", "P521": "secp521r1"}

PATTERN_RULES[".ts"] = PATTERN_RULES[".js"]
PATTERN_RULES[".mjs"] = PATTERN_RULES[".js"]
PATTERN_RULES[".jsx"] = PATTERN_RULES[".js"]

MODE_TOKENS = {"ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "CCM", "XTS", "POLY1305", "SIV"}

# Post-quantum APIs, recognised by shape rather than by an exhaustive rule list,
# because every library spells them differently: pyca exposes
# `mlkem.MLKEM768PrivateKey`, liboqs takes `KeyEncapsulation("ML-KEM-768")`,
# Bouncy Castle uses `MLKEMParameters`, and older code still says Kyber.
#
# Detecting these matters as much as detecting RSA: without it, an already
# migrated hybrid key exchange gets reported as broken because only its
# classical half is visible.
PQC_CLASS = re.compile(
    r"(?:^|\.)(?:ML[_-]?KEM|MLKEM|Kyber|ML[_-]?DSA|MLDSA|Dilithium|"
    r"SLH[_-]?DSA|SLHDSA|SPHINCS|FN[_-]?DSA|FNDSA|Falcon|HQC|XMSS|LMS)"
    r"[_-]?(\d{2,4})?", re.I)
PQC_FAMILY = {
    "mlkem": "ML-KEM", "ml-kem": "ML-KEM", "ml_kem": "ML-KEM", "kyber": "ML-KEM",
    "mldsa": "ML-DSA", "ml-dsa": "ML-DSA", "ml_dsa": "ML-DSA", "dilithium": "ML-DSA",
    "slhdsa": "SLH-DSA", "slh-dsa": "SLH-DSA", "slh_dsa": "SLH-DSA", "sphincs": "SLH-DSA",
    "fndsa": "FN-DSA", "fn-dsa": "FN-DSA", "fn_dsa": "FN-DSA", "falcon": "FN-DSA",
    "hqc": "HQC", "xmss": "XMSS", "lms": "LMS",
}


def detect_pqc(name: str) -> tuple[str, dict] | None:
    """Recognise a post-quantum algorithm from an API name, with its parameter set."""
    # `mlkem.MLKEM768PrivateKey` matches twice: the lowercase module prefix
    # first, which carries no parameter set. Prefer whichever match names one.
    best = None
    for match in PQC_CLASS.finditer(name or ""):
        token = match.group(0).lstrip(".").rstrip("0123456789_-").lower().replace(" ", "")
        family = PQC_FAMILY.get(token) or PQC_FAMILY.get(token.replace("_", "-"))
        if family is None:
            continue
        if best is None or (match.group(1) and not best[1]):
            best = (family, match.group(1))
    if best is None:
        return None
    family, parameter = best
    params: dict = {}
    if parameter:
        params["parameter_set"] = f"{family}-{parameter}"
    return family, params


def split_suite(name: str) -> tuple[str, int | None, str | None]:
    """Split a composite cipher name into (algorithm, key size, mode).

    Node and the JCA both pack all three into one token, in several shapes:
    `aes-128-cbc`, `AES/GCM/NoPadding`, `des-ede3-cbc`, `chacha20-poly1305`.
    Longest-prefix matching on the algorithm is what stops `des-ede3-cbc`
    resolving to plain DES via its first token.
    """
    parts = [p for p in re.split(r"[-_/]", name.strip()) if p]
    if not parts:
        return name, None, None

    algorithm, consumed = name, 0
    for length in range(len(parts), 0, -1):
        candidate = "-".join(parts[:length]).lower()
        if candidate in ALIASES:
            algorithm, consumed = ALIASES[candidate], length
            break
    else:
        algorithm, consumed = parts[0], 1

    key_size = mode = None
    for token in parts[consumed:]:
        upper = token.upper()
        if token.isdigit() and int(token) in {40, 56, 64, 112, 128, 168, 192, 256}:
            key_size = int(token)
        elif upper in MODE_TOKENS:
            mode = upper
    return algorithm, key_size, mode

# Only these rules take a key size, so only these lose confidence when the
# argument is a variable rather than a literal. A hash call takes data.
KEYED_RULES = {
    "rsa.generate_private_key", "dsa.generate_private_key", "ec.generate_private_key",
    "dh.generate_parameters", "RSA.generate", "DSA.generate",
    "AES.new", "DES.new", "DES3.new", "ARC4.new", "Blowfish.new",
    "algorithms.AES", "algorithms.TripleDES", "algorithms.ARC4",
    "algorithms.ChaCha20", "algorithms.Blowfish", "Cipher.new",
}


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map local names back to their fully-qualified origin.

    `from hashlib import sha256` then a bare `sha256(blob)` is idiomatic Python
    and extremely common in real code — botocore signs requests that way — but a
    scanner matching only on the dotted `hashlib.sha256` never sees it. This
    resolves the local name so both spellings hit the same rule.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _expand(name: str, aliases: dict[str, str]) -> str:
    """Rewrite a call's leading segment through the import map."""
    if not name:
        return name
    head, _, rest = name.partition(".")
    target = aliases.get(head)
    if target is None:
        return name
    return f"{target}.{rest}" if rest else target


def _dotted(node: ast.AST) -> str:
    """Resolve a call target to a dotted string, e.g. hashlib.md5."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class SourceScanner(Scanner):
    source_type = SourceType.SOURCE_CODE
    name = "source"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        root = Path(target)
        if not root.exists():
            result.errors.append(ScanError("source_code", target, "path does not exist"))
            return result
        files = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file() and not any(d in p.relative_to(root).parts for d in SKIP_DIRS)
        ]
        for path in files:
            try:
                if path.suffix == ".py":
                    result.extend(self._scan_python(path, root))
                elif path.suffix in PATTERN_RULES:
                    result.extend(self._scan_patterns(path, root))
            except Exception as exc:  # one bad file never kills the scan
                result.errors.append(ScanError("source_code", str(path), str(exc)))
        return result

    # ------------------------------------------------------------------ Python
    def _scan_python(self, path: Path, root: Path) -> ScanResult:
        result = ScanResult()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except SyntaxError as exc:
            result.errors.append(ScanError("source_code", str(path), f"parse error: {exc}"))
            return result
        lines = text.splitlines()
        aliases = _import_aliases(tree)
        modes_by_line: dict[int, str] = {}
        pending: list[tuple[int, str, dict, Confidence]] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _expand(_dotted(node.func), aliases)
            if not name:
                continue
            for mode_key, mode_val in PY_MODE_RULES.items():
                if name.endswith(mode_key):
                    modes_by_line[node.lineno] = mode_val
            match = next((k for k in PY_CALL_RULES if name == k or name.endswith("." + k)), None)
            if match is None:
                pqc = detect_pqc(name)
                if pqc is None:
                    continue
                algorithm, pqc_params = pqc
                literal = self._first_str(node)
                if literal:
                    from_literal = detect_pqc(literal)
                    if from_literal:
                        algorithm, pqc_params = from_literal
                pending.append((node.lineno, algorithm, dict(pqc_params), Confidence.HIGH))
                continue
            algorithm, params = PY_CALL_RULES[match]
            params = dict(params)
            key_size, confidence = self._python_key_size(node, match)
            arg_mode = self._python_mode_arg(node)
            if arg_mode:
                params["mode"] = arg_mode
            if self._declared_non_security(node):
                params["usedforsecurity"] = False
            if match not in KEYED_RULES:
                confidence = Confidence.HIGH
            curve = self._python_curve(node)
            if curve:
                params["curve"] = curve
            if algorithm == "unknown":
                literal = self._first_str(node)
                if literal:
                    algorithm = literal
                    confidence = Confidence.HIGH
                else:
                    continue
            pending.append((node.lineno, algorithm, {**params, **({"key_size": key_size} if key_size else {})}, confidence))

        for lineno, algorithm, params, confidence in pending:
            key_size = params.pop("key_size", None)
            for offset in (0, -1, 1, -2, 2):
                if lineno + offset in modes_by_line:
                    params["mode"] = modes_by_line[lineno + offset]
                    break
            loc = f"{path.relative_to(root) if root != path else path}:{lineno}"
            snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else None
            result.assets.append(self._asset(algorithm, key_size, params, loc, snippet,
                                             "python-ast", confidence))
        return result

    @staticmethod
    def _first_str(node: ast.Call) -> str | None:
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
        return None

    @staticmethod
    def _python_key_size(node: ast.Call, callee: str = "") -> tuple[int | None, Confidence]:
        """Literal argument -> high confidence; a variable -> medium."""
        for kw in node.keywords:
            if kw.arg in {"key_size", "bits", "modulus_length", "public_exponent_size"}:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                    return kw.value.value, Confidence.HIGH
                return None, Confidence.MEDIUM
        index = KEY_SIZE_ARG_INDEX.get(callee)
        if index is not None:
            if len(node.args) > index:
                chosen = node.args[index]
                if isinstance(chosen, ast.Constant) and isinstance(chosen.value, int):
                    return chosen.value, Confidence.HIGH
                return None, Confidence.MEDIUM
            # Key size passed by keyword under a name we do not recognise, or
            # omitted entirely: say nothing rather than read another argument.
            return None, Confidence.MEDIUM if node.args else Confidence.HIGH
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value >= 56:
                return arg.value, Confidence.HIGH
        if node.args or node.keywords:
            if any(not isinstance(a, ast.Constant) for a in node.args):
                return None, Confidence.MEDIUM
        return None, Confidence.HIGH

    @staticmethod
    def _declared_non_security(node: ast.Call) -> bool:
        """`hashlib.md5(usedforsecurity=False)` is an explicit statement that the
        digest is a checksum or cache key, not a security control. Reporting it
        as broken cryptography is a false positive."""
        for kw in node.keywords:
            if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant):
                return kw.value.value is False
        return False

    @staticmethod
    def _python_mode_arg(node: ast.Call) -> str | None:
        """Modes arrive as arguments, e.g. AES.new(key, AES.MODE_ECB).

        These are ast.Attribute nodes, not calls, so the Call-node walk that
        finds `modes.ECB()` never reaches them.
        """
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            name = None
            if isinstance(arg, ast.Attribute):
                name = arg.attr
            elif isinstance(arg, ast.Name):
                name = arg.id
            if name and name.upper().startswith("MODE_"):
                return name.upper().removeprefix("MODE_")
        return None

    @staticmethod
    def _python_curve(node: ast.Call) -> str | None:
        candidates = list(node.args) + [kw.value for kw in node.keywords if kw.arg == "curve"]
        for arg in candidates:
            name = None
            if isinstance(arg, ast.Call):
                name = _dotted(arg.func).split(".")[-1]
            elif isinstance(arg, ast.Attribute):
                name = arg.attr
            elif isinstance(arg, ast.Name):
                name = arg.id
            if name and name.upper() in PY_CURVES:
                return PY_CURVES[name.upper()]
        return None

    # ---------------------------------------------------------------- patterns
    @staticmethod
    def _code_span(line: str, suffix: str) -> int:
        """Length of the code portion of a line, before any line comment.

        Independent verification against real code found a finding anchored to
        `//private static final String RSA_ENC_OID = ...` — a commented-out
        declaration in jjwt. Dead code is not cryptography in use.
        """
        markers = ["//", "/*", "*/"] if suffix != ".go" else ["//", "/*", "*/"]
        if suffix in {".py"}:
            markers = ["#"]
        stripped = line.lstrip()
        if stripped.startswith(("*", "//", "#", "/*")):
            return 0
        cut = len(line)
        for marker in markers:
            index = line.find(marker)
            if index != -1:
                cut = min(cut, index)
        return cut

    def _scan_patterns(self, path: Path, root: Path) -> ScanResult:
        result = ScanResult()
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        for pattern, algo_spec, size_group, mode_group in PATTERN_RULES[path.suffix]:
            for match in re.finditer(pattern, text):
                lineno = text[: match.start()].count("\n") + 1
                line_start = text.rfind("\n", 0, match.start()) + 1
                if match.start() - line_start >= self._code_span(
                        lines[lineno - 1] if lineno <= len(lines) else "", path.suffix):
                    continue          # the match sits inside a comment
                algorithm = match.group(int(algo_spec[1:])) if algo_spec.startswith("@") else algo_spec
                if not algorithm:
                    continue
                params: dict = {}
                algorithm, key_size, suite_mode = split_suite(algorithm)
                if suite_mode:
                    params["mode"] = suite_mode
                if size_group:
                    try:
                        key_size = int(match.group(size_group))
                    except (IndexError, TypeError, ValueError):
                        pass
                if mode_group:
                    try:
                        mode = match.group(mode_group)
                        if mode:
                            params["mode"] = mode.upper()
                    except IndexError:
                        pass
                if path.suffix == ".go" and match.group(0).startswith("elliptic."):
                    params["curve"] = GO_CURVES.get(match.group(1), match.group(1))
                if not self._recognised(algorithm):
                    continue
                loc = f"{path.relative_to(root) if root != path else path}:{lineno}"
                snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else None
                result.assets.append(self._asset(algorithm, key_size, params, loc, snippet,
                                                 f"pattern-{path.suffix.lstrip('.')}",
                                                 Confidence.MEDIUM))
        return result


    # ------------------------------------------------------------------ helper
    @staticmethod
    def _recognised(algorithm: str) -> bool:
        """Pattern rules cast a wide net, so anything that does not resolve to a
        known algorithm is dropped rather than reported as UNKNOWN. An
        unscoreable row is worse than no row: it cannot be assigned an X, a Y or
        a criticality, and it dilutes every count on the Overview."""
        from ..knowledge.algorithms import classify
        from ..models import QuantumStatus
        return classify(algorithm).quantum_status is not QuantumStatus.UNKNOWN

    def _asset(self, algorithm: str, key_size: int | None, params: dict,
               location: str, snippet: str | None, method: str,
               confidence: Confidence) -> Asset:
        from ..knowledge.algorithms import normalise
        return Asset(
            algorithm=normalise(algorithm),
            asset_type=AssetType.ALGORITHM,
            key_size=key_size,
            parameters=params,
            location_class="call-site",
            evidence=[Evidence(self.source_type, method, location, confidence, snippet)],
        )
