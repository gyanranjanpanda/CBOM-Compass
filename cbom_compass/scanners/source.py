"""Source-code scanner — PRD v1.1 section 6.1.

Python is scanned with the stdlib `ast` module: we walk Call nodes, resolve the
dotted callee, and pull key sizes and curves out of the actual arguments. That
gives high confidence when an argument is a literal and medium when it is a
variable, which is exactly the confidence distinction the UI needs.

Java, JavaScript/TypeScript, Go, C/C++/Objective-C, C# and Rust use pattern
rules, which is why their findings carry medium confidence while Python's carry
high. C and C# are not optional coverage for this problem: C is where mbedTLS
and OpenSSL are called directly on embedded hardware, which is the population
with the longest migration time in `knowledge/mosca.py`, and C# is most of the
government and banking estate this tool is aimed at. Leaving either out would
have meant the assets hardest to migrate were also the ones never found.

Three mechanisms do the attribute extraction that the strict metric measures:

  * `split_suite` decomposes separator-joined names — `aes_128_gcm`,
    `des-ede3-cbc`, `AES/GCM/NoPadding`.
  * `COMPOSITE_NAMES` handles identifiers where splitting cannot recover the
    parts — `Aes256Gcm`, `ChaCha20Poly1305`, `nistP384`, `prime256v1`.
  * `subsume_bare` collapses the overlapping rules that fire on one call, so
    `ECDsa.Create(ECCurve.NamedCurves.nistP384)` reports the curve rather than
    reporting the same call twice.

Comment handling is file-wide rather than per-line (`comment_spans`), because a
multi-line `/* ... */` block has middle lines that look exactly like code.

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
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".cbom-workspace"}

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

# --- C and C++ -------------------------------------------------------------
# Four ecosystems share these suffixes and none of them can be ignored: OpenSSL
# is everywhere, mbedTLS owns embedded, libsodium owns the "just give me
# something safe" tier, and CNG owns Windows. Embedded C in particular is where
# the Mosca Y estimate is largest, so missing it understates exactly the assets
# that take longest to migrate.
PATTERN_RULES[".c"] = [
    # OpenSSL EVP: the whole cipher spec is in the function name.
    (r"EVP_(aes_\d{3}_[a-z0-9]+|des_ede3_[a-z]+|des_[a-z]+|rc4|chacha20(?:_poly1305)?|"
     r"camellia_\d{3}_[a-z]+|bf_[a-z]+|rc2_[a-z]+)\s*\(", "@1", None, None),
    (r"EVP_(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512)\s*\(",
     "@1", None, None),
    # Low-level OpenSSL, and the same names mbedTLS uses without the prefix.
    (r"\b(?:mbedtls_)?(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)_(?:Init|Update|Final|starts|update|finish)\b",
     "@1", None, None),
    (r"\bmbedtls_(md5|sha1|sha256|sha512)(?:_ret)?\s*\(", "@1", None, None),
    (r"MBEDTLS_CIPHER_(AES_\d{3}_[A-Z]+|DES_EDE3_[A-Z]+|DES_[A-Z]+|ARC4_128|"
     r"CHACHA20(?:_POLY1305)?|CAMELLIA_\d{3}_[A-Z]+|BLOWFISH_[A-Z]+)\b",
     "@1", None, None),
    # Key sizes are arguments, not part of the name.
    (r"RSA_generate_key_ex\s*\([^,]+,\s*(\d{3,5})", "RSA", 1, None),
    (r"RSA_generate_key\s*\(\s*(\d{3,5})", "RSA", 1, None),
    (r"DH_generate_parameters(?:_ex)?\s*\((?:[^,]+,\s*)?(\d{3,5})", "DH", 1, None),
    (r"DSA_generate_parameters(?:_ex)?\s*\((?:[^,]+,\s*)?(\d{3,5})", "DSA", 1, None),
    (r"AES_set_(?:en|de)crypt_key\s*\([^,]+,\s*(\d{2,4})", "AES", 1, None),
    (r"mbedtls_(?:rsa|pk)_gen_key\s*\([^)]*?(\d{4})", "RSA", 1, None),
    (r"mbedtls_aes_setkey_(?:enc|dec)\s*\([^,]+,[^,]+,\s*(\d{2,4})", "AES", 1, None),
    # Named curves arrive as NIDs and mbedTLS group ids.
    # The curve is the whole finding: without it P-192 and P-521 are the same
    # row, and one of them is below acceptable classical strength. The group
    # goes through COMPOSITE_NAMES, which carries both the curve and its size.
    (r"NID_(?:X9_62_)?(prime192v1|prime256v1|secp224r1|secp256k1|secp384r1|secp521r1)\b",
     "@1", None, None),
    (r"MBEDTLS_ECP_DP_(SECP192R1|SECP224R1|SECP256R1|SECP384R1|SECP521R1|CURVE25519)\b",
     "@1", None, None),
    (r"\bED25519\b|\bcrypto_sign_(?:keypair|detached)\b", "Ed25519", None, None),
    (r"\bX25519\b|\bcrypto_(?:box|scalarmult)_(?:keypair|base)\b", "X25519", None, None),
    # Windows CNG and the older CryptoAPI.
    (r"BCRYPT_(RSA|DSA|DH|ECDSA|ECDH|AES|3DES|DES|RC4|MD5|SHA1|SHA256|SHA384|SHA512)"
     r"(?:_P\d{3})?_ALGORITHM\b", "@1", None, None),
    (r"\bCALG_(RSA|DSA|DH|AES|AES_128|AES_192|AES_256|3DES|DES|RC4|RC2|MD5|MD4|SHA1|"
     r"SHA_256|SHA_384|SHA_512)\b", "@1", None, None),
    (r"CryptGenKey\s*\([^,]+,\s*CALG_(RSA_KEYX|RSA_SIGN|DSS_SIGN)", "RSA", None, None),
    (r"(?i)\b(ml[_-]?kem|kyber|ml[_-]?dsa|dilithium|slh[_-]?dsa|sphincs)[_-]?(\d{2,4})?\b",
     "@1", None, None),
    (r"OQS_(?:KEM|SIG)_alg_(ml_kem_\d{3,4}|kyber_\d{3,4}|ml_dsa_\d{2}|"
     r"dilithium_\d|sphincs_[a-z0-9_]+|falcon_\d{3,4})\b", "@1", None, None),
]
# One rule set, several spellings of "this is C".
for _suffix in (".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".m", ".mm"):
    PATTERN_RULES[_suffix] = PATTERN_RULES[".c"]

# --- C# / .NET -------------------------------------------------------------
PATTERN_RULES[".cs"] = [
    (r"new\s+(RSACryptoServiceProvider|DSACryptoServiceProvider|"
     r"TripleDESCryptoServiceProvider|DESCryptoServiceProvider|"
     r"AesCryptoServiceProvider|AesManaged|RijndaelManaged|RC2CryptoServiceProvider|"
     r"MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider|"
     r"SHA256Managed|SHA512Managed|AesGcm|ChaCha20Poly1305)\s*\(", "@1", None, None),
    # `new RSACryptoServiceProvider(2048)` — the size is the only argument.
    (r"new\s+RSACryptoServiceProvider\s*\(\s*(\d{3,5})\s*\)", "RSA", 1, None),
    (r"new\s+DSACryptoServiceProvider\s*\(\s*(\d{3,5})\s*\)", "DSA", 1, None),
    (r"\b(RSA|DSA|Aes|TripleDES|DES|RC2|MD5|SHA1|SHA256|SHA384|SHA512|ECDsa|ECDiffieHellman)"
     r"\.Create\s*\(", "@1", None, None),
    (r"RSA\.Create\s*\(\s*(\d{3,5})\s*\)", "RSA", 1, None),
    (r"\.KeySize\s*=\s*(\d{3,5})", "RSA", 1, None),
    (r"\bnew\s+(HMACMD5|HMACSHA1|HMACSHA256|HMACSHA384|HMACSHA512)\s*\(",
     "@1", None, None),
    (r"CipherMode\.(ECB|CBC|CFB|OFB|CTS)\b", "AES", None, 1),
    (r"ECCurve\.NamedCurves\.(nistP256|nistP384|nistP521|brainpoolP256r1)\b",
     "@1", None, None),
    (r"HashAlgorithmName\.(MD5|SHA1|SHA256|SHA384|SHA512)\b", "@1", None, None),
    (r"RSAEncryptionPadding\.(Pkcs1|OaepSHA1|OaepSHA256)\b", "RSA", None, None),
    (r"(?i)\b(ml[_-]?kem|kyber|ml[_-]?dsa|dilithium|slh[_-]?dsa|sphincs)[_-]?(\d{2,4})?\b",
     "@1", None, None),
]

# --- Rust ------------------------------------------------------------------
PATTERN_RULES[".rs"] = [
    # RustCrypto type names pack algorithm, size and mode into one identifier.
    (r"\b(Aes128Gcm|Aes256Gcm|Aes128GcmSiv|Aes256GcmSiv|Aes128CbcEnc|Aes256CbcEnc|"
     r"Aes128Ctr|Aes256Ctr|ChaCha20Poly1305|XChaCha20Poly1305)\b", "@1", None, None),
    (r"\baes::(Aes128|Aes192|Aes256)\b", "AES", None, None),
    (r"\b(Md5|Md4|Sha1|Sha224|Sha256|Sha384|Sha512|Sha3_256|Sha3_512|Blake2b)::(?:new|digest)\b",
     "@1", None, None),
    (r"\b(md5|sha1|sha2|sha3|blake2)::(Md5|Sha1|Sha256|Sha384|Sha512)\b",
     "@2", None, None),
    (r"RsaPrivateKey::new\s*\([^,]+,\s*(\d{3,5})", "RSA", 1, None),
    (r"Rsa::generate\s*\(\s*(\d{3,5})", "RSA", 1, None),
    (r"ring::aead::(AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305)\b", "@1", None, None),
    (r"ring::digest::(SHA1(?:_FOR_LEGACY_USE_ONLY)?|SHA256|SHA384|SHA512)\b",
     "@1", None, None),
    (r"ring::signature::(ECDSA_P256_SHA256|ECDSA_P384_SHA384|ED25519|RSA_PKCS1_2048_8192_SHA256)",
     "@1", None, None),
    (r"\b(?:use\s+)?(ed25519_dalek|x25519_dalek|p256|p384|k256|curve25519_dalek)\b",
     "@1", None, None),
    (r"\b(?:use\s+)?(pqcrypto_kyber|pqcrypto_dilithium|pqcrypto_falcon|pqcrypto_sphincsplus)\b",
     "@1", None, None),
    (r"(?i)\b(ml[_-]?kem|kyber|ml[_-]?dsa|dilithium|slh[_-]?dsa|sphincs)[_-]?(\d{2,4})?\b",
     "@1", None, None),
]

PATTERN_RULES[".ts"] = PATTERN_RULES[".js"]
PATTERN_RULES[".mjs"] = PATTERN_RULES[".js"]
PATTERN_RULES[".jsx"] = PATTERN_RULES[".js"]

MODE_TOKENS = {"ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "CCM", "XTS", "POLY1305", "SIV"}

# Identifiers that pack algorithm, size, mode or curve into one CamelCase or
# underscored token, where splitting on separators does not recover the parts.
# `split_suite` handles `aes_128_gcm`; it cannot handle `Aes128Gcm`, and generic
# CamelCase splitting mangles `ChaCha20Poly1305`, so these are listed rather
# than guessed. Keys are matched case-insensitively.
COMPOSITE_NAMES: dict[str, tuple[str, int | None, dict]] = {
    # --- Rust (RustCrypto)
    "aes128gcm": ("AES", 128, {"mode": "GCM"}),
    "aes256gcm": ("AES", 256, {"mode": "GCM"}),
    "aes128gcmsiv": ("AES", 128, {"mode": "GCM-SIV"}),
    "aes256gcmsiv": ("AES", 256, {"mode": "GCM-SIV"}),
    "aes128cbcenc": ("AES", 128, {"mode": "CBC"}),
    "aes256cbcenc": ("AES", 256, {"mode": "CBC"}),
    "aes128ctr": ("AES", 128, {"mode": "CTR"}),
    "aes256ctr": ("AES", 256, {"mode": "CTR"}),
    "chacha20poly1305": ("ChaCha20", 256, {"mode": "POLY1305"}),
    "xchacha20poly1305": ("ChaCha20", 256, {"mode": "POLY1305", "nonce": "extended"}),
    "ed25519_dalek": ("EdDSA", None, {"curve": "ed25519"}),
    "x25519_dalek": ("ECDH", None, {"curve": "x25519"}),
    "curve25519_dalek": ("ECDH", None, {"curve": "x25519"}),
    "p256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "p384": ("ECDSA", 384, {"curve": "secp384r1"}),
    "k256": ("ECDSA", 256, {"curve": "secp256k1"}),
    "pqcrypto_kyber": ("ML-KEM", None, {}),
    "pqcrypto_dilithium": ("ML-DSA", None, {}),
    "pqcrypto_falcon": ("FN-DSA", None, {}),
    "pqcrypto_sphincsplus": ("SLH-DSA", None, {}),
    # --- Rust (ring)
    "sha1_for_legacy_use_only": ("SHA-1", None, {}),
    "ecdsa_p256_sha256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "ecdsa_p384_sha384": ("ECDSA", 384, {"curve": "secp384r1"}),
    "rsa_pkcs1_2048_8192_sha256": ("RSA", None, {"padding": "PKCS1v15"}),
    # --- C# / .NET
    "rsacryptoserviceprovider": ("RSA", None, {}),
    "dsacryptoserviceprovider": ("DSA", None, {}),
    "tripledescryptoserviceprovider": ("3DES", None, {}),
    "descryptoserviceprovider": ("DES", None, {}),
    "aescryptoserviceprovider": ("AES", None, {}),
    "aesmanaged": ("AES", None, {}),
    "rijndaelmanaged": ("AES", None, {}),
    "rc2cryptoserviceprovider": ("RC2", None, {}),
    "md5cryptoserviceprovider": ("MD5", None, {}),
    "sha1managed": ("SHA-1", None, {}),
    "sha1cryptoserviceprovider": ("SHA-1", None, {}),
    "sha256managed": ("SHA-256", None, {}),
    "sha512managed": ("SHA-512", None, {}),
    "aesgcm": ("AES", None, {"mode": "GCM"}),
    "hmacmd5": ("HMAC", None, {"hash": "MD5"}),
    "hmacsha1": ("HMAC", None, {"hash": "SHA-1"}),
    "hmacsha256": ("HMAC", None, {"hash": "SHA-256"}),
    "hmacsha384": ("HMAC", None, {"hash": "SHA-384"}),
    "hmacsha512": ("HMAC", None, {"hash": "SHA-512"}),
    "ecdsa": ("ECDSA", None, {}),
    "ecdiffiehellman": ("ECDH", None, {}),
    "tripledes": ("3DES", None, {}),
    "nistp256": ("ECDSA", 256, {"curve": "secp256r1"}),
    "nistp384": ("ECDSA", 384, {"curve": "secp384r1"}),
    "nistp521": ("ECDSA", 521, {"curve": "secp521r1"}),
    "brainpoolp256r1": ("ECDSA", 256, {"curve": "brainpoolP256r1"}),
    "oaepsha1": ("RSA", None, {"padding": "OAEP", "hash": "SHA-1"}),
    "oaepsha256": ("RSA", None, {"padding": "OAEP", "hash": "SHA-256"}),
    "pkcs1": ("RSA", None, {"padding": "PKCS1v15"}),
    # --- C / C++ named curves and mbedTLS group ids
    "prime192v1": ("ECDSA", 192, {"curve": "secp192r1"}),
    "prime256v1": ("ECDSA", 256, {"curve": "secp256r1"}),
    "secp192r1": ("ECDSA", 192, {"curve": "secp192r1"}),
    "secp224r1": ("ECDSA", 224, {"curve": "secp224r1"}),
    "secp256r1": ("ECDSA", 256, {"curve": "secp256r1"}),
    "secp256k1": ("ECDSA", 256, {"curve": "secp256k1"}),
    "secp384r1": ("ECDSA", 384, {"curve": "secp384r1"}),
    "secp521r1": ("ECDSA", 521, {"curve": "secp521r1"}),
    "curve25519": ("ECDH", None, {"curve": "x25519"}),
    # --- liboqs parameter-set identifiers
    "ml_kem_512": ("ML-KEM", None, {"parameter_set": "ML-KEM-512"}),
    "ml_kem_768": ("ML-KEM", None, {"parameter_set": "ML-KEM-768"}),
    "ml_kem_1024": ("ML-KEM", None, {"parameter_set": "ML-KEM-1024"}),
    "ml_dsa_44": ("ML-DSA", None, {"parameter_set": "ML-DSA-44"}),
    "ml_dsa_65": ("ML-DSA", None, {"parameter_set": "ML-DSA-65"}),
    "ml_dsa_87": ("ML-DSA", None, {"parameter_set": "ML-DSA-87"}),
}

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


def comment_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges that are comments, for the C-family syntaxes.

    A line-level check is not enough. Independent verification against real code
    found a finding anchored to `//private static final String RSA_ENC_OID` — a
    commented-out declaration in jjwt — and the same corpus caught a second
    class of miss: a multi-line `/* ... */` block whose *middle* lines look like
    ordinary code, because they neither open nor close the comment. Dead code is
    not cryptography in use, in either shape.

    String literals are tracked but deliberately *not* masked: the Java rules
    match inside them on purpose, because `Cipher.getInstance("AES/GCM/NoPadding")`
    puts the entire algorithm spec in a string. They are tracked only so that a
    `//` inside `"https://example.com"` does not open a comment that swallows the
    rest of the file.
    """
    spans: list[tuple[int, int]] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char in "\"'":
            quote, index = char, index + 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == quote or text[index] == "\n":
                    break
                index += 1
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            spans.append((index, end))
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end == -1 else end + 2
            spans.append((index, end))
            index = end
            continue
        if char == "#" and text.startswith("#", index):
            # Shell-style comments in configuration-ish files. Harmless for the
            # C-family syntaxes, where `#` only begins a preprocessor directive
            # — and a preprocessor directive is not a call site either.
            end = text.find("\n", index)
            end = length if end == -1 else end
            spans.append((index, end))
            index = end
            continue
        index += 1
    return spans


def in_comment(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


# How far apart two rules may fire and still be describing one call. A named
# curve or a key size is routinely written on the line after the constructor:
#
#     var rsa = RSA.Create();
#     rsa.KeySize = 3072;
#
# Two rules match, one line apart, and they are one usage.
SUBSUME_WINDOW = 1


def subsume_bare(found: list[tuple[int, "Asset"]]) -> list["Asset"]:
    """Drop an attribute-free finding that a richer one on the same call describes.

    Several rules deliberately overlap: one recognises the algorithm, another
    recognises the curve or key size beside it. `ECDsa.Create(ECCurve.NamedCurves
    .nistP384)` matches both, which is what gets the curve extracted at all — but
    emitting the bare `ECDSA` as well reports one call twice, and the bare row is
    the less useful of the two because an ECDSA with no curve cannot be told
    apart from a P-192 one.

    Only an entirely attribute-free finding is dropped, and only when a finding
    of the *same algorithm* nearby carries at least one attribute. A finding that
    already says something is never removed by one that says something else.
    """
    def attributes(asset) -> int:
        return (bool(asset.key_size) + bool(asset.parameters.get("curve"))
                + bool(asset.parameters.get("mode"))
                + bool(asset.parameters.get("parameter_set")))

    keep: list["Asset"] = []
    for lineno, asset in found:
        if attributes(asset) == 0 and any(
            other.algorithm == asset.algorithm
            and abs(other_line - lineno) <= SUBSUME_WINDOW
            and attributes(other) > 0
            for other_line, other in found
        ):
            continue
        keep.append(asset)
    return keep


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


# How a folded value reads in the evidence drill-down, and what it does to
# confidence. A source literal is exactly as certain as writing the value at the
# call site. An environment default is what runs unless the deployment overrides
# it — a real finding, but one the reader must be able to see is conditional.
ORIGIN_NOTE = {
    "literal": "module-level constant",
    "env-default": "default of an environment variable; runtime may override",
}


def _origin_confidence(origin: str) -> Confidence:
    return Confidence.HIGH if origin == "literal" else Confidence.MEDIUM


def _const_value(node: ast.AST, aliases: dict[str, str]) -> tuple[object, str] | None:
    """Fold a expression down to a literal, returning (value, provenance).

    Two provenances, and the difference matters for confidence:

    ``literal``      the value is written in the source and cannot change.
    ``env-default``  the value is the *default* of an environment lookup. It is
                     what runs unless the variable is set, which makes it a real
                     finding — but one the deployment can override, so it is
                     reported at medium confidence and says so.

    Only the shapes that actually occur are folded: string and integer
    constants, ``os.environ.get(key, default)`` / ``os.getenv``, and ``int()``
    or ``str()`` wrapped around either. No general evaluation, because a scanner
    that executes what it reads is a scanner that can be made to run anything.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return node.value, "literal"
    if not isinstance(node, ast.Call):
        return None

    callee = _expand(_dotted(node.func), aliases)
    tail = callee.rsplit(".", 1)[-1]

    if callee.endswith("environ.get") or tail == "getenv":
        if len(node.args) >= 2:
            inner = _const_value(node.args[1], aliases)
            if inner is not None:
                return inner[0], "env-default"
        return None
    if tail in {"int", "str"} and node.args:
        inner = _const_value(node.args[0], aliases)
        if inner is None:
            return None
        try:
            return (int(inner[0]) if tail == "int" else str(inner[0])), inner[1]
        except (TypeError, ValueError):
            return None
    return None


def module_constants(tree: ast.Module,
                     aliases: dict[str, str]) -> dict[str, tuple[object, str]]:
    """Module-level names bound to a foldable constant.

    Configuration-driven cryptography is the single largest class of finding a
    call-site-only scanner misses, and almost all of it is this shape:

        ALGORITHM = os.environ.get("DIGEST", "md5")
        digest    = hashlib.new(ALGORITHM, blob)

    The algorithm never appears at the call site, but it is right there at the
    top of the file. Only module scope is walked: a name assigned inside a
    function can be reassigned on any path, and following that properly is
    dataflow analysis, not constant folding.
    """
    constants: dict[str, tuple[object, str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        folded = _const_value(node.value, aliases)
        if folded is not None:
            constants[target.id] = folded
    return constants


def resolve_name(node: ast.AST, constants: dict[str, tuple[object, str]]):
    """Look an `ast.Name` up in the module constant table."""
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def getattr_target(node: ast.Call, aliases: dict[str, str]) -> str | None:
    """`getattr(hashlib, "sha1")` names an algorithm as plainly as `hashlib.sha1`.

    The attribute is a literal, so this is indirection in spelling only — there
    is nothing dynamic about it, and it resolves to the same dotted name.
    """
    if len(node.args) != 2:
        return None
    attribute = node.args[1]
    if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        return None
    base = _expand(_dotted(node.args[0]), aliases)
    return f"{base}.{attribute.value}" if base else None


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
        constants = module_constants(tree, aliases)
        modes_by_line: dict[int, str] = {}
        pending: list[tuple[int, str, dict, Confidence, dict]] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _expand(_dotted(node.func), aliases)
            if not name:
                continue
            detail: dict = {}
            if name.rsplit(".", 1)[-1] == "getattr":
                indirect = getattr_target(node, aliases)
                if indirect:
                    name = indirect
                    detail["resolved_from"] = "getattr with a literal attribute name"
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
                pending.append((node.lineno, algorithm, dict(pqc_params),
                                Confidence.HIGH, detail))
                continue
            algorithm, params = PY_CALL_RULES[match]
            params = dict(params)
            key_size, confidence, size_origin = self._python_key_size(
                node, match, constants)
            if size_origin:
                detail["key_size_resolved_from"] = size_origin
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
                    # `hashlib.new(ALGORITHM)` — the name is not at the call
                    # site, but it may be bound to a constant at module scope.
                    folded = next(
                        (resolve_name(arg, constants) for arg in node.args
                         if resolve_name(arg, constants) is not None), None)
                    if folded is None or not isinstance(folded[0], str):
                        continue
                    algorithm, origin = folded[0], folded[1]
                    detail["resolved_from"] = ORIGIN_NOTE[origin]
                    confidence = (Confidence.HIGH if origin == "literal"
                                  else Confidence.MEDIUM)
            pending.append((node.lineno, algorithm,
                            {**params, **({"key_size": key_size} if key_size else {})},
                            confidence, detail))

        for lineno, algorithm, params, confidence, detail in pending:
            key_size = params.pop("key_size", None)
            for offset in (0, -1, 1, -2, 2):
                if lineno + offset in modes_by_line:
                    params["mode"] = modes_by_line[lineno + offset]
                    break
            loc = f"{path.relative_to(root) if root != path else path}:{lineno}"
            snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else None
            result.assets.append(self._asset(algorithm, key_size, params, loc, snippet,
                                             "python-ast", confidence, detail))
        return result

    @staticmethod
    def _first_str(node: ast.Call) -> str | None:
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
        return None

    @staticmethod
    def _python_key_size(node: ast.Call, callee: str = "",
                         constants: dict[str, tuple[object, str]] | None = None
                         ) -> tuple[int | None, Confidence, str | None]:
        """Returns (key size, confidence, how the size was resolved).

        A literal argument is high confidence. A variable used to mean "we
        cannot know" and the size was dropped; now it is looked up in the
        module constant table first, because `key_size=KEY_BITS` with
        `KEY_BITS = int(os.environ.get("RSA_BITS", "1024"))` at the top of the
        file is an RSA-1024 key, and reporting RSA with no size loses the one
        attribute that makes it urgent.
        """
        constants = constants or {}

        def folded(value: ast.AST) -> tuple[int, str] | None:
            hit = resolve_name(value, constants)
            if hit is None or not isinstance(hit[0], int) or isinstance(hit[0], bool):
                return None
            return hit[0], hit[1]

        for kw in node.keywords:
            if kw.arg in {"key_size", "bits", "modulus_length", "public_exponent_size"}:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                    return kw.value.value, Confidence.HIGH, None
                hit = folded(kw.value)
                if hit:
                    return hit[0], _origin_confidence(hit[1]), ORIGIN_NOTE[hit[1]]
                return None, Confidence.MEDIUM, None
        index = KEY_SIZE_ARG_INDEX.get(callee)
        if index is not None:
            if len(node.args) > index:
                chosen = node.args[index]
                if isinstance(chosen, ast.Constant) and isinstance(chosen.value, int):
                    return chosen.value, Confidence.HIGH, None
                hit = folded(chosen)
                if hit:
                    return hit[0], _origin_confidence(hit[1]), ORIGIN_NOTE[hit[1]]
                return None, Confidence.MEDIUM, None
            # Key size passed by keyword under a name we do not recognise, or
            # omitted entirely: say nothing rather than read another argument.
            return None, Confidence.MEDIUM if node.args else Confidence.HIGH, None
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value >= 56:
                return arg.value, Confidence.HIGH, None
        if node.args or node.keywords:
            if any(not isinstance(a, ast.Constant) for a in node.args):
                return None, Confidence.MEDIUM, None
        return None, Confidence.HIGH, None

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
    def _scan_patterns(self, path: Path, root: Path) -> ScanResult:
        result = ScanResult()
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        commented = comment_spans(text)
        found: list[tuple[int, Asset]] = []
        for pattern, algo_spec, size_group, mode_group in PATTERN_RULES[path.suffix]:
            for match in re.finditer(pattern, text):
                lineno = text[: match.start()].count("\n") + 1
                if in_comment(match.start(), commented):
                    continue          # the match sits inside a comment
                algorithm = match.group(int(algo_spec[1:])) if algo_spec.startswith("@") else algo_spec
                if not algorithm:
                    continue
                params: dict = {}
                composite = COMPOSITE_NAMES.get(algorithm.lower())
                if composite is not None:
                    algorithm, key_size, extra = composite
                    params.update(extra)
                else:
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
                found.append((lineno, self._asset(
                    algorithm, key_size, params, loc, snippet,
                    f"pattern-{path.suffix.lstrip('.')}", Confidence.MEDIUM)))
        result.assets.extend(subsume_bare(found))
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
               confidence: Confidence, detail: dict | None = None) -> Asset:
        from ..knowledge.algorithms import normalise
        return Asset(
            algorithm=normalise(algorithm),
            asset_type=AssetType.ALGORITHM,
            key_size=key_size,
            parameters=params,
            location_class="call-site",
            evidence=[Evidence(self.source_type, method, location, confidence,
                               snippet, detail or {})],
        )
