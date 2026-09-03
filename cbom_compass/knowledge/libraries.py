"""Crypto-library knowledge base — maps a library + version onto the algorithms
it makes available, and onto known-bad versions.

Used by the dependency scanner (manifest -> library -> algorithms) and by the
binary scanner (resolved import/version string -> the same table), which is why
binary scanning was rescoped away from YARA constant matching: resolving *which
library at which version* feeds this table and flows through the whole pipeline,
whereas an AES S-box hit is an unscoreable dead end.
"""

from __future__ import annotations

# library name (lowercased) -> algorithms it exposes / is characterised by
LIBRARY_ALGORITHMS: dict[str, list[str]] = {
    "openssl": ["RSA", "ECDSA", "ECDH", "DH", "AES", "SHA-256", "SHA-1", "3DES", "MD5"],
    "libcrypto": ["RSA", "ECDSA", "ECDH", "DH", "AES", "SHA-256", "SHA-1"],
    "libssl": ["RSA", "ECDH", "AES", "SHA-256"],
    "cryptography": ["RSA", "ECDSA", "ECDH", "DH", "AES", "SHA-256", "ChaCha20"],
    "pycryptodome": ["RSA", "DSA", "AES", "3DES", "SHA-256", "MD5"],
    "pycrypto": ["RSA", "DSA", "AES", "DES", "MD5", "SHA-1"],
    "rsa": ["RSA"],
    "ecdsa": ["ECDSA"],
    "pyopenssl": ["RSA", "ECDSA", "AES", "SHA-256"],
    "paramiko": ["RSA", "ECDSA", "EdDSA", "AES", "SHA-256"],
    "bcrypt": ["bcrypt"],
    "pyjwt": ["RSA", "ECDSA", "HMAC", "SHA-256"],
    "jsonwebtoken": ["RSA", "ECDSA", "HMAC", "SHA-256"],
    "node-forge": ["RSA", "AES", "3DES", "SHA-1", "MD5"],
    "crypto-js": ["AES", "3DES", "SHA-256", "MD5", "SHA-1"],
    "bouncycastle": ["RSA", "ECDSA", "AES", "SHA-256", "ML-KEM", "ML-DSA"],
    "bcprov-jdk18on": ["RSA", "ECDSA", "AES", "SHA-256", "ML-KEM", "ML-DSA"],
    "golang.org/x/crypto": ["EdDSA", "ECDH", "AES", "ChaCha20", "SHA-256"],
    "liboqs": ["ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC"],
    "oqs-provider": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "libsodium": ["EdDSA", "ECDH", "ChaCha20", "BLAKE2b"],
    "pynacl": ["EdDSA", "ECDH", "ChaCha20", "BLAKE2b"],
}

# Libraries that are themselves unmaintained/abandoned — an availability risk on
# top of whatever cryptography they expose.
ABANDONED = {"pycrypto", "node-forge-legacy"}

# Minimum version considered current, where a floor is meaningful.
MIN_SAFE_VERSION = {
    "openssl": "3.0.0",
    "cryptography": "42.0.0",
}

# Binary evidence: strings/symbols that identify a linked crypto library.
BINARY_SIGNATURES = [
    (rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "openssl"),
    (rb"libcrypto\.so\.(\d+(?:\.\d+)*)", "libcrypto"),
    (rb"libssl\.so\.(\d+(?:\.\d+)*)", "libssl"),
    (rb"GnuTLS (\d+\.\d+\.\d+)", "gnutls"),
    (rb"BoringSSL", "boringssl"),
    (rb"mbed TLS (\d+\.\d+\.\d+)", "mbedtls"),
    (rb"libsodium (\d+\.\d+\.\d+)", "libsodium"),
    (rb"wolfSSL (\d+\.\d+\.\d+)", "wolfssl"),
]

# Linked-library filename fragment -> knowledge-base library name. Resolved from
# the import table (ELF DT_NEEDED, Mach-O LOAD_DYLIB, PE import descriptors).
LINKED_LIBRARY_HINTS = [
    ("libcrypto", "libcrypto"), ("libssl", "libssl"), ("libgnutls", "gnutls"),
    ("libsodium", "libsodium"), ("libmbedtls", "mbedtls"), ("libmbedcrypto", "mbedtls"),
    ("libwolfssl", "wolfssl"), ("libnss3", "nss"), ("liboqs", "liboqs"),
    ("bcrypt.dll", "windows-cng"), ("ncrypt.dll", "windows-cng"),
    ("advapi32.dll", "windows-cryptoapi"), ("crypt32.dll", "windows-cryptoapi"),
    ("security.framework", "apple-security"), ("libcommoncrypto", "apple-commoncrypto"),
    ("corecrypto", "apple-corecrypto"),
]

# Imported symbol -> algorithm. This is the high-confidence binary signal.
SYMBOL_ALGORITHMS = {
    b"RSA_generate_key": "RSA", b"RSA_public_encrypt": "RSA", b"RSA_private_decrypt": "RSA",
    b"EVP_PKEY_CTX_set_rsa_keygen_bits": "RSA",
    b"ECDSA_do_sign": "ECDSA", b"EC_KEY_generate_key": "ECDSA",
    b"ECDH_compute_key": "ECDH", b"DH_generate_key": "DH",
    b"AES_set_encrypt_key": "AES", b"EVP_aes_128_cbc": "AES", b"EVP_aes_256_gcm": "AES",
    b"EVP_aes_128_ecb": "AES",
    b"MD5_Init": "MD5", b"MD5_Update": "MD5",
    b"SHA1_Init": "SHA-1", b"SHA1_Update": "SHA-1",
    b"SHA256_Init": "SHA-256", b"SHA384_Init": "SHA-384", b"SHA512_Init": "SHA-512",
    b"DES_ecb_encrypt": "DES", b"DES_ede3_cbc_encrypt": "3DES",
    b"RC4": "RC4",
    b"OQS_KEM_new": "ML-KEM", b"OQS_SIG_new": "ML-DSA",
    # Additional real-world import-table symbols.
    b"AES_encrypt": "AES", b"AES_decrypt": "AES", b"AES_cbc_encrypt": "AES",
    b"EVP_aes_192_cbc": "AES", b"EVP_aes_256_cbc": "AES", b"EVP_aes_128_gcm": "AES",
    b"RSA_sign": "RSA", b"RSA_verify": "RSA", b"RSA_new": "RSA", b"RSA_size": "RSA",
    b"ECDSA_verify": "ECDSA", b"ECDSA_sign": "ECDSA", b"EC_POINT_mul": "ECDSA",
    b"DH_compute_key": "DH", b"DH_new": "DH",
    b"SHA1_Final": "SHA-1", b"SHA256_Final": "SHA-256", b"SHA512_Final": "SHA-512",
    b"MD5_Final": "MD5", b"MD4_Init": "MD4",
    b"EVP_sha1": "SHA-1", b"EVP_sha256": "SHA-256", b"EVP_sha384": "SHA-384",
    b"EVP_sha512": "SHA-512", b"EVP_md5": "MD5",
    b"EVP_des_ede3_cbc": "3DES", b"EVP_des_cbc": "DES", b"EVP_rc4": "RC4",
    b"EVP_chacha20": "ChaCha20", b"EVP_chacha20_poly1305": "ChaCha20",
    b"CC_MD5_Init": "MD5", b"CC_SHA1_Init": "SHA-1", b"CC_SHA256_Init": "SHA-256",
    b"CCCryptorCreate": "AES",
    b"BCryptGenerateSymmetricKey": "AES", b"CryptCreateHash": "unknown",
    b"crypto_sign_ed25519": "EdDSA", b"crypto_box_curve25519": "ECDH",
}

# Symbols that imply a key size or mode from their own name.
SYMBOL_PARAMETERS = {
    b"EVP_aes_128_cbc": (128, "CBC"), b"EVP_aes_128_ecb": (128, "ECB"),
    b"EVP_aes_128_gcm": (128, "GCM"), b"EVP_aes_192_cbc": (192, "CBC"),
    b"EVP_aes_256_cbc": (256, "CBC"), b"EVP_aes_256_gcm": (256, "GCM"),
    b"EVP_des_ede3_cbc": (None, "CBC"), b"EVP_des_cbc": (None, "CBC"),
}

# Key size implied by an OpenSSL symbol, where the symbol names one.
SYMBOL_KEY_SIZE = {
    b"EVP_aes_128_cbc": 128, b"EVP_aes_128_ecb": 128, b"EVP_aes_256_gcm": 256,
}


def algorithms_for(library: str) -> list[str]:
    return LIBRARY_ALGORITHMS.get(library.strip().lower(), [])


def is_abandoned(library: str) -> bool:
    return library.strip().lower() in ABANDONED
