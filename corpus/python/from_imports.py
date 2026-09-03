"""Import styles other than the dotted one.

`from hashlib import sha256` followed by a bare `sha256(blob)` is idiomatic and
very common in real code — botocore signs every AWS request that way — and a
scanner matching only `hashlib.sha256(...)` misses all of it.
"""
from hashlib import md5, sha1, sha256
from hashlib import sha512 as long_digest
import hashlib as hl

from Crypto.Cipher import AES as Rijndael
from cryptography.hazmat.primitives.asymmetric import rsa as asymmetric


def legacy_checksum(blob):
    return md5(blob).hexdigest()


def legacy_signature(blob):
    return sha1(blob).hexdigest()


def content_digest(blob):
    return sha256(blob).hexdigest()


def aliased_digest(blob):
    return long_digest(blob).hexdigest()


def module_aliased_digest(blob):
    return hl.sha384(blob).hexdigest()


def aliased_cipher(key):
    return Rijndael.new(key, Rijndael.MODE_GCM)


def aliased_keygen():
    return asymmetric.generate_private_key(public_exponent=65537, key_size=3072)


def cache_key(blob):
    """Explicitly not a security control — must not be scored as a risk."""
    return hl.md5(blob, usedforsecurity=False).hexdigest()
