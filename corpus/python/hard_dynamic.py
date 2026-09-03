"""Hard cases: real cryptography that static analysis cannot resolve.

These are labelled as expected findings. We currently miss them, and the
evaluator reports that as a miss rather than quietly excluding them.
"""
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import rsa

ALGORITHM = os.environ.get("DIGEST", "md5")
KEY_BITS = int(os.environ.get("RSA_BITS", "1024"))


def configured_digest(blob):
    # Algorithm chosen at runtime from configuration.
    return hashlib.new(ALGORITHM, blob).hexdigest()


def configured_key():
    # Key size chosen at runtime.
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def indirect_digest(blob):
    fn = getattr(hashlib, "sha1")
    return fn(blob).hexdigest()
