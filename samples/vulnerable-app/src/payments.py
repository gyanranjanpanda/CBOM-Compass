"""Payment gateway crypto — deliberately mixed quality for scanner fixtures."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def gateway_signing_key():
    # Shor-broken and NIST-deprecated after 2030.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def legacy_partner_key():
    # Below classical strength as well as Shor-broken.
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def card_token_key():
    return ec.generate_private_key(ec.SECP256R1())


def encrypt_pan(key, data):
    # ECB leaks plaintext structure.
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    return cipher.encryptor().update(data)


def encrypt_archive(key, nonce, data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    return cipher.encryptor().update(data)


def receipt_checksum(blob):
    return hashlib.md5(blob).hexdigest()


def audit_digest(blob):
    return hashlib.sha256(blob).hexdigest()


def archive_digest(blob):
    return hashlib.sha384(blob).hexdigest()
