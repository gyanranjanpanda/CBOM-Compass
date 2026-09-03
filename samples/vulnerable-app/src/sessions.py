import hashlib
from Crypto.Cipher import DES3, ARC4
from cryptography.hazmat.primitives.asymmetric import x25519


def session_key_exchange():
    return x25519.X25519PrivateKey.generate()


def legacy_vpn_cipher(key, iv):
    return DES3.new(key, DES3.MODE_CBC, iv)


def ancient_stream(key):
    return ARC4.new(key)


def session_id(seed):
    return hashlib.sha1(seed).hexdigest()
