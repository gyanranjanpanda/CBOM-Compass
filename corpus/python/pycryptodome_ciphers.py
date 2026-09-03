"""Symmetric ciphers via pycryptodome."""
from Crypto.Cipher import AES, ARC4, DES, DES3


def ecb_cipher(key):
    return AES.new(key, AES.MODE_ECB)


def gcm_cipher(key):
    return AES.new(key, AES.MODE_GCM)


def triple_des(key, iv):
    return DES3.new(key, DES3.MODE_CBC, iv)


def single_des(key):
    return DES.new(key, DES.MODE_ECB)


def stream_cipher(key):
    return ARC4.new(key)
