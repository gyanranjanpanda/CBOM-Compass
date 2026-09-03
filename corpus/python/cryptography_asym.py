"""Asymmetric key generation via pyca/cryptography."""
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed25519, rsa, x25519


def weak_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def standard_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def strong_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def legacy_dsa():
    return dsa.generate_private_key(key_size=2048)


def p256_key():
    return ec.generate_private_key(ec.SECP256R1())


def p384_key():
    return ec.generate_private_key(ec.SECP384R1())


def edwards_key():
    return ed25519.Ed25519PrivateKey.generate()


def montgomery_key():
    return x25519.X25519PrivateKey.generate()


def finite_field_params():
    return dh.generate_parameters(generator=2, key_size=2048)
