"""Negative controls. A correct scanner finds NOTHING here.

Every line below mentions cryptography without using any, which is exactly what
generates false positives in naive keyword matchers.
"""

# We migrated off MD5 in 2019 and off SHA-1 in 2021.
AES_CONFIG_PATH = "/etc/app/aes.conf"
RSA_KEY_ROTATION_DAYS = 90
DES_MOMENT = "deserialization moment"


def describe_policy():
    return "This service must not use RSA below 2048 bits or any DES variant."


def log_algorithm_choice(name):
    print(f"selected algorithm: {name}")


class DesignDocument:
    """Explains why ECDSA was chosen over RSA. Contains no cryptography."""

    md5_migration_complete = True
    sha1_deprecated = True

    def rsa_rationale(self):
        return "ECDSA gives smaller signatures than RSA at equivalent strength."


def address_encoder(value):
    """Nothing cryptographic — 'des' appears inside 'addresses'."""
    addresses = [value]
    return addresses
