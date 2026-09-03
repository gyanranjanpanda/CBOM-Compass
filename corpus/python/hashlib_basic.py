"""Hash usage across the stdlib surface."""
import hashlib


def legacy_checksum(blob):
    return hashlib.md5(blob).hexdigest()


def legacy_signature_digest(blob):
    return hashlib.sha1(blob).hexdigest()


def content_digest(blob):
    return hashlib.sha256(blob).hexdigest()


def archive_digest(blob):
    return hashlib.sha384(blob).hexdigest()


def long_term_digest(blob):
    return hashlib.sha512(blob).hexdigest()
