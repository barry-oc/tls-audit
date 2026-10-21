"""X.509 certificate parsing for tls-audit."""

from __future__ import annotations

import datetime as _dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

_SIG_ALG_NAMES = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10040.4.3": "dsaWithSha1",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


def _utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _validity(cert, name):
    # cryptography >= 42 exposes *_utc; older versions only expose the naive form.
    try:
        value = getattr(cert, name + "_utc")
    except AttributeError:
        value = getattr(cert, name)
    return _utc(value)


def _cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    return name.rfc4514_string()


def _describe_key(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": public_key.key_size, "curve": None}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "type": "EC",
            "bits": public_key.curve.key_size,
            "curve": public_key.curve.name,
        }
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 256, "curve": None}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 456, "curve": None}
    return {"type": type(public_key).__name__, "bits": None, "curve": None}


def parse_certificate(der: bytes) -> dict:
    """Parse a DER-encoded X.509 certificate into a findings dict."""
    cert = x509.load_der_x509_certificate(der)

    not_before = _validity(cert, "not_valid_before")
    not_after = _validity(cert, "not_valid_after")
    now = _dt.datetime.now(_dt.timezone.utc)
    days_left = (not_after - now).days

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(v.value) for v in san_ext.value]
    except x509.ExtensionNotFound:
        sans = []

    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_name = _SIG_ALG_NAMES.get(sig_oid, sig_oid)
    sig_sha1 = isinstance(cert.signature_hash_algorithm, hashes.SHA1)

    return {
        "subject": _cn(cert.subject),
        "issuer": _cn(cert.issuer),
        "serial_number": str(cert.serial_number),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "expired": days_left < 0,
        "key": _describe_key(cert.public_key()),
        "signature_algorithm": sig_name,
        "signature_sha1": sig_sha1,
        "sans": sans,
    }
