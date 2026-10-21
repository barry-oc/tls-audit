import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_audit import certificate


def _make_cert(days=90, sha1=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("test.example"), x509.DNSName("www.test.example")]
            ),
            critical=False,
        )
    )
    algo = hashes.SHA1() if sha1 else hashes.SHA256()
    return builder.sign(key, algo).public_bytes(serialization.Encoding.DER)


def test_parse_certificate_basic():
    info = certificate.parse_certificate(_make_cert())
    assert info["subject"] == "test.example"
    assert info["issuer"] == "test.example"
    assert info["key"]["type"] == "RSA"
    assert info["key"]["bits"] == 2048
    assert info["signature_sha1"] is False
    assert "test.example" in info["sans"]
    assert "www.test.example" in info["sans"]
    assert 0 <= info["days_left"] <= 90


def test_parse_certificate_detects_sha1():
    info = certificate.parse_certificate(_make_cert(sha1=True))
    assert info["signature_sha1"] is True


def test_parse_certificate_detects_expiry():
    info = certificate.parse_certificate(_make_cert(days=-5))
    assert info["expired"] is True
    assert info["days_left"] < 0
