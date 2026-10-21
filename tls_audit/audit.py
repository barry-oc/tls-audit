"""Core audit logic: connect to a host and check TLS, certificate, and ciphers."""

from __future__ import annotations

import ipaddress
import socket
import ssl

from . import certificate

DEFAULT_TIMEOUT = 10.0

# (category, OpenSSL cipher string) — each tested against TLS 1.2.
WEAK_CIPHERS = [
    ("RC4", "RC4-SHA:RC4-MD5"),
    ("3DES", "DES-CBC3-SHA"),
    ("NULL", "NULL-SHA256:NULL-SHA:NULL-MD5"),
    ("EXPORT", "EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5"),
    ("ANON", "ADH-AES256-GCM-SHA384:ADH-AES128-GCM-SHA256:AECDH-AES256-SHA"),
]

_PQC_HINTS = (
    "kyber", "mlkem", "ml-kem", "x25519kyber", "frodokem",
    "dilithium", "mldsa", "ml-dsa", "falcon", "sphincs",
    "ntru", "sike", "classic mceliece", "bike", "hqc",
)

_PROTOCOLS = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _no_verify_context() -> ssl.SSLContext:
    """A client context that does not verify the peer (so we can still
    inspect expired/self-signed certificates)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _resolve(host: str, port: int):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return infos[0][4][0]
    except socket.gaierror:
        return None


def audit_host(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> dict:
    server_hostname = None if _is_ip(host) else host

    result = {
        "host": host,
        "port": port,
        "ip": _resolve(host, port),
        "reachable": False,
        "certificate": None,
        "chain_valid": None,
        "protocols": {},
        "weak_ciphers": {},
        "negotiated": None,
        "post_quantum": {},
        "errors": [],
    }

    if result["ip"] is None:
        result["errors"].append("DNS resolution failed")
        return result

    # 1) Main connection: grab certificate + negotiated parameters (no verification).
    ctx = _no_verify_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                result["reachable"] = True
                der = ssock.getpeercert(binary_form=True)
                if der:
                    result["certificate"] = certificate.parse_certificate(der)
                cipher = ssock.cipher()
                result["negotiated"] = {
                    "version": ssock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "bits": cipher[2] if cipher else None,
                }
    except (ssl.SSLError, socket.error, OSError) as exc:
        result["errors"].append(f"TLS handshake failed: {exc}")
        return result

    # 2) Certificate chain validation (default verification).
    result["chain_valid"] = _check_chain(host, port, timeout, server_hostname)

    # 3) Protocol support.
    for label, version in _PROTOCOLS:
        result["protocols"][label] = _probe_protocol(host, port, timeout, version, server_hostname)

    # 4) Weak cipher acceptance (TLS 1.2).
    for category, cipher_str in WEAK_CIPHERS:
        result["weak_ciphers"][category] = _probe_cipher(host, port, timeout, cipher_str, server_hostname)

    # 5) Post-quantum detection.
    result["post_quantum"] = _pq_check(result)

    return result


def _check_chain(host, port, timeout, server_hostname):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname):
                return {"valid": True, "error": None}
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": str(exc)}
    except (ssl.SSLError, socket.error, OSError) as exc:
        return {"valid": False, "error": str(exc)}


def _probe_protocol(host, port, timeout, version, server_hostname):
    ctx = _no_verify_context()
    ctx.minimum_version = version
    ctx.maximum_version = version
    try:
        # SECLEVEL=0 so legacy TLS 1.0/1.1 ciphers are still offered locally.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                return {"supported": True, "version": ssock.version()}
    except (ssl.SSLError, socket.error, OSError):
        return {"supported": False, "version": None}


def _probe_cipher(host, port, timeout, cipher_str, server_hostname):
    ctx = _no_verify_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(f"{cipher_str}:@SECLEVEL=0")
    except ssl.SSLError:
        return {"accepted": False, "cipher": None, "note": "unavailable in local OpenSSL"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                c = ssock.cipher()
                return {"accepted": True, "cipher": c[0] if c else None, "note": None}
    except (ssl.SSLError, socket.error, OSError):
        return {"accepted": False, "cipher": None, "note": None}


def _pq_check(result):
    evidence = []
    negotiated = result.get("negotiated") or {}
    cipher = (negotiated.get("cipher") or "").lower()
    for hint in _PQC_HINTS:
        if hint in cipher:
            evidence.append(hint)
    cert = result.get("certificate") or {}
    sig = (cert.get("signature_algorithm") or "").lower()
    for hint in ("dilithium", "mldsa", "ml-dsa", "falcon", "sphincs"):
        if hint in sig:
            evidence.append(hint)
    if evidence:
        return {"status": "post_quantum", "evidence": sorted(set(evidence))}
    return {"status": "classical", "evidence": []}
