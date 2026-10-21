"""Terminal and JSON rendering for tls-audit results."""

from __future__ import annotations


def evaluate(result):
    """Return (fails, warns) string lists for a single audit result."""
    fails: list = []
    warns: list = []

    cert = result.get("certificate")
    if cert:
        if cert.get("expired"):
            fails.append("certificate is expired")
        elif cert.get("days_left") is not None and cert["days_left"] <= 30:
            warns.append(f"certificate expires in {cert['days_left']} days")
        if cert.get("signature_sha1"):
            fails.append("certificate uses a SHA-1 signature")
        key = cert.get("key") or {}
        if key.get("type") == "RSA" and key.get("bits") and key["bits"] < 2048:
            fails.append(f"RSA key is {key['bits']} bits (under 2048)")

    chain = result.get("chain_valid")
    if chain and not chain.get("valid"):
        fails.append("certificate chain does not validate")

    for label, info in (result.get("protocols") or {}).items():
        if info.get("supported") and label in ("TLS 1.0", "TLS 1.1"):
            fails.append(f"{label} is enabled")

    for category, info in (result.get("weak_ciphers") or {}).items():
        if info.get("accepted"):
            fails.append(f"{category} cipher accepted")

    pq = result.get("post_quantum") or {}
    if pq.get("status") == "classical":
        warns.append("no post-quantum key exchange detected")

    return fails, warns


def render_terminal(results):
    lines: list = []
    for r in results:
        lines.append("")
        lines.append(_header(r))
        if not r.get("reachable"):
            for e in r.get("errors") or ["connection failed"]:
                lines.append(f"  ✗ {e}")
            continue

        _cert_section(r, lines)
        _chain_section(r, lines)
        _protocol_section(r, lines)
        _cipher_section(r, lines)
        _pq_section(r, lines)

        fails, warns = evaluate(r)
        if not fails:
            lines.append(f"  Result: ✓ clean ({len(warns)} warning(s))")
        else:
            lines.append(f"  Result: ✗ {len(fails)} failure(s), {len(warns)} warning(s)")
    return "\n".join(lines)


def _header(r):
    ip = r.get("ip") or "unresolved"
    return f"━━━ {r['host']}:{r['port']}  ({ip}) ━━━"


def _cert_section(r, lines):
    cert = r.get("certificate")
    if not cert:
        lines.append("  Certificate")
        lines.append("    ✗ no certificate presented")
        return

    lines.append("  Certificate")
    lines.append(f"    Subject     {cert.get('subject')}")
    lines.append(f"    Issuer      {cert.get('issuer')}")
    lines.append(f"    Serial      {cert.get('serial_number')}")

    days = cert.get("days_left")
    if cert.get("expired"):
        lines.append(f"    Expiry      ✗ EXPIRED ({abs(days)} days ago)")
    elif days is not None and days <= 30:
        lines.append(f"    Expiry      ⚠ {days} days remaining")
    else:
        lines.append(f"    Expiry      ✓ {days} days remaining")

    key = cert.get("key") or {}
    curve = f" ({key['curve']})" if key.get("curve") else ""
    bits = key.get("bits") or "?"
    lines.append(f"    Key         {key.get('type')} {bits} bits{curve}")

    sig = cert.get("signature_algorithm")
    if cert.get("signature_sha1"):
        lines.append(f"    Signature   ✗ {sig} (SHA-1)")
    else:
        lines.append(f"    Signature   ✓ {sig}")

    sans = cert.get("sans") or []
    lines.append(f"    SANs        {', '.join(sans) if sans else '(none)'}")


def _chain_section(r, lines):
    chain = r.get("chain_valid")
    if not chain:
        return
    if chain.get("valid"):
        lines.append("  Chain        ✓ validates")
    else:
        lines.append(f"  Chain        ✗ {chain.get('error')}")


def _protocol_section(r, lines):
    lines.append("  Protocols")
    for label in ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"):
        info = (r.get("protocols") or {}).get(label)
        if info is None:
            continue
        if info.get("supported"):
            mark = "✗" if label in ("TLS 1.0", "TLS 1.1") else "✓"
            lines.append(f"    {mark} {label:<8} enabled")
        else:
            mark = "✓" if label in ("TLS 1.0", "TLS 1.1") else "✗"
            lines.append(f"    {mark} {label:<8} disabled")


def _cipher_section(r, lines):
    weak = r.get("weak_ciphers") or {}
    if not weak:
        return
    lines.append("  Weak ciphers (TLS 1.2)")
    for category in ("RC4", "3DES", "NULL", "EXPORT", "ANON"):
        info = weak.get(category)
        if info is None:
            continue
        if info.get("accepted"):
            lines.append(f"    ✗ {category:<8} ACCEPTED")
        elif info.get("note"):
            lines.append(f"    • {category:<8} untestable ({info['note']})")
        else:
            lines.append(f"    ✓ {category:<8} not accepted")


def _pq_section(r, lines):
    pq = r.get("post_quantum") or {}
    lines.append("  Post-quantum")
    if pq.get("status") == "post_quantum":
        lines.append(f"    ✓ {', '.join(pq.get('evidence') or [])} detected")
    else:
        lines.append("    ⚠ classical key exchange (no PQC detected)")
        lines.append("      → traffic is exposed to harvest-now-decrypt-later")
