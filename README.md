# tls-audit

**Check a host's TLS configuration, certificate, and post-quantum readiness.**

`tls-audit` connects to a host and reports what it actually negotiates —
the certificate, which protocol versions are enabled, whether known-weak
ciphers are accepted, and whether anything post-quantum is in play.

It is a companion to [`sec-headers`](https://github.com/barry-oc/sec-headers),
which covers the HTTP layer. This tool covers the transport layer.

Example output (illustrative):

```text
━━━ example.com:443  (93.184.216.34) ━━━
  Certificate
    Subject     example.com
    Issuer      Example CA
    Serial      1234567890
    Expiry      ✓ 83 days remaining
    Key         EC 256 bits (secp256r1)
    Signature   ✓ ecdsa-with-SHA256
    SANs        example.com, *.example.com
  Chain        ✓ validates
  Protocols
    ✓ TLS 1.3   enabled
    ✓ TLS 1.2   enabled
    ✓ TLS 1.1   disabled
    ✓ TLS 1.0   disabled
  Weak ciphers (TLS 1.2)
    ✓ RC4       not accepted
    ✓ 3DES      not accepted
    ✓ NULL      not accepted
    ✓ EXPORT    not accepted
    ✓ ANON      not accepted
  Post-quantum
    ⚠ classical key exchange (no PQC detected)
      → traffic is exposed to harvest-now-decrypt-later
  Result: ✓ clean (1 warning(s))
```

## What it checks

| Check | What it reports |
|---|---|
| Certificate | subject, issuer, serial, expiry, key type/size, signature algorithm, SANs |
| Chain | whether the certificate chain validates against the system trust store |
| Protocols | which of TLS 1.0 / 1.1 / 1.2 / 1.3 the server accepts |
| Weak ciphers | whether RC4, 3DES, NULL, EXPORT, or anonymous ciphers are accepted |
| Post-quantum | whether any PQC key exchange or signature is detected |

## Install

```bash
pip install git+https://github.com/barry-oc/tls-audit.git
```

Or from source:

```bash
git clone https://github.com/barry-oc/tls-audit.git
cd tls-audit
pip install -e .
```

## Usage

### Single host

```bash
tls-audit example.com
tls-audit example.com:8443
```

### Multiple hosts

```bash
tls-audit example.com barryocallaghan.com google.com
```

### From a file (one host per line, `#` for comments)

```bash
tls-audit -f hosts.txt
```

### JSON output

```bash
tls-audit example.com --json | jq '.[0].certificate.days_left'
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-f, --file PATH` | — | Read hosts from a file |
| `-p, --port N` | 443 | Default port (hosts without an explicit port) |
| `-t, --timeout SEC` | 10 | Connection timeout |
| `--json` | off | Structured JSON output |
| `--version` | — | Show version |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No failures (warnings allowed) |
| 1 | At least one failure |

Failures are: expired certificate, SHA-1 signature, RSA key under 2048 bits,
certificate chain that does not validate, TLS 1.0/1.1 enabled, or a weak
cipher accepted.

## Limitations

This tool is honest about what it can and cannot measure:

- **Weak-cipher detection depends on the local OpenSSL build.** If a cipher
  (usually RC4 or EXPORT) has been compiled out of your Python's OpenSSL, the
  tool reports it as "untestable" rather than guessing.
- **Post-quantum detection is basic.** Python's TLS stack does not yet expose
  the negotiated key-exchange group, so PQC detection is limited to cipher-suite
  and certificate-signature names. For the vast majority of servers today this
  correctly reports "classical" — which is the point.
- **TLS 1.0/1.1 probing** requires the client OpenSSL to still offer legacy
  ciphers. The tool forces `SECLEVEL=0` to maximize detection, but a hardened
  client build may under-report support.

If you need exhaustive cipher and protocol enumeration (every cipher, every
extension), use `testssl.sh` or `nmap --script ssl-enum-ciphers`. This tool is
meant for a fast, scriptable, honest health check — not a full lab-grade audit.

## Requirements

- Python 3.9+
- `cryptography` (installed automatically)

## License

MIT © 2026 Barry O'Callaghan
