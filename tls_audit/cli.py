"""Command-line interface for tls-audit."""

from __future__ import annotations

import argparse
import json

from . import __version__, audit, output


def _parse_target(spec: str, default_port: int):
    s = spec.strip()
    if s.startswith("https://") or s.startswith("http://"):
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].rstrip(":")

    if s.startswith("["):  # IPv6 literal: [::1]:443
        host, _, rest = s[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port

    if s.count(":") == 1:
        host, _, port = s.partition(":")
        if port.isdigit():
            return host, int(port)

    return s, default_port


def _collect_targets(args):
    targets = []
    for spec in args.targets:
        targets.append(_parse_target(spec, args.port))
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.append(_parse_target(line, args.port))
    return targets


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="tls-audit",
        description="Audit a host's TLS configuration, certificate, and post-quantum readiness.",
    )
    parser.add_argument("targets", nargs="*", help="hosts to audit (optionally host:port)")
    parser.add_argument("-f", "--file", metavar="PATH", help="read hosts from a file (one per line, # for comments)")
    parser.add_argument("-p", "--port", type=int, default=443, help="default port (default: 443)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="connection timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true", help="output structured JSON")
    parser.add_argument("--version", action="version", version=f"tls-audit {__version__}")
    args = parser.parse_args(argv)

    targets = _collect_targets(args)
    if not targets:
        parser.error("no targets given — pass hosts or use -f/--file")

    results = [audit.audit_host(host, port, args.timeout) for host, port in targets]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(output.render_terminal(results))

    return 1 if any(output.evaluate(r)[0] for r in results) else 0
