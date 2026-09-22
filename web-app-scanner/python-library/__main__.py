#!/usr/bin/env python3
"""Unified CLI entry point for the reusable python-library toolkit."""

from __future__ import annotations

import argparse
import sys

from . import (
    api_contract,
    apk_inspector,
    bundle_analyzer,
    port_scanner,
    security_headers,
    sourcemap_extractor,
    string_extractor,
    web_audit,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m python_library",
        description="Reusable Web Security & Reconnaissance Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    subparsers.add_parser("bundle", help="Analyze JavaScript bundle", add_help=False)
    subparsers.add_parser("sourcemap", help="Inspect and extract sourcemaps", add_help=False)
    subparsers.add_parser("headers", help="Audit HTTP security headers and TLS", add_help=False)
    subparsers.add_parser("ports", help="Fast TCP port scanner", add_help=False)
    subparsers.add_parser("audit", help="Unified web application auditor", add_help=False)
    subparsers.add_parser("contract", help="API contract and health auditor", add_help=False)
    subparsers.add_parser("apk", help="Inspect Android APK / DEX bytecode", add_help=False)
    subparsers.add_parser("strings", help="Extract printable strings from binaries", add_help=False)

    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return 0

    cmd = argv[0]
    rest = argv[1:]

    dispatch = {
        "bundle": bundle_analyzer.main,
        "sourcemap": sourcemap_extractor.main,
        "headers": security_headers.main,
        "ports": port_scanner.main,
        "audit": web_audit.main,
        "contract": api_contract.main,
        "apk": apk_inspector.main,
        "strings": string_extractor.main,
    }

    if cmd in dispatch:
        return dispatch[cmd](rest)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
