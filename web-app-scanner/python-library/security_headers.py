#!/usr/bin/env python3
"""Reusable Security Headers and TLS Auditor.

Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, CORS, and Cookie security flags for any web endpoint.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

RECOMMENDED_HEADERS: dict[str, dict[str, str]] = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "expected": "max-age=31536000; includeSubDomains",
        "severity": "HIGH",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "expected": "default-src 'self' ...",
        "severity": "HIGH",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "expected": "nosniff",
        "severity": "MEDIUM",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "expected": "DENY or SAMEORIGIN",
        "severity": "MEDIUM",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "expected": "strict-origin-when-cross-origin or no-referrer",
        "severity": "LOW",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "expected": "geolocation=(), camera=(), microphone=()",
        "severity": "LOW",
    },
}


def audit_security_headers(url: str, timeout: int = 10) -> dict[str, Any]:
    """Audit HTTP security headers for a given URL."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"},
    )

    ctx = ssl.create_default_context()
    tls_version = None
    tls_cipher = None

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            status = resp.getcode()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            sock = resp.fp.raw._sock if hasattr(resp, "fp") and hasattr(resp.fp, "raw") else None
            if sock and hasattr(sock, "version"):
                tls_version = sock.version()
                cipher_info = sock.cipher()
                tls_cipher = cipher_info[0] if cipher_info else None
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = {k.lower(): v for k, v in exc.headers.items()}
    except Exception as exc:
        raise RuntimeError(f"Connection failed for {url}: {exc}") from exc

    analysis: dict[str, Any] = {
        "url": url,
        "status_code": status,
        "tls_version": tls_version,
        "tls_cipher": tls_cipher,
        "headers_present": {},
        "missing_headers": [],
        "cors": {},
        "cookies": [],
    }

    for key, spec in RECOMMENDED_HEADERS.items():
        val = headers.get(key)
        if val:
            analysis["headers_present"][key] = {
                "name": spec["name"],
                "value": val,
            }
        else:
            analysis["missing_headers"].append({
                "header": key,
                "name": spec["name"],
                "severity": spec["severity"],
                "expected": spec["expected"],
            })

    # Check CORS headers
    cors_origin = headers.get("access-control-allow-origin")
    cors_creds = headers.get("access-control-allow-credentials")
    if cors_origin:
        analysis["cors"]["allow_origin"] = cors_origin
        analysis["cors"]["allow_credentials"] = cors_creds
        analysis["cors"]["wildcard_with_creds"] = cors_origin == "*" and cors_creds == "true"

    # Check Cookie flags
    set_cookies = [v for k, v in headers.items() if k == "set-cookie"]
    for cookie_header in set_cookies:
        cookie_parts = [p.strip() for p in cookie_header.split(";")]
        name_val = cookie_parts[0]
        flags = [p.lower() for p in cookie_parts[1:]]
        analysis["cookies"].append({
            "cookie": name_val,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": next((p for p in cookie_parts if p.lower().startswith("samesite")), None),
        })

    return analysis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit HTTP Security Headers and TLS configuration.")
    parser.add_argument("--url", required=True, help="Target URL or domain (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        results = audit_security_headers(args.url, timeout=args.timeout)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    print(f"=== Security Headers Audit: {results['url']} ===")
    print(f"Status Code: {results['status_code']}")
    if results["tls_version"]:
        print(f"TLS: {results['tls_version']} ({results['tls_cipher']})")

    print(f"\n[+] Configured Headers ({len(results['headers_present'])}):")
    for k, v in results["headers_present"].items():
        print(f"  ✓ {v['name']}: {v['value']}")

    print(f"\n[-] Missing Headers ({len(results['missing_headers'])}):")
    for m in results["missing_headers"]:
        print(f"  ✗ [{m['severity']}] {m['name']} (Expected: {m['expected']})")

    if results["cors"]:
        print(f"\n[*] CORS Policy:")
        print(f"  Origin: {results['cors'].get('allow_origin')}")
        print(f"  Credentials: {results['cors'].get('allow_credentials')}")
        if results["cors"].get("wildcard_with_creds"):
            print("  ! CRITICAL: Wildcard CORS origin with credentials allowed!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
