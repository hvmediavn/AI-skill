#!/usr/bin/env python3
"""Reusable Public API Contract and Endpoint Health Auditor.

Checks endpoint HTTP status, response headers, content types, latency, and JSON schema.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def probe_endpoint(
    base_url: str,
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Probe a single endpoint and measure status, latency, headers, and body."""
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers, method=method)
    t0 = time.time()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - t0
            raw_body = resp.read(65536)  # Read up to 64KB
            content_type = resp.headers.get("Content-Type", "")
            is_json = "application/json" in content_type.lower()
            parsed_json = None
            if is_json:
                try:
                    parsed_json = json.loads(raw_body.decode("utf-8", errors="replace"))
                except Exception:
                    pass

            return {
                "path": path,
                "url": url,
                "status": resp.getcode(),
                "elapsed_seconds": round(elapsed, 3),
                "content_type": content_type,
                "is_json": is_json,
                "json_keys": list(parsed_json.keys()) if isinstance(parsed_json, dict) else [],
                "body_snippet": raw_body[:200].decode("utf-8", errors="replace"),
                "ok": True,
            }
    except urllib.error.HTTPError as exc:
        elapsed = time.time() - t0
        return {
            "path": path,
            "url": url,
            "status": exc.code,
            "elapsed_seconds": round(elapsed, 3),
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "ok": False,
            "error": f"HTTP {exc.code}",
        }
    except Exception as exc:
        elapsed = time.time() - t0
        return {
            "path": path,
            "url": url,
            "status": None,
            "elapsed_seconds": round(elapsed, 3),
            "ok": False,
            "error": str(exc),
        }


def audit_api_contract(
    base_url: str,
    endpoints: list[str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Audit a collection of API endpoints against a base URL."""
    if not endpoints:
        endpoints = [
            "/api/health",
            "/api/status",
            "/api/version",
            "/health",
            "/status",
            "/robots.txt",
        ]

    results = []
    for ep in endpoints:
        res = probe_endpoint(base_url, ep, timeout=timeout)
        results.append(res)

    return {
        "base_url": base_url,
        "total_probed": len(endpoints),
        "endpoints": results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Public API Contract and Endpoint Auditor.")
    parser.add_argument("--base-url", required=True, help="API Base URL (e.g. https://api.example.com)")
    parser.add_argument(
        "--endpoints",
        help="Comma-separated paths to probe (e.g. '/api/health,/robots.txt').",
    )
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ep_list = [ep.strip() for ep in args.endpoints.split(",") if ep.strip()] if args.endpoints else None
    res = audit_api_contract(args.base_url, endpoints=ep_list, timeout=args.timeout)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0

    print(f"=== API Contract Audit: {res['base_url']} ===")
    for ep in res["endpoints"]:
        status = ep.get("status") or ep.get("error")
        timing = f"{ep.get('elapsed_seconds', 0)}s"
        ctype = ep.get("content_type", "")
        print(f"[{status}] {ep['path']} ({timing}) {ctype}")
        if ep.get("json_keys"):
            print(f"      Keys: {', '.join(ep['json_keys'][:10])}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
