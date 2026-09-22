#!/usr/bin/env python3
"""Unified Web Application Auditor.

Combines HTTP headers inspection, JavaScript script discovery, bundle analysis,
sourcemap probing, and endpoint checks. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from bundle_analyzer import analyze_bundle_content
from security_headers import audit_security_headers
from sourcemap_extractor import fetch_sourcemap, parse_sourcemap_data

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def fetch_page(url: str, timeout: int = 15) -> tuple[int, str, dict[str, str]]:
    """Fetch root HTML page."""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.getcode(), body, headers


def extract_scripts(html: str, base_url: str) -> list[str]:
    """Extract full URLs of script tags from HTML."""
    script_srcs = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
    full_urls: list[str] = []
    for src in script_srcs:
        full_url = urllib.parse.urljoin(base_url, src)
        if full_url not in full_urls:
            full_urls.append(full_url)
    return full_urls


def audit_target(
    target_url: str,
    max_scripts: int = 5,
    timeout: int = 15,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Perform comprehensive web audit on a target URL."""
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    print(f"[*] Auditing target: {target_url} ...")
    report: dict[str, Any] = {
        "target_url": target_url,
        "security_headers": {},
        "discovered_scripts": [],
        "bundles_analysis": [],
        "sourcemaps": [],
    }

    # 1. Security Headers
    try:
        report["security_headers"] = audit_security_headers(target_url, timeout=timeout)
    except Exception as exc:
        report["security_headers"] = {"error": str(exc)}

    # 2. Fetch HTML and extract scripts
    try:
        status, html, _ = fetch_page(target_url, timeout=timeout)
        scripts = extract_scripts(html, target_url)
        report["discovered_scripts"] = scripts
    except Exception as exc:
        print(f"[-] Failed to fetch HTML page: {exc}")
        return report

    # 3. Analyze Scripts & Probing Sourcemaps
    for script_url in scripts[:max_scripts]:
        print(f"[*] Checking bundle: {script_url} ...")
        # Probing sourcemap
        map_url = f"{script_url}.map"
        map_info: dict[str, Any] = {"map_url": map_url, "found": False}
        try:
            m_status, m_body = fetch_sourcemap(map_url, timeout=timeout)
            if m_status == 200 and m_body:
                meta = parse_sourcemap_data(m_body)
                map_info["found"] = True
                map_info["sources_count"] = meta["sources_count"]
                map_info["has_content"] = meta["has_content"]
        except Exception:
            pass
        report["sourcemaps"].append(map_info)

        # Analyze bundle content
        try:
            req = urllib.request.Request(script_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.read().decode("utf-8", errors="replace")
                analysis = analyze_bundle_content(code, source_label=script_url)
                report["bundles_analysis"].append(analysis)
        except Exception as exc:
            report["bundles_analysis"].append({"source": script_url, "error": str(exc)})

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        report_file = out_dir / "audit_report.json"
        report_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Saved audit report to {report_file}")

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unified Web Application Security Auditor.")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--max-scripts", type=int, default=5, help="Max number of JS bundles to analyze (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    parser.add_argument("--out-dir", type=Path, help="Directory to save audit report")
    parser.add_argument("--json", action="store_true", help="Print output as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = audit_target(args.url, max_scripts=args.max_scripts, timeout=args.timeout, out_dir=args.out_dir)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    print(f"\n=== Web Audit Summary: {report['target_url']} ===")
    headers_sec = report.get("security_headers", {})
    if "headers_present" in headers_sec:
        print(f"[+] Headers present: {len(headers_sec['headers_present'])}")
        print(f"[-] Headers missing: {len(headers_sec.get('missing_headers', []))}")
    print(f"[+] Discovered script bundles: {len(report.get('discovered_scripts', []))}")
    maps_found = [m for m in report.get("sourcemaps", []) if m.get("found")]
    if maps_found:
        print(f"[!] Exposed sourcemaps found: {len(maps_found)}")
        for m in maps_found:
            print(f"    - {m['map_url']} ({m.get('sources_count', 0)} sources)")
    else:
        print("[-] No exposed sourcemaps detected.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
