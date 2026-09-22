#!/usr/bin/env python3
"""Reusable JavaScript bundle analyzer for security auditing.

Extracts API endpoints, tokens, secrets, storage keys, and payment patterns.
Can analyze a remote URL or a local file. Standard library only (urllib fallback).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

PATTERNS: dict[str, str] = {
    "telegram_bots": r"(?i)\b[0-9]{8,10}:[a-zA-Z0-9_-]{32,36}\b",
    "revenuecat_keys": r"(?i)\b(?:appl|goog|rcb)_[a-zA-Z0-9_-]{16,}\b",
    "google_api_keys": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "jwt_tokens": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "vietqr_urls": r"https?://[^\s\"'`]+vietqr[^\s\"'`]+",
    "api_routes": r"['\"`](/api/[^\s\"'`<>]+)['\"`]",
    "generic_endpoints": r"['\"`](/(?:v1|v2|v3|auth|user|admin|order|payment|webhook|ctv)/[^\s\"'`<>]+)['\"`]",
    "localstorage_keys": r"(?i)localStorage\.(?:getItem|setItem|removeItem)\(['\"]([^'\"]+)['\"]",
    "payment_keywords": r"(?i)\b(?:stk|so_tai_khoan|ngan_hang|bank_account|chu_tai_khoan|qr_code|sepay|casso|payos)\b",
    "admin_auth_hints": r"(?i)\b(?:admin|role|ctv|daily|agency|superadmin|dashboard_secret)\b",
}


def fetch_bundle(url: str, timeout: int = 15, user_agent: str = DEFAULT_USER_AGENT) -> str:
    """Fetch bundle text from remote URL."""
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def analyze_bundle_content(code: str, source_label: str = "bundle") -> dict[str, Any]:
    """Analyze JavaScript code string and return structured findings."""
    results: dict[str, Any] = {
        "source": source_label,
        "char_count": len(code),
        "byte_count": len(code.encode("utf-8")),
        "findings": {},
        "react_components": [],
        "context_snippets": [],
    }

    for key, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, code)))
        results["findings"][key] = sorted(matches)[:50]

    # React component names
    comp_names = sorted(list(set(re.findall(r"\bfunction\s+([A-Z][a-zA-Z0-9_]{2,})\s*\(", code))))
    results["react_components"] = comp_names[:40]

    # Context snippets around key terms
    snippets = []
    for term in ("admin", "upgrade", "token", "apiKey", "secret"):
        for m in re.finditer(rf"(?i)\b{re.escape(term)}\b", code):
            start = max(0, m.start() - 100)
            end = min(len(code), m.end() + 100)
            snippet = code[start:end].replace("\n", " ").strip()
            if snippet and snippet not in snippets:
                snippets.append(snippet)
            if len(snippets) >= 10:
                break
        if len(snippets) >= 10:
            break
    results["context_snippets"] = snippets

    return results


def analyze(
    target_url: str | None = None,
    file_path: Path | str | None = None,
    out_file: Path | str | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """Main entry point to analyze a JS bundle by URL or file path."""
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Bundle file not found: {path}")
        code = path.read_text(encoding="utf-8", errors="replace")
        label = str(path.name)
    elif target_url:
        code = fetch_bundle(target_url, timeout=timeout)
        label = target_url
    else:
        raise ValueError("Must provide either target_url or file_path")

    data = analyze_bundle_content(code, source_label=label)

    if out_file:
        out_path = Path(out_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze JavaScript bundles for endpoints, keys, and tokens.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Target URL of the remote JS bundle")
    group.add_argument("--file", type=Path, help="Local path to the JS bundle file")
    parser.add_argument("--out", type=Path, help="Save structured JSON report to this file")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    parser.add_argument("--json", action="store_true", help="Print output as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = analyze(target_url=args.url, file_path=args.file, out_file=args.out, timeout=args.timeout)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"=== Bundle Analysis: {report['source']} ===")
        print(f"Size: {report['char_count']} chars ({report['byte_count']} bytes)")
        for key, matches in report["findings"].items():
            if matches:
                print(f"\n[+] {key} ({len(matches)}):")
                for item in matches[:10]:
                    print(f"  - {item}")
        if report["react_components"]:
            print(f"\n[+] React Components ({len(report['react_components'])}):")
            print("  " + ", ".join(report["react_components"][:15]))
        if args.out:
            print(f"\nWrote full report to: {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
