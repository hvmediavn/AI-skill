#!/usr/bin/env python3
"""Reusable Binary String Extractor.

Extracts ASCII and UTF-8 printable strings from any binary file (executable, library, DEX).
Supports minimum length filtering and keyword matching. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def extract_printable_strings(
    file_path: Path | str,
    min_len: int = 4,
    keywords: list[str] | None = None,
) -> list[str]:
    """Extract printable ASCII and UTF-8 strings from a binary file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    content = path.read_bytes()
    # Match sequences of printable ASCII chars
    pattern = rf"[\x20-\x7E]{{{min_len},}}".encode("ascii")
    raw_matches = re.findall(pattern, content)

    extracted = [m.decode("ascii", errors="ignore") for m in raw_matches]

    if keywords:
        kw_lower = [k.lower().strip() for k in keywords if k.strip()]
        extracted = [s for s in extracted if any(k in s.lower() for k in kw_lower)]

    return extracted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract printable strings from binary files.")
    parser.add_argument("--file", type=Path, required=True, help="Path to binary file")
    parser.add_argument("--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument(
        "--filter",
        help="Comma-separated keywords to filter strings (e.g. 'http,key,token,admin')",
    )
    parser.add_argument("--limit", type=int, default=100, help="Max results to print (default: 100)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    keywords = [k.strip() for k in args.filter.split(",")] if args.filter else None

    try:
        results = extract_printable_strings(args.file, min_len=args.min_len, keywords=keywords)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results[: args.limit], indent=2))
        return 0

    print(f"=== Extracted Strings: {args.file.name} (Total: {len(results)}) ===")
    for s in results[: args.limit]:
        print(s)

    if len(results) > args.limit:
        print(f"\n... and {len(results) - args.limit} more strings (use --limit to show more)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
