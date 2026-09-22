#!/usr/bin/env python3
"""Reusable JavaScript source map inspector and unpacker.

Checks, fetches, and reconstructs original source files from .js.map source maps.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def fetch_sourcemap(url: str, timeout: int = 15) -> tuple[int, str]:
    """Fetch remote sourcemap by URL, returning HTTP status and text."""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            return status, body
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch sourcemap: {exc}") from exc


def parse_sourcemap_data(raw_data: str) -> dict[str, Any]:
    """Parse raw JSON string of a sourcemap and extract metadata."""
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid sourcemap JSON format") from exc

    version = data.get("version", 3)
    file_target = data.get("file", "")
    sources = data.get("sources", [])
    sources_content = data.get("sourcesContent", [])

    return {
        "version": version,
        "file": file_target,
        "sources_count": len(sources),
        "sources": sources,
        "has_content": bool(sources_content),
        "sources_content_count": len(sources_content) if sources_content else 0,
        "_raw_data": data,
    }


def unpack_sources(map_data: dict[str, Any], output_dir: Path) -> int:
    """Unpack embedded sourcesContent into files under output_dir."""
    sources = map_data.get("sources", [])
    contents = map_data.get("_raw_data", {}).get("sourcesContent", [])
    if not contents:
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    unpacked = 0

    for src_path, content in zip(sources, contents):
        if not content:
            continue
        # Clean relative path (remove webpack:/// or leading slashes)
        clean = src_path.replace("webpack:///", "").replace("webpack://", "").lstrip("/\\")
        clean_parts = [p for p in Path(clean).parts if p not in ("..", ".")]
        if not clean_parts:
            clean_parts = [f"source_{unpacked}.js"]
        target = output_dir.joinpath(*clean_parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", errors="replace")
        unpacked += 1

    return unpacked


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect and extract JavaScript source maps.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="URL to the source map (.js.map) or bundle")
    group.add_argument("--file", type=Path, help="Local path to .js.map file")
    parser.add_argument("--out-dir", type=Path, help="Directory to unpack source files into")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    parser.add_argument("--json", action="store_true", help="Output summary as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.file:
            path = Path(args.file)
            if not path.is_file():
                print(f"Error: File not found: {path}", file=sys.stderr)
                return 1
            raw = path.read_text(encoding="utf-8", errors="replace")
            source_label = str(path)
        else:
            url = args.url
            if not url.endswith(".map"):
                url = f"{url}.map"
            print(f"Checking sourcemap: {url} ...")
            status, raw = fetch_sourcemap(url, timeout=args.timeout)
            if status != 200 or not raw:
                print(f"Sourcemap not available (HTTP status: {status})")
                return 1
            source_label = url

        meta = parse_sourcemap_data(raw)
        meta["source_label"] = source_label

        unpacked_count = 0
        if args.out_dir:
            unpacked_count = unpack_sources(meta, args.out_dir)

        if args.json:
            result = {
                "source": source_label,
                "file": meta["file"],
                "version": meta["version"],
                "sources_count": meta["sources_count"],
                "has_content": meta["has_content"],
                "unpacked": unpacked_count,
                "sample_sources": meta["sources"][:30],
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"[+] Sourcemap found: {source_label}")
            print(f"    Target file: {meta['file']}")
            print(f"    Total original sources: {meta['sources_count']}")
            print(f"    Has embedded source code: {meta['has_content']}")
            if meta["sources"]:
                print("    Sample source paths:")
                for s in meta["sources"][:15]:
                    print(f"      - {s}")
            if args.out_dir:
                print(f"[+] Unpacked {unpacked_count} source files to: {args.out_dir}")

        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
