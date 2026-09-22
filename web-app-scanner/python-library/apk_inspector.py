#!/usr/bin/env python3
"""Reusable Android APK / DEX Inspector.

Inspects Android APK packages without requiring apktool or jadx.
Decodes binary AndroidManifest.xml (AXML), extracts DEX class names, strings,
API endpoints, and package metadata. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any


def parse_axml_strings(data: bytes) -> list[str]:
    """Parse string pool from binary AndroidManifest.xml (AXML)."""
    if len(data) < 8:
        return []
    magic, _ = struct.unpack("<II", data[:8])
    if magic != 0x00080003:
        return []

    pos = 8
    strings: list[str] = []
    while pos < len(data) - 8:
        chunk_type, chunk_size = struct.unpack("<II", data[pos : pos + 8])
        if chunk_type == 0x001C0001:  # String pool chunk
            str_count, _, flags, str_start, _ = struct.unpack("<IIIII", data[pos + 8 : pos + 28])
            is_utf8 = bool(flags & (1 << 8))

            offsets = []
            for i in range(str_count):
                off = struct.unpack("<I", data[pos + 28 + i * 4 : pos + 32 + i * 4])[0]
                offsets.append(off)

            base = pos + str_start
            for off in offsets:
                cur = base + off
                if cur >= len(data):
                    continue
                if is_utf8:
                    cur += 1  # skip u16len
                    u8len = data[cur] if cur < len(data) else 0
                    cur += 1
                    s = data[cur : cur + u8len].decode("utf-8", errors="replace")
                else:
                    u16len = struct.unpack("<H", data[cur : cur + 2])[0] if cur + 2 <= len(data) else 0
                    cur += 2
                    s = data[cur : cur + u16len * 2].decode("utf-16le", errors="replace")
                strings.append(s)
            break
        if chunk_size <= 0:
            break
        pos += chunk_size

    return strings


def parse_dex_header_and_strings(dex_bytes: bytes) -> tuple[list[str], list[str]]:
    """Parse string pool and class definitions from DEX bytecode header."""
    if len(dex_bytes) < 112 or not dex_bytes.startswith(b"dex\n"):
        return [], []

    string_ids_size, string_ids_off = struct.unpack("<II", dex_bytes[56:64])
    type_ids_size, type_ids_off = struct.unpack("<II", dex_bytes[64:72])
    class_defs_size, class_defs_off = struct.unpack("<II", dex_bytes[96:104])

    # 1. Parse string offsets
    strings: list[str] = []
    for i in range(min(string_ids_size, 50000)):
        off_pos = string_ids_off + i * 4
        if off_pos + 4 > len(dex_bytes):
            break
        data_off = struct.unpack("<I", dex_bytes[off_pos : off_pos + 4])[0]
        if data_off >= len(dex_bytes):
            continue

        # Read MUTF-8 string (uleb128 len prefix)
        pos = data_off
        while pos < len(dex_bytes) and (dex_bytes[pos] & 0x80):
            pos += 1
        pos += 1  # skip last byte of uleb128

        end = pos
        while end < len(dex_bytes) and dex_bytes[end] != 0:
            end += 1
        strings.append(dex_bytes[pos:end].decode("utf-8", errors="replace"))

    # 2. Parse Class Descriptors
    classes: list[str] = []
    for i in range(min(class_defs_size, 20000)):
        pos = class_defs_off + i * 32
        if pos + 4 > len(dex_bytes):
            break
        class_idx = struct.unpack("<I", dex_bytes[pos : pos + 4])[0]
        if class_idx < type_ids_size:
            type_pos = type_ids_off + class_idx * 4
            if type_pos + 4 <= len(dex_bytes):
                desc_idx = struct.unpack("<I", dex_bytes[type_pos : type_pos + 4])[0]
                if desc_idx < len(strings):
                    classes.append(strings[desc_idx])

    return strings, classes


def inspect_apk(apk_path: Path | str, out_dir: Path | None = None) -> dict[str, Any]:
    """Inspect APK archive and extract metadata, manifest strings, and classes."""
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"APK file not found: {path}")

    with zipfile.ZipFile(path, "r") as zf:
        namelist = zf.namelist()

        manifest_strings = []
        if "AndroidManifest.xml" in namelist:
            manifest_strings = parse_axml_strings(zf.read("AndroidManifest.xml"))

        dex_strings = []
        classes = []
        dex_files = [n for n in namelist if n.endswith(".dex")]
        for dex_name in dex_files:
            s, c = parse_dex_header_and_strings(zf.read(dex_name))
            dex_strings.extend(s)
            classes.extend(c)

    # Filter interesting URLs, endpoints, and credentials from strings
    suspicious = set()
    for s in dex_strings + manifest_strings:
        if (
            re.match(r"^https?://", s, re.IGNORECASE)
            or any(kw in s.lower() for kw in ("api_key", "secret", "token", "password", "auth", "endpoint"))
        ) and 4 < len(s) < 200:
            suspicious.add(s)

    report: dict[str, Any] = {
        "apk_name": path.name,
        "size_bytes": path.stat().st_size,
        "dex_count": len(dex_files),
        "manifest_strings_count": len(manifest_strings),
        "total_classes": len(classes),
        "interesting_strings": sorted(list(suspicious))[:100],
        "sample_classes": [c for c in classes if not c.startswith(("Landroid/", "Landroidx/", "Ljava/"))][:40],
    }

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        report_file = out_dir / f"{path.stem}_inspection.json"
        report_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Saved report to {report_file}")

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Android APK and DEX Bytecode Inspector.")
    parser.add_argument("--apk", type=Path, required=True, help="Path to the target .apk file")
    parser.add_argument("--out-dir", type=Path, help="Directory to save report JSON")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        res = inspect_apk(args.apk, out_dir=args.out_dir)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(res, indent=2))
        return 0

    print(f"=== APK Inspection: {res['apk_name']} ===")
    print(f"Size: {res['size_bytes']:,} bytes | DEX files: {res['dex_count']}")
    print(f"Classes: {res['total_classes']} | Manifest Strings: {res['manifest_strings_count']}")
    if res["interesting_strings"]:
        print(f"\n[+] Interesting Strings / Endpoints ({len(res['interesting_strings'])}):")
        for s in res["interesting_strings"][:20]:
            print(f"  - {s}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
