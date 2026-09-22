#!/usr/bin/env python3
"""Reusable fast multi-threaded TCP Port Scanner.

Standard library only (socket + concurrent.futures). Supports port ranges and lists.
No hardcoded hosts or IPs.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 1521, 2049, 2082, 2083, 2086, 2087, 3000, 3001, 3306,
    5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 27017,
]


def parse_port_specs(spec_str: str) -> list[int]:
    """Parse comma-separated port numbers and ranges (e.g. '80,443,8000-8080')."""
    ports: set[int] = set()
    for part in spec_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start, end = int(start_str.strip()), int(end_str.strip())
                for p in range(min(start, end), max(start, end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            else:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
        except ValueError:
            continue
    return sorted(ports)


def check_port(host: str, port: int, timeout: float = 0.5) -> int | None:
    """Attempt a TCP connection to host:port. Returns port if open, None otherwise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            res = sock.connect_ex((host, port))
            if res == 0:
                return port
    except Exception:
        pass
    return None


def scan_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 0.5,
    workers: int = 50,
) -> dict[str, Any]:
    """Scan a target host across a list of ports using a thread pool."""
    if not ports:
        ports = COMMON_PORTS

    t0 = time.time()
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as executor:
        future_map = {executor.submit(check_port, host, p, timeout): p for p in ports}
        for future in as_completed(future_map):
            port = future.result()
            if port is not None:
                open_ports.append(port)

    elapsed = time.time() - t0
    return {
        "host": host,
        "scanned_count": len(ports),
        "open_ports": sorted(open_ports),
        "elapsed_seconds": round(elapsed, 2),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fast multi-threaded TCP Port Scanner.")
    parser.add_argument("--host", required=True, help="Target hostname or IP address")
    parser.add_argument(
        "--ports",
        help="Ports to scan (e.g. '80,443,8000-8080'). Defaults to top common ports.",
    )
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--workers", type=int, default=50, help="Number of concurrent worker threads (default: 50)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ports = parse_port_specs(args.ports) if args.ports else COMMON_PORTS

    print(f"[*] Scanning {args.host} ({len(ports)} ports, {args.workers} workers, timeout {args.timeout}s)...")
    res = scan_ports(args.host, ports=ports, timeout=args.timeout, workers=args.workers)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[*] Scan complete in {res['elapsed_seconds']}s.")
        if res["open_ports"]:
            print(f"[+] Open Ports ({len(res['open_ports'])}):")
            for p in res["open_ports"]:
                print(f"  - Port {p}/TCP open")
        else:
            print("[-] No open ports found.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
