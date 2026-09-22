# Reusable Python Security & Reconnaissance Codebase

This directory provides a modular, reusable Python security and web reconnaissance toolkit, along with a catalog of verified utilities.

- **Zero hardcoded paths or targets**: All tools accept target URLs, hosts, ports, and file paths via CLI arguments (`argparse`) or clean function parameters.
- **Pure Python standard library**: Designed to run anywhere with Python 3.9+ without external dependency friction.

---

## 1. Quick CLI Usage

You can run individual modules directly or use the unified runner `cli.py`:

```powershell
# Show all available subcommands
python web-app-scanner\python-library\cli.py --help

# Audit security headers and TLS for an authorized target
python web-app-scanner\python-library\cli.py headers --url https://example.com --json

# Analyze JavaScript bundle for API endpoints, secrets, and Telegram tokens
python web-app-scanner\python-library\cli.py bundle --url https://example.com/assets/app.js

# Inspect and unpack JavaScript source map
python web-app-scanner\python-library\cli.py sourcemap --url https://example.com/assets/app.js.map --out-dir unpacked_src/

# Fast multi-threaded TCP port scanner
python web-app-scanner\python-library\cli.py ports --host 192.168.1.1 --ports 80,443,8000-8080 --workers 50

# Unified web audit (headers, script discovery, sourcemap probing, bundle analysis)
python web-app-scanner\python-library\cli.py audit --url https://example.com --out-dir output/audit

# Public API contract and endpoint health auditor
python web-app-scanner\python-library\cli.py contract --base-url https://api.example.com

# Extract strings from binary files or libraries
python web-app-scanner\python-library\cli.py strings --file binary.so --filter api,key,token

# Inspect Android APK / DEX strings and manifest
python web-app-scanner\python-library\cli.py apk --apk app.apk --out-dir output/apk_report
```

---

## 2. Python Import Usage

All tools are modular and can be imported into your custom scripts:

```python
from bundle_analyzer import analyze_bundle_content
from security_headers import audit_security_headers
from port_scanner import scan_ports
from sourcemap_extractor import parse_sourcemap_data, unpack_sources

# Check headers
headers_report = audit_security_headers("https://example.com")

# Scan ports
open_ports = scan_ports("127.0.0.1", ports=[80, 443, 8080])

# Analyze JS bundle
findings = analyze_bundle_content(js_code_string)
```

---

## 3. Historical Archive & Discovery (`index.json` & `files/`)

The archive under `files/` contains historical task scripts that have been sanitized:
- All developer-specific absolute paths (`C:\...`, `/opt/...`) and specific target URLs/IPs have been replaced with CLI arguments and parameters.
- Search catalog entries:
  ```powershell
  python web-app-scanner\scripts\brain_python_library.py search "bundle"
  python web-app-scanner\scripts\brain_python_library.py search "port" --json
  ```
- Validate archive integrity and checksums:
  ```powershell
  python web-app-scanner\scripts\brain_python_library.py verify
  ```
