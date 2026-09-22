#!/usr/bin/env python3
"""Local pre-deploy security checks for web application source trees."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlsplit


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "node_modules",
    "output",
    "vendor",
    "venv",
}
BUILD_DIRS = ("dist", "build", ".next", "out")
EXAMPLE_ENV_NAMES = {".env.example", ".env.sample", ".env.template"}
TEXT_LIMIT = 2 * 1024 * 1024

SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:APP_KEY|API_KEY|AUTH_KEY|COOKIE_SECRET|ENCRYPTION_KEY|JWT|PASSWORD|PASS|"
    r"PRIVATE_KEY|SECRET|SESSION_KEY|SIGNING_KEY|TOKEN|DATABASE_URL|DB_URL|REDIS_URL|"
    r"MONGO_URL|MONGODB_URI|MYSQL_URL|POSTGRES_URL)(?:$|_)",
    re.IGNORECASE,
)
SECRET_URL_KEY_RE = re.compile(
    r"(?:DATABASE|DB|REDIS|MONGO|MYSQL|POSTGRES).*(?:URL|URI)", re.IGNORECASE
)
ADMIN_USER_RE = re.compile(r"ADMIN.*(?:USER|LOGIN)|(?:USER|LOGIN).*ADMIN", re.IGNORECASE)
ADMIN_PASSWORD_RE = re.compile(r"ADMIN.*(?:PASS|PASSWORD)|(?:PASS|PASSWORD).*ADMIN", re.IGNORECASE)
ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
PLACEHOLDER_MARKERS = (
    "changeme",
    "change-me",
    "default",
    "example",
    "insert",
    "placeholder",
    "replace",
    "sample",
    "todo",
    "your-secret",
    "your_secret",
)
COMMON_PASSWORDS = {
    "123456",
    "admin",
    "admin123",
    "changeme",
    "password",
    "password1",
    "qwerty",
    "root",
    "secret",
    "superadmin",
}
SOURCE_EXTENSIONS = {
    ".cshtml",
    ".ejs",
    ".erb",
    ".hbs",
    ".html",
    ".htm",
    ".js",
    ".jsx",
    ".php",
    ".svelte",
    ".ts",
    ".tsx",
    ".twig",
    ".vue",
}
CONFIG_EXTENSIONS = SOURCE_EXTENSIONS | {".json", ".py", ".rb", ".sql", ".yaml", ".yml"}

XSS_PATTERNS = (
    ("react-dangerous-html", re.compile(r"\bdangerouslySetInnerHTML\b"), "React raw HTML sink"),
    ("dom-inner-html", re.compile(r"\.innerHTML\s*="), "DOM innerHTML assignment"),
    ("vue-v-html", re.compile(r"\bv-html\s*="), "Vue raw HTML directive"),
    ("document-write", re.compile(r"\bdocument\.(?:write|writeln)\s*\("), "document.write sink"),
    ("angular-trust-html", re.compile(r"\bbypassSecurityTrustHtml\s*\("), "Angular sanitizer bypass"),
    ("dynamic-eval", re.compile(r"(?<![\w.])eval\s*\("), "dynamic code evaluation"),
    ("unescaped-template", re.compile(r"<%-|\{\{\{|\|\s*safe\b"), "unescaped template output"),
)

SOURCEMAP_CONFIG_PATTERNS = (
    (
        re.compile(
            r"\bsourcemap\s*:\s*(?:true\b|['\"](?:hidden|inline)['\"])",
            re.IGNORECASE,
        ),
        "enabled Vite/Rollup source map",
    ),
    (re.compile(r"['\"]?sourceMap['\"]?\s*:\s*true\b"), "sourceMap: true"),
    (re.compile(r"\bproductionBrowserSourceMaps\s*:\s*true\b"), "Next.js production source maps"),
    (re.compile(r"\bproductionSourceMap\s*:\s*true\b"), "Vue production source maps"),
    (
        re.compile(r"\bdevtool\s*:\s*['\"][^'\"\r\n]*source-map['\"]", re.IGNORECASE),
        "Webpack source-map devtool",
    ),
    (
        re.compile(r"^\s*GENERATE_SOURCEMAP\s*=\s*true\s*$", re.IGNORECASE | re.MULTILINE),
        "CRA source maps",
    ),
)


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def iter_files(root: Path, *, include_build: bool = True) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts[:-1]
        if any(part in SKIP_DIRS for part in relative_parts):
            continue
        if not include_build and any(part in BUILD_DIRS for part in relative_parts):
            continue
        yield path


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > TEXT_LIMIT:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def line_number(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def make_finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    details: str,
    *,
    path: str | None = None,
    line: int | None = None,
    confidence: str = "high",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "details": details,
        "confidence": confidence,
    }
    if path is not None:
        finding["path"] = path
    if line is not None:
        finding["line"] = line
    if evidence:
        finding["evidence"] = evidence
    return finding


def clean_env_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    elif " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def parse_env(text: str) -> dict[str, tuple[str, int]]:
    values: dict[str, tuple[str, int]] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ENV_LINE_RE.match(stripped)
        if match:
            values[match.group(1)] = (clean_env_value(match.group(2)), number)
    return values


def is_runtime_reference(value: str) -> bool:
    return bool(
        re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", value)
        or re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", value)
    )


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower().strip()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if lowered in COMMON_PASSWORDS or compact in COMMON_PASSWORDS:
        return True
    if lowered and set(lowered) <= {"x", "*", "-", "_"}:
        return True
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def estimated_entropy_bits(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    entropy_per_character = -sum(
        (count / len(value)) * math.log2(count / len(value)) for count in counts.values()
    )
    return entropy_per_character * len(value)


def secret_weaknesses(value: str) -> list[str]:
    reasons: list[str] = []
    if not value:
        return ["empty"]
    if looks_like_placeholder(value):
        reasons.append("known placeholder or default")
    if len(value) < 32:
        reasons.append("shorter than 32 characters")
    if len(set(value)) < min(8, max(4, len(value) // 4)):
        reasons.append("low character diversity")
    repeated = len(value) >= 8 and any(
        len(value) % period == 0 and value == value[:period] * (len(value) // period)
        for period in range(1, min(16, len(value) // 2) + 1)
    )
    adjacent_steps = sum(
        abs(ord(right.lower()) - ord(left.lower())) == 1
        for left, right in zip(value, value[1:])
        if left.isalnum() and right.isalnum()
    )
    sequential = len(value) >= 12 and adjacent_steps / max(1, len(value) - 1) >= 0.75
    compact = re.sub(r"[^a-z0-9]", "", value.lower())
    keyboard_sequences = (
        "0123456789" * 4,
        "9876543210" * 4,
        "abcdefghijklmnopqrstuvwxyz" * 2,
        "zyxwvutsrqponmlkjihgfedcba" * 2,
        "qwertyuiopasdfghjklzxcvbnm" * 2,
    )
    known_sequence = len(compact) >= 8 and any(compact in sequence for sequence in keyboard_sequences)
    if repeated or sequential or known_sequence:
        reasons.append("repeating or predictable pattern")
    if len(value) >= 32 and estimated_entropy_bits(value) < 100:
        reasons.append("low estimated entropy")
    return reasons


def secret_url_component(key: str, value: str) -> tuple[str, str] | None:
    if not SECRET_URL_KEY_RE.search(key):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.password is not None:
        return unquote(parsed.password), "URL password"
    for query_key, query_value in parse_qsl(parsed.query, keep_blank_values=True):
        if SECRET_KEY_RE.search(query_key) and query_value:
            return unquote(query_value), "URL query credential"
    return None


def env_files(root: Path) -> list[Path]:
    files = []
    for path in iter_files(root):
        name = path.name.lower()
        if (name == ".env" or name.startswith(".env.")) and name not in EXAMPLE_ENV_NAMES:
            files.append(path)
    return sorted(files)


def example_env_values(root: Path) -> dict[str, str]:
    examples: dict[str, str] = {}
    for path in iter_files(root):
        if path.name.lower() not in EXAMPLE_ENV_NAMES:
            continue
        text = read_text(path)
        if text is None:
            continue
        for key, (value, _) in parse_env(text).items():
            if value:
                examples[key] = value
    return examples


def audit_env_secrets(root: Path) -> tuple[list[dict[str, Any]], list[tuple[Path, dict[str, tuple[str, int]]]]]:
    findings: list[dict[str, Any]] = []
    parsed_files: list[tuple[Path, dict[str, tuple[str, int]]]] = []
    examples = example_env_values(root)

    for path in env_files(root):
        text = read_text(path)
        if text is None:
            continue
        values = parse_env(text)
        parsed_files.append((path, values))
        for key, (value, number) in values.items():
            if not SECRET_KEY_RE.search(key) or is_runtime_reference(value):
                continue
            location = relative_path(path, root)
            url_component = secret_url_component(key, value)
            checked_value, component = url_component or (value, None)
            evidence = {"key": key, "length": len(checked_value)}
            if component:
                evidence["component"] = component
            if value and examples.get(key) == value:
                findings.append(
                    make_finding(
                        "ENV-EXAMPLE-VALUE",
                        "high",
                        "secrets",
                        "Deploy secret matches the example value",
                        "Generate a fresh per-environment value and rotate any deployed copy.",
                        path=location,
                        line=number,
                        evidence={**evidence, "reason": "matches example file"},
                    )
                )
            weaknesses = secret_weaknesses(checked_value)
            if weaknesses:
                findings.append(
                    make_finding(
                        "ENV-WEAK-SECRET",
                        "high",
                        "secrets",
                        "Deploy secret is weak or not randomized",
                        "Use a cryptographically random value of at least 32 characters and rotate it before deploy.",
                        path=location,
                        line=number,
                        evidence={**evidence, "reasons": weaknesses},
                    )
                )
    return findings, parsed_files


def password_classes(value: str) -> int:
    checks = (
        any(char.islower() for char in value),
        any(char.isupper() for char in value),
        any(char.isdigit() for char in value),
        any(not char.isalnum() for char in value),
    )
    return sum(checks)


def admin_password_weaknesses(username: str, password: str) -> list[str]:
    reasons: list[str] = []
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or looks_like_placeholder(password):
        reasons.append("common or default password")
    if username and lowered == username.lower():
        reasons.append("same as username")
    if len(password) < 12:
        reasons.append("shorter than 12 characters")
    if password_classes(password) < 3:
        reasons.append("insufficient character variety")
    return reasons


def audit_admin_env(
    root: Path, parsed_files: list[tuple[Path, dict[str, tuple[str, int]]]]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path, values in parsed_files:
        user_item = next(((key, item) for key, item in values.items() if ADMIN_USER_RE.search(key)), None)
        password_item = next(
            ((key, item) for key, item in values.items() if ADMIN_PASSWORD_RE.search(key)), None
        )
        if password_item is None:
            continue
        password_key, (password, number) = password_item
        if is_runtime_reference(password):
            continue
        username = user_item[1][0] if user_item else ""
        reasons = admin_password_weaknesses(username, password)
        if reasons:
            findings.append(
                make_finding(
                    "ADMIN-WEAK-CREDENTIAL",
                    "critical" if password.lower() in COMMON_PASSWORDS else "high",
                    "admin-auth",
                    "Admin credential is weak or uses a default",
                    "Replace the admin password before deploy and require MFA where supported.",
                    path=relative_path(path, root),
                    line=number,
                    evidence={"key": password_key, "length": len(password), "reasons": reasons},
                )
            )
    return findings


def audit_admin_source(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    credential_re = re.compile(
        r"(?i)['\"]?(?:admin[_-]?(?:password|pass)|(?:password|pass)[_-]?admin)['\"]?"
        r"\s*[:=]\s*(?:['\"](?P<quoted>[^'\"]+)['\"]|(?P<bare>[^\s#,\]}]+))"
    )
    admin_user_re = re.compile(
        r"(?i)['\"]?(?:admin[_-]?(?:username|user)|(?:username|user))['\"]?"
        r"\s*[:=]\s*['\"]?(admin|root|superadmin)['\"]?"
    )
    password_re = re.compile(
        r"(?i)['\"]?(?:password|pass|pwd)['\"]?\s*[:=]\s*"
        r"(?:['\"](?P<quoted>[^'\"]+)['\"]|(?P<bare>[^\s#,\]}]+))"
    )

    def assigned_value(match: re.Match[str]) -> str:
        return match.group("quoted") or match.group("bare")

    for path in iter_files(root, include_build=False):
        if path.suffix.lower() not in CONFIG_EXTENSIONS or path.name.startswith(".env"):
            continue
        text = read_text(path)
        if text is None:
            continue
        candidates: list[tuple[str, int, str]] = [
            (assigned_value(match), match.start(), "admin password")
            for match in credential_re.finditer(text)
        ]
        for user_match in admin_user_re.finditer(text):
            window_start = max(0, user_match.start() - 300)
            window_end = min(len(text), user_match.end() + 300)
            for password_match in password_re.finditer(text, window_start, window_end):
                candidates.append(
                    (
                        assigned_value(password_match),
                        password_match.start(),
                        "password near admin user",
                    )
                )

        for password, position, field in candidates:
            finding_key = (relative_path(path, root), position)
            if finding_key in seen:
                continue
            seen.add(finding_key)
            if is_runtime_reference(password):
                continue
            reasons = admin_password_weaknesses("admin", password)
            if not reasons:
                continue
            findings.append(
                make_finding(
                    "ADMIN-WEAK-CREDENTIAL",
                    "critical" if password.lower() in COMMON_PASSWORDS else "high",
                    "admin-auth",
                    "Hardcoded admin credential is weak or uses a default",
                    "Remove the plaintext credential, rotate it, and provision the admin through a secret store.",
                    path=relative_path(path, root),
                    line=line_number(text, position),
                    evidence={"field": field, "length": len(password), "reasons": reasons},
                )
            )
    return findings


def frontend_packages(root: Path) -> list[tuple[Path, str]]:
    packages: list[tuple[Path, str]] = []
    for path in iter_files(root):
        if path.name != "package.json":
            continue
        text = read_text(path)
        if text is None:
            continue
        try:
            package = json.loads(text)
        except json.JSONDecodeError:
            continue
        scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        build_command = scripts.get("build", "") if isinstance(scripts, dict) else ""
        if isinstance(build_command, str) and build_command.strip():
            packages.append((path.parent, build_command))
    return packages


def contains_build_artifact(output: Path) -> bool:
    ignored_names = {".ds_store", ".gitkeep", ".keep"}
    return any(
        path.is_file() and path.name.lower() not in ignored_names
        for path in output.rglob("*")
    )


def audit_frontend_build(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for package_root, _ in frontend_packages(root):
        outputs = [
            package_root / name
            for name in BUILD_DIRS
            if (package_root / name).is_dir() and contains_build_artifact(package_root / name)
        ]
        package_path = relative_path(package_root / "package.json", root)
        if not outputs:
            findings.append(
                make_finding(
                    "FE-BUILD-MISSING",
                    "medium",
                    "frontend-build",
                    "Frontend production build output was not found",
                    "Run the production build and audit the generated artifacts before deploy.",
                    path=package_path,
                    confidence="review-required",
                )
            )
            continue

        for output in outputs:
            for map_path in output.rglob("*.map"):
                if map_path.is_file():
                    findings.append(
                        make_finding(
                            "FE-SOURCEMAP-FILE",
                            "high",
                            "frontend-build",
                            "Production source map artifact is present",
                            "Disable production source maps and remove map files from the deploy artifact.",
                            path=relative_path(map_path, root),
                        )
                    )
            for asset in output.rglob("*"):
                if not asset.is_file() or asset.suffix.lower() not in {".js", ".css"}:
                    continue
                text = read_text(asset)
                if text is None:
                    continue
                match = re.search(r"(?:#|@)\s*sourceMappingURL\s*=", text)
                if match:
                    findings.append(
                        make_finding(
                            "FE-SOURCEMAP-REFERENCE",
                            "high",
                            "frontend-build",
                            "Built asset references a source map",
                            "Rebuild with production source maps disabled and remove the reference.",
                            path=relative_path(asset, root),
                            line=line_number(text, match.start()),
                        )
                    )
    return findings


def is_sourcemap_config(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env"):
        return name in {".env", ".env.prod", ".env.production"} or name.startswith(
            (".env.prod.", ".env.production.")
        )
    return bool(
        name.startswith(("vite.config.", "webpack.config.", "next.config.", "vue.config."))
        or name == "angular.json"
    )


def sourcemap_value_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "false", "none", "off"}
    if isinstance(value, dict):
        return any(sourcemap_value_enabled(item) for item in value.values())
    if isinstance(value, list):
        return any(sourcemap_value_enabled(item) for item in value)
    return False


def angular_has_production_sourcemap(config: Any) -> bool:
    if not isinstance(config, dict) or not isinstance(config.get("projects"), dict):
        return False
    for project in config["projects"].values():
        if not isinstance(project, dict):
            continue
        targets = project.get("architect") or project.get("targets") or {}
        if not isinstance(targets, dict) or not isinstance(targets.get("build"), dict):
            continue
        build = targets["build"]
        options = build.get("options", {})
        configurations = build.get("configurations", {})
        production = configurations.get("production", {}) if isinstance(configurations, dict) else {}
        if isinstance(production, dict) and "sourceMap" in production:
            if sourcemap_value_enabled(production["sourceMap"]):
                return True
            continue
        if isinstance(options, dict) and "sourceMap" in options:
            if sourcemap_value_enabled(options["sourceMap"]):
                return True
    return False


def audit_sourcemap_config(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in iter_files(root, include_build=False):
        if not is_sourcemap_config(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        if path.name.lower() == "angular.json":
            try:
                angular_config = json.loads(text)
            except json.JSONDecodeError:
                continue
            if angular_has_production_sourcemap(angular_config):
                match = re.search(r"['\"]sourceMap['\"]", text, re.IGNORECASE)
                findings.append(
                    make_finding(
                        "FE-SOURCEMAP-ENABLED",
                        "high",
                        "frontend-build",
                        "Production source maps are enabled in configuration",
                        "Disable production source maps and rebuild before deploy.",
                        path=relative_path(path, root),
                        line=line_number(text, match.start()) if match else 1,
                        evidence={"setting": "Angular production sourceMap"},
                    )
                )
            continue
        for pattern, label in SOURCEMAP_CONFIG_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    make_finding(
                        "FE-SOURCEMAP-ENABLED",
                        "high",
                        "frontend-build",
                        "Production source maps are enabled in configuration",
                        "Disable production source maps and rebuild before deploy.",
                        path=relative_path(path, root),
                        line=line_number(text, match.start()),
                        evidence={"setting": label},
                    )
                )
    return findings


def audit_xss_sinks(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in iter_files(root, include_build=False):
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        text = read_text(path)
        if text is None:
            continue
        for sink_id, pattern, label in XSS_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    make_finding(
                        "XSS-STATIC-SINK",
                        "medium",
                        "xss",
                        "Potential client-side XSS sink requires review",
                        "Trace whether untrusted input reaches this sink and apply contextual encoding or sanitization.",
                        path=relative_path(path, root),
                        line=line_number(text, match.start()),
                        confidence="review-required",
                        evidence={"sink": label, "rule": sink_id},
                    )
                )
    return findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        summary[finding["severity"]] += 1
    summary["total"] = len(findings)
    return summary


def audit_project(project: Path) -> dict[str, Any]:
    root = project.resolve()
    if not root.is_dir():
        raise ValueError(f"Project directory does not exist: {project}")

    env_findings, parsed_env_files = audit_env_secrets(root)
    findings = env_findings
    findings.extend(audit_admin_env(root, parsed_env_files))
    findings.extend(audit_admin_source(root))
    findings.extend(audit_frontend_build(root))
    findings.extend(audit_sourcemap_config(root))
    findings.extend(audit_xss_sinks(root))
    findings.sort(
        key=lambda item: (
            -SEVERITY_RANK[item["severity"]],
            item["category"],
            item.get("path", ""),
            item.get("line", 0),
            item["id"],
        )
    )
    return {"project": str(root), "summary": summarize(findings), "findings": findings}


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Pre-deploy Security Audit",
        "",
        f"Project: `{report['project']}`",
        "",
        (
            "Summary: "
            f"{summary['critical']} critical, {summary['high']} high, "
            f"{summary['medium']} medium, {summary['low']} low, {summary['info']} info."
        ),
        "",
    ]
    if not report["findings"]:
        lines.extend(["No findings detected by the configured checks.", ""])
        return "\n".join(lines)

    current_severity = None
    for finding in report["findings"]:
        severity = finding["severity"]
        if severity != current_severity:
            lines.extend([f"## {severity.title()}", ""])
            current_severity = severity
        location = finding.get("path", "project")
        if "line" in finding:
            location += f":{finding['line']}"
        lines.extend(
            [
                f"### [{finding['id']}] {finding['title']}",
                "",
                f"- Category: `{finding['category']}`",
                f"- Location: `{location}`",
                f"- Confidence: `{finding['confidence']}`",
                f"- Remediation: {finding['details']}",
                "",
            ]
        )
    return "\n".join(lines)


def write_reports(report: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "findings.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output / "FINDINGS.md").write_text(markdown_report(report), encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit local web source and build artifacts before deployment."
    )
    parser.add_argument("project", nargs="?", default=".", help="Project directory to audit")
    parser.add_argument("--out", default="output/deploy-audit", help="Report output directory")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Return exit code 1 when a finding meets this severity",
    )
    parser.add_argument("--check", action="store_true", help="Check that the audit tool can run")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.check:
        print("deploy_audit: ready (Python standard library only)")
        return 0

    try:
        report = audit_project(Path(args.project))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output = Path(args.out)
    write_reports(report, output)
    summary = report["summary"]
    print(
        f"Wrote {output / 'FINDINGS.md'} and {output / 'findings.json'} "
        f"({summary['total']} findings)."
    )

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[item["severity"]] >= threshold for item in report["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
