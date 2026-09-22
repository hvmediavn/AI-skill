#!/usr/bin/env python3
"""Build and search a local library of reusable Antigravity Python scripts."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable


DEFAULT_BRAIN = Path.home() / ".gemini" / "antigravity" / "brain"
DEFAULT_LIBRARY = Path(__file__).resolve().parents[1] / "python-library"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {
    ".git",
    ".system_generated",
    ".user_uploaded",
    ".venv",
    "__pycache__",
    "node_modules",
    "site-packages",
    "venv",
}

CATEGORY_PATTERNS = {
    "xss": (
        "xss",
        "innerhtml",
        "dangerouslysetinnerhtml",
        "document.write",
        "unescaped",
        "sanitize_html",
    ),
    "source-map": ("sourcemap", "source_map", "source map", ".map"),
    "env-secrets": (".env", "dotenv", "redact_env", "secret", "api_key", "token"),
    "admin-auth": ("admin", "authentication", "authorize", "credential", "login"),
    "web-recon": ("web_recon", "passive_audit", "security_header", "cors", "tls"),
    "endpoint-discovery": ("endpoint", "crawl", "route", "urlparse", "urljoin"),
    "build-deploy": ("build", "deploy", "bundle", "package", "artifact"),
    "reporting": ("report", "finding", "markdown", "write_text"),
    "database": ("database", "sqlite", "prisma", "sqlalchemy", "cursor.execute"),
}

CATEGORY_DESCRIPTIONS = {
    "xss": "XSS sink or output-escaping analysis",
    "source-map": "JavaScript source-map inspection",
    "env-secrets": "environment and secret-handling checks",
    "admin-auth": "admin authentication or credential checks",
    "web-recon": "web security reconnaissance",
    "endpoint-discovery": "application endpoint discovery",
    "build-deploy": "build or deployment automation",
    "reporting": "audit report generation",
    "database": "database inspection or migration work",
}

NETWORK_CALLS = {
    "http.client.httpconnection",
    "http.client.httpsconnection",
    "httpx.get",
    "httpx.post",
    "requests.delete",
    "requests.get",
    "requests.head",
    "requests.patch",
    "requests.post",
    "requests.put",
    "socket.create_connection",
    "urllib.request.urlopen",
    "urlopen",
}
NETWORK_MODULES = {
    "aiohttp",
    "asyncio",
    "ftplib",
    "http.client",
    "httpx",
    "paramiko",
    "playwright",
    "requests",
    "selenium",
    "smtplib",
    "socket",
    "urllib.request",
}
NETWORK_METHODS = {
    "connect",
    "connect_ex",
    "delete",
    "get",
    "goto",
    "head",
    "open",
    "open_connection",
    "patch",
    "post",
    "put",
    "recv",
    "request",
    "send",
    "sendall",
    "urlopen",
}
DESTRUCTIVE_CALLS = {
    "os.remove",
    "os.rmdir",
    "os.system",
    "pathlib.path.rmdir",
    "pathlib.path.unlink",
    "shutil.rmtree",
}
DESTRUCTIVE_METHODS = {"remove", "rmdir", "rmtree", "unlink"}
DESTRUCTIVE_MODULES = {"os", "pathlib", "shutil"}
SUBPROCESS_CALLS = {
    "os.popen",
    "os.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.popen",
    "subprocess.run",
}
WRITE_CALLS = {
    "json.dump",
    "pathlib.path.write_bytes",
    "pathlib.path.write_text",
    "write_bytes",
    "write_text",
}
SENSITIVE_NAME_RE = re.compile(
    r"(?:^|_)(?:access_token|admin_password|api_key|auth_token|authorization|client_secret|"
    r"cookie|credential|database_url|db_url|password|passwd|private_key|refresh_token|"
    r"secret|session_id|token|x_admin_password|x_api_key)(?:$|_)",
    re.IGNORECASE,
)
PATTERN_NAME_RE = re.compile(
    r"(?:_re|_regex|_pattern|_patterns|_marker|_markers|_keyword|_keywords|_field|_fields|_name|_names)$",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
URI_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
CREDENTIAL_URI_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@")
TOKEN_VALUE_RES = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
)
GENERATED_SECRET_RE = re.compile(
    r"(?is)(?:api[_-]?key|authorization|client[_-]?secret|jwt[_-]?secret|password|"
    r"private[_-]?key|refresh[_-]?token)\b.{0,80}?(?:=|:|\|\|)\s*['\"][^'\"\r\n]{4,}"
)
SAFE_IMPORT_CALLS = {
    "argparse.argumentparser",
    "collections.counter",
    "collections.defaultdict",
    "collections.deque",
    "dataclasses.dataclass",
    "dict",
    "frozenset",
    "functools.lru_cache",
    "json.dumps",
    "json.loads",
    "list",
    "logging.getlogger",
    "os.getenv",
    "os.path.abspath",
    "os.path.basename",
    "os.path.dirname",
    "os.path.join",
    "pathlib.path",
    "pathlib.path.cwd",
    "pathlib.path.home",
    "pathlib.purepath",
    "pathlib.pureposixpath",
    "pathlib.purewindowspath",
    "re.compile",
    "re.escape",
    "set",
    "tuple",
    "typing.newtype",
    "typing.typevar",
}
SAFE_IMPORT_PREFIXES = ("math.", "operator.")


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def assigned_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in assigned_names(item)]
    return []


def is_main_guard(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    values = (test.left, test.comparators[0])
    return any(isinstance(value, ast.Name) and value.id == "__name__" for value in values) and any(
        isinstance(value, ast.Constant) and value.value == "__main__" for value in values
    )


class ImportTimeCallCollector(ast.NodeVisitor):
    """Collect calls evaluated while a module is imported."""

    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def _visit_function_header(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        annotations = [node.returns]
        annotations.extend(argument.annotation for argument in node.args.posonlyargs)
        annotations.extend(argument.annotation for argument in node.args.args)
        annotations.extend(argument.annotation for argument in node.args.kwonlyargs)
        if node.args.vararg:
            annotations.append(node.args.vararg.annotation)
        if node.args.kwarg:
            annotations.append(node.args.kwarg.annotation)
        for annotation in annotations:
            if annotation is not None:
                self.visit(annotation)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_header(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for statement in node.body:
            self.visit(statement)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        if is_main_guard(node):
            for statement in node.orelse:
                self.visit(statement)
            return
        for statement in (*node.body, *node.orelse):
            self.visit(statement)


def string_literals(tree: ast.AST) -> list[str]:
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def normalize_identifier(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def static_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value.decode("utf-8", errors="replace")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = static_string(node.left)
        right = static_string(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        return "".join(parts)
    return None


def has_sensitive_literal(tree: ast.AST, source: str) -> bool:
    literals = string_literals(tree)
    static_values = [value for node in ast.walk(tree) if (value := static_string(node)) is not None]
    if (
        PRIVATE_KEY_RE.search(source)
        or any(pattern.search(source) for pattern in TOKEN_VALUE_RES)
        or any(CREDENTIAL_URI_RE.search(value) for value in static_values)
        or any(GENERATED_SECRET_RE.search(value) for value in literals)
    ):
        return True

    for node in ast.walk(tree):
        pairs: list[tuple[str, ast.AST]] = []
        if isinstance(node, ast.Assign):
            for target in node.targets:
                pairs.extend((name, node.value) for name in assigned_names(target))
        elif isinstance(node, ast.AnnAssign):
            pairs.extend((name, node.value) for name in assigned_names(node.target) if node.value)
        elif isinstance(node, ast.NamedExpr):
            pairs.extend((name, node.value) for name in assigned_names(node.target))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    pairs.append((key.value, value))
        elif isinstance(node, ast.Call):
            pairs.extend((keyword.arg or "", keyword.value) for keyword in node.keywords)

        for name, value_node in pairs:
            normalized_name = normalize_identifier(name)
            if PATTERN_NAME_RE.search(normalized_name) or not SENSITIVE_NAME_RE.search(
                normalized_name
            ):
                continue
            value = static_string(value_node)
            if value is not None:
                value = value.strip()
                if value and not value.startswith(("${", "$", "<", "{{")):
                    return True
    return False


def import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def resolved_call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    name = dotted_name(node.func)
    if not name:
        return ""
    first, separator, remainder = name.partition(".")
    resolved = aliases.get(first, first)
    return f"{resolved}.{remainder}".lower() if separator else resolved.lower()


def collect_calls(nodes: Iterable[ast.Call], aliases: dict[str, str]) -> set[str]:
    return {name for node in nodes if (name := resolved_call_name(node, aliases))}


def call_matches(calls: set[str], known: set[str]) -> bool:
    for call in calls:
        if call in known or any(call.endswith(f".{item}") for item in known):
            return True
    return False


def imported_family(imports: Iterable[str], families: set[str]) -> bool:
    return any(
        imported == family or imported.startswith(f"{family}.")
        for imported in imports
        for family in families
    )


def has_network_call(calls: set[str], imports: Iterable[str]) -> bool:
    if call_matches(calls, NETWORK_CALLS):
        return True
    return imported_family(imports, NETWORK_MODULES) and any(
        call.rsplit(".", 1)[-1] in NETWORK_METHODS for call in calls
    )


def has_destructive_call(calls: set[str], imports: Iterable[str]) -> bool:
    if call_matches(calls, DESTRUCTIVE_CALLS):
        return True
    return imported_family(imports, DESTRUCTIVE_MODULES) and any(
        call.rsplit(".", 1)[-1] in DESTRUCTIVE_METHODS for call in calls
    )


def open_mode(call: ast.Call) -> str | None:
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        return call.args[1].value if isinstance(call.args[1].value, str) else None
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value if isinstance(keyword.value.value, str) else None
    return None


def has_file_write(calls: set[str], call_nodes: Iterable[ast.Call], aliases: dict[str, str]) -> bool:
    if call_matches(calls, WRITE_CALLS):
        return True
    for call in call_nodes:
        if resolved_call_name(call, aliases).rsplit(".", 1)[-1] != "open":
            continue
        mode = open_mode(call)
        if mode and any(marker in mode for marker in ("w", "a", "x", "+")):
            return True
    return False


def has_unresolved_import_call(calls: set[str]) -> bool:
    return any(
        call not in SAFE_IMPORT_CALLS
        and not any(call.startswith(prefix) for prefix in SAFE_IMPORT_PREFIXES)
        for call in calls
    )


def classify_categories(path: Path, source: str, imports: list[str], functions: list[str]) -> list[str]:
    haystack = " ".join(
        [path.name.lower(), source.lower(), *[name.lower() for name in imports + functions]]
    )
    return [
        category
        for category, patterns in CATEGORY_PATTERNS.items()
        if any(pattern in haystack for pattern in patterns)
    ]


def describe(categories: list[str], functions: list[str], classes: list[str]) -> str:
    if categories:
        purposes = [CATEGORY_DESCRIPTIONS[item] for item in categories[:3]]
        if len(purposes) == 1:
            purpose = purposes[0]
        else:
            purpose = ", ".join(purposes[:-1]) + f", and {purposes[-1]}"
        description = f"Python utility for {purpose}."
    else:
        description = "General Python utility retained for possible reuse."

    symbols = functions[:3] + classes[:2]
    if symbols:
        description += f" Main symbols: {', '.join(symbols)}."
    return description


def source_sha256(raw_source: bytes) -> str:
    return hashlib.sha256(raw_source.replace(b"\r\n", b"\n")).hexdigest()


def analyze_file(path: Path, root: Path) -> tuple[dict[str, Any], str | None]:
    relative = path.relative_to(root).as_posix()
    size = path.stat().st_size
    base: dict[str, Any] = {
        "id": hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16],
        "name": path.name,
        "source_relpath": relative,
        "size_bytes": size,
    }
    if size > MAX_SOURCE_BYTES:
        return {
            **base,
            "description": "Python file exceeds the safe indexing size limit.",
            "categories": [],
            "imports": [],
            "functions": [],
            "classes": [],
            "signals": {"syntax_valid": None, "oversized": True},
            "reuse_level": "do-not-run",
            "status": "blocked",
            "block_reasons": ["oversized"],
        }, None

    try:
        raw_source = path.read_bytes()
        source = raw_source.decode("utf-8", errors="replace")
    except OSError:
        return {
            **base,
            "description": "Python file could not be read.",
            "categories": [],
            "imports": [],
            "functions": [],
            "classes": [],
            "signals": {"syntax_valid": None},
            "reuse_level": "do-not-run",
            "status": "blocked",
            "block_reasons": ["unreadable"],
        }, None

    digest = source_sha256(raw_source)
    base.update({"sha256": digest, "line_count": len(source.splitlines())})
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source, filename=relative)
    except SyntaxError:
        return {
            **base,
            "description": "Python source has invalid syntax and requires manual recovery.",
            "categories": [],
            "imports": [],
            "functions": [],
            "classes": [],
            "signals": {"syntax_valid": False},
            "reuse_level": "do-not-run",
            "status": "blocked",
            "block_reasons": ["syntax-error"],
        }, source

    imports: set[str] = set()
    functions: list[str] = []
    classes: list[str] = []
    has_main = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.If) and is_main_guard(node):
            has_main = True

    aliases = import_aliases(tree)
    all_call_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    import_time_collector = ImportTimeCallCollector()
    import_time_collector.visit(tree)
    import_call_nodes = import_time_collector.calls
    all_calls = collect_calls(all_call_nodes, aliases)
    import_runtime_calls = collect_calls(import_call_nodes, aliases)
    literals = string_literals(tree)
    url_count = sum(len(URL_RE.findall(value)) for value in literals)
    absolute_path_count = sum(
        1 for value in literals if WINDOWS_PATH_RE.match(value) or value.startswith(("/home/", "/Users/"))
    )
    network_calls = has_network_call(all_calls, imports)
    top_level_network = has_network_call(import_runtime_calls, imports)
    destructive_calls = has_destructive_call(all_calls, imports)
    top_level_destructive = has_destructive_call(import_runtime_calls, imports)
    subprocess_calls = call_matches(all_calls, SUBPROCESS_CALLS)
    top_level_subprocess = call_matches(import_runtime_calls, SUBPROCESS_CALLS)
    file_writes = has_file_write(all_calls, all_call_nodes, aliases)
    top_level_file_write = has_file_write(import_runtime_calls, import_call_nodes, aliases)
    unresolved_import_call = has_unresolved_import_call(import_runtime_calls)
    secret_literal = has_sensitive_literal(tree, source)
    block_reasons = []
    if secret_literal:
        block_reasons.append("secret-literal")
    if top_level_network:
        block_reasons.append("top-level-network")
    if top_level_destructive:
        block_reasons.append("top-level-destructive")
    if top_level_file_write:
        block_reasons.append("top-level-file-write")
    if top_level_subprocess:
        block_reasons.append("top-level-subprocess")
    if unresolved_import_call:
        block_reasons.append("top-level-call")

    categories = classify_categories(path, source, sorted(imports), functions)
    if block_reasons:
        reuse_level = "do-not-run"
        status = "blocked"
    elif destructive_calls or network_calls or file_writes or subprocess_calls:
        reuse_level = "reference-only"
        status = "copied"
    elif url_count or absolute_path_count or subprocess_calls or not has_main:
        reuse_level = "adapt"
        status = "copied"
    else:
        reuse_level = "direct"
        status = "copied"

    entry: dict[str, Any] = {
        **base,
        "description": describe(categories, functions, classes),
        "categories": categories,
        "imports": sorted(imports),
        "functions": functions,
        "classes": classes,
        "signals": {
            "syntax_valid": True,
            "has_main_guard": has_main,
            "has_cli": "argparse" in imports,
            "url_literal_count": url_count,
            "absolute_path_literal_count": absolute_path_count,
            "network_calls": network_calls,
            "file_writes": file_writes,
            "subprocess_calls": subprocess_calls,
            "destructive_calls": destructive_calls,
            "import_time_calls": bool(import_runtime_calls),
        },
        "reuse_level": reuse_level,
        "status": status,
        "block_reasons": block_reasons,
    }
    return entry, source


def iter_python_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.py")):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts[:-1]
        if any(part in SKIP_DIRS for part in relative_parts):
            continue
        yield path


def reset_files_dir(library: Path) -> Path:
    resolved_library = library.resolve()
    files_dir = (resolved_library / "files").resolve()
    if files_dir.parent != resolved_library or files_dir.name != "files":
        raise ValueError("Refusing to reset an unsafe library files path")
    if files_dir.exists():
        shutil.rmtree(files_dir)
    files_dir.mkdir(parents=True)
    return files_dir


def sync_library(brain: Path, library: Path) -> dict[str, Any]:
    root = brain.resolve()
    if not root.is_dir():
        raise ValueError(f"Brain directory does not exist: {brain}")

    library = library.resolve()
    library.mkdir(parents=True, exist_ok=True)
    files_dir = reset_files_dir(library)
    entries: list[dict[str, Any]] = []
    for source_path in iter_python_files(root):
        entry, source = analyze_file(source_path, root)
        if entry["status"] == "copied" and source is not None:
            destination = files_dir / Path(entry["source_relpath"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)
            entry["library_path"] = destination.relative_to(library).as_posix()
        entries.append(entry)

    copied = sum(entry["status"] == "copied" for entry in entries)
    blocked = len(entries) - copied
    index = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "Antigravity brain Python archive",
        "safety": (
            "Files are statically parsed and never imported. Blocked files are metadata-only. "
            "The index never stores Python string literal values."
        ),
        "stats": {"scanned": len(entries), "copied": copied, "blocked": blocked},
        "entries": entries,
    }
    (library / "index.json").write_text(
        json.dumps(index, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )
    return index


def normalize_search_text(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def search_index(library: Path, query: str, status: str, limit: int) -> list[dict[str, Any]]:
    index_path = library / "index.json"
    if not index_path.is_file():
        raise ValueError(f"Library index does not exist: {index_path}")
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Library index is unreadable: {index_path}") from exc

    terms = normalize_search_text(query).split()
    if not terms:
        raise ValueError("Search query must contain at least one letter or number")
    matches: list[tuple[int, dict[str, Any]]] = []
    for entry in index.get("entries", []):
        if status != "all" and entry.get("status") != status:
            continue
        fields = [
            entry.get("name", ""),
            entry.get("source_relpath", ""),
            entry.get("description", ""),
            *entry.get("categories", []),
            *entry.get("imports", []),
            *entry.get("functions", []),
            *entry.get("classes", []),
        ]
        haystack = normalize_search_text(" ".join(fields))
        if not all(term in haystack for term in terms):
            continue
        score = sum(3 if term in normalize_search_text(entry.get("name", "")) else 1 for term in terms)
        matches.append((score, entry))

    matches.sort(key=lambda item: (-item[0], item[1].get("source_relpath", "")))
    return [entry for _, entry in matches[:limit]]


def verify_library(library: Path) -> tuple[int, int]:
    library = library.resolve()
    index_path = library / "index.json"
    if not index_path.is_file():
        raise ValueError(f"Library index does not exist: {index_path}")
    try:
        raw_index = index_path.read_text(encoding="utf-8")
        index = json.loads(raw_index)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Library index is unreadable: {index_path}") from exc

    if index.get("schema_version") != 1 or not isinstance(index.get("entries"), list):
        raise ValueError("Library index has an unsupported or invalid schema")
    def strings(value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield str(key)
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    for value in strings(index):
        if URI_RE.search(value) or PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
            raise ValueError("Library index contains a URI or absolute path")

    entries = index["entries"]
    ids = [entry.get("id") for entry in entries]
    source_paths = [entry.get("source_relpath") for entry in entries]
    if len(ids) != len(set(ids)) or len(source_paths) != len(set(source_paths)):
        raise ValueError("Library index contains duplicate ids or source paths")

    files_root = (library / "files").resolve()
    expected_files: set[Path] = set()
    copied = 0
    blocked = 0
    for entry in entries:
        source_relpath = entry.get("source_relpath", "")
        source_path = PurePosixPath(source_relpath)
        if (
            not source_relpath
            or source_path.is_absolute()
            or ".." in source_path.parts
            or "\\" in source_relpath
        ):
            raise ValueError(f"Invalid source_relpath: {source_relpath}")
        status = entry.get("status")
        if status == "blocked":
            blocked += 1
            if "library_path" in entry:
                raise ValueError(f"Blocked entry has a library path: {entry.get('source_relpath')}")
            continue
        if status != "copied" or not entry.get("library_path") or not entry.get("sha256"):
            raise ValueError(f"Invalid entry status or path: {entry.get('source_relpath')}")
        copied += 1
        path = (library / entry["library_path"]).resolve()
        if files_root not in path.parents or not path.is_file():
            raise ValueError(f"Copied file is missing or outside the archive: {entry['library_path']}")
        expected_files.add(path)
        digest = source_sha256(path.read_bytes())
        if digest != entry["sha256"]:
            raise ValueError(f"Checksum mismatch: {entry['library_path']}")

    actual_files = {path.resolve() for path in files_root.rglob("*.py") if path.is_file()}
    if actual_files != expected_files:
        raise ValueError("Archive file set does not match index.json")
    expected_stats = {"scanned": len(entries), "copied": copied, "blocked": blocked}
    if index.get("stats") != expected_stats:
        raise ValueError("Library index statistics do not match its entries")
    return copied, blocked


def print_search_results(entries: list[dict[str, Any]]) -> None:
    if not entries:
        print("No matching Python library entries.")
        return
    for entry in entries:
        location = entry.get("library_path", "metadata only")
        categories = ", ".join(entry.get("categories", [])) or "general"
        print(f"[{entry['reuse_level']}] {entry['name']} ({categories})")
        print(f"  {entry['description']}")
        print(f"  {location}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and search reusable Python scripts from Antigravity brain data."
    )
    parser.add_argument("--check", action="store_true", help="Check that the tool can run")
    subparsers = parser.add_subparsers(dest="command")

    sync_parser = subparsers.add_parser("sync", help="Build the in-project Python library")
    sync_parser.add_argument("brain", nargs="?", type=Path, default=DEFAULT_BRAIN)
    sync_parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)

    search_parser = subparsers.add_parser("search", help="Search the generated library index")
    search_parser.add_argument("query")
    search_parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    search_parser.add_argument("--status", choices=("copied", "blocked", "all"), default="copied")
    search_parser.add_argument("--limit", type=int, default=20)
    search_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    verify_parser = subparsers.add_parser("verify", help="Verify index schema and copied files")
    verify_parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.check:
        print("brain_python_library: ready (Python standard library only)")
        return 0

    try:
        if args.command == "sync":
            index = sync_library(args.brain, args.library)
            print(
                f"Wrote {args.library / 'index.json'}: {index['stats']['copied']} copied, "
                f"{index['stats']['blocked']} blocked."
            )
            return 0
        if args.command == "search":
            if args.limit < 1:
                raise ValueError("--limit must be at least 1")
            entries = search_index(args.library, args.query, args.status, args.limit)
            if args.json:
                print(json.dumps(entries, ensure_ascii=True, indent=2))
            else:
                print_search_results(entries)
            return 0
        if args.command == "verify":
            copied, blocked = verify_library(args.library)
            print(f"Library valid: {copied} copied files verified, {blocked} blocked entries.")
            return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
