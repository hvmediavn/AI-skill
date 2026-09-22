# Brain Python Library

The library keeps reusable Python generated during earlier Antigravity tasks inside this skill, so an agent can search existing work before creating another helper.

## Layout

```text
python-library/
  README.md
  index.json
  files/<session-id>/<original-relative-path>.py
```

`index.json` is the discovery interface. Do not recursively read every source file to find a candidate.

## Search workflow

1. Search with task terms and request JSON when another tool will consume the result:

   ```powershell
   python web-app-scanner\scripts\brain_python_library.py search "source map" --json
   ```

2. Prefer `direct`, then `adapt`. Treat `reference-only` as code to inspect and extract from, not a command to launch unchanged.
3. Open the selected `library_path` and review hardcoded paths, network destinations, write behavior, dependencies, and authorization requirements.
4. Do not request or recover blocked source through the catalog. Reimplement the needed idea without carrying unsafe values or import-time side effects forward.

Use `--status all` to include metadata-only blocked entries, `--status blocked` to audit exclusions, and `--limit N` to cap results.

After syncing or moving the skill, verify the complete archive:

```powershell
python web-app-scanner\scripts\brain_python_library.py verify
```

Verification checks the schema, unique IDs and source paths, statistics, copied file set, path containment, and every SHA-256 checksum. It also rejects URLs or absolute Windows paths in the database.

## Index schema

Each entry contains:

- `id`, `name`, `source_relpath`, `sha256`, `size_bytes`, and `line_count` for identity and provenance.
- `description` and `categories` for purpose-oriented search.
- `imports`, `functions`, and `classes` for structural discovery.
- `signals` for syntax, CLI/main guard, URL/path literals, networking, writes, subprocesses, and destructive calls.
- `reuse_level`, `status`, and `block_reasons` for handling guidance.
- `library_path` only when the file passed the copy gate.

The index does not store source snippets or Python string literal values. It intentionally omits the absolute source root so the archive remains portable.

## Sync safety

`sync` uses the standard-library AST parser and never imports or executes scanned modules. It skips generated-system, upload, cache, virtual-environment, dependency, and Git directories.

Files are not copied when they have invalid syntax, exceed the size limit, assign a static string to a likely credential/header field, embed a credential URI or generated-code secret fallback, or make a module-scope call outside a conservative pure-data allowlist. Import-time analysis includes aliases, decorators, function defaults, annotations, class bodies, local helpers, networking, file operations, subprocesses, and database calls. Blocked entries remain searchable as redacted metadata so the agent knows prior work existed without placing risky source in the reusable library.

`copied` means the file passed the import-safety and secret-copy gates. It does not authorize running its CLI or calling its functions; networking, write, subprocess, and destructive capabilities inside guarded functions are surfaced in `signals` and normally result in `reference-only`.
