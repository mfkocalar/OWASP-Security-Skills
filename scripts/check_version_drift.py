#!/usr/bin/env python3
"""Check that no version string in the repo disagrees with plugin.json's
canonical version (PKG-05 / D-04: plugin.json is the single canonical
version source).

Checks performed:
- `plugin.json`'s `version` field is read as the canonical value. If the
  file is missing or unparseable, a single failing DriftResult is emitted.
- `marketplace.json` must carry NO top-level `version` key and NO
  plugin-entry `version` key (plugin.json is authoritative). Absence
  passes; presence with a value that disagrees with canonical fails.
- A narrow, explicit set of scan targets (default: README.md) is searched
  ONLY for plugin-version-shaped references — a shields.io/badge
  `version-<x.y.z>` token, or a line explicitly labelled
  `version:`/`Version:` — and each match must equal canonical. This is
  intentionally NOT a blanket `\\d+\\.\\d+\\.\\d+` grep: OWASP edition
  numbers such as MASVS `2.1.0` or ASVS `5.0.0` are legitimate non-plugin
  version strings and must never be flagged as drift.

Design rules:
- Stdlib only (argparse, json, re, sys, pathlib, dataclasses). No PyYAML,
  no requests, matching this repo's "no heavy runtime dependencies"
  constraint.
- Each check is soft: append a pass/fail result, never raise, so one
  file's failure does not abort the run (mirrors lint_skill_md.py).
- Output is JSON to stdout by default; `--format text` prints a human
  summary instead.
- Exit code is 0 when every check passed, 1 when any check failed.

Usage:
    python3 scripts/check_version_drift.py
    python3 scripts/check_version_drift.py --format text
    python3 scripts/check_version_drift.py path/to/other-file.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLUGIN_JSON = REPO_ROOT / ".claude-plugin" / "plugin.json"
DEFAULT_MARKETPLACE_JSON = REPO_ROOT / ".claude-plugin" / "marketplace.json"
DEFAULT_SCAN_TARGETS = [REPO_ROOT / "README.md"]

# Narrow, explicit version-token matchers. Deliberately scoped so OWASP
# edition numbers (MASVS 2.1.0, ASVS 5.0.0) never match: neither pattern
# fires on a bare "vX.Y.Z" or "X.Y.Z" mention, only on a shields.io-style
# "version-X.Y.Z" badge segment or a line explicitly labelled Version:.
_VERSION = r"\d+\.\d+\.\d+"
BADGE_VERSION_RE = re.compile(r"version-(" + _VERSION + r")\b", re.IGNORECASE)
LABEL_VERSION_RE = re.compile(
    r"(?im)^\s*\**version\**\s*:\**\s*(" + _VERSION + r")\b"
)


@dataclass
class DriftResult:
    file: str
    check: str
    passed: bool
    message: str


def load_canonical_version(plugin_json_path: Path) -> tuple[str | None, DriftResult]:
    """Read plugin.json's version field as the canonical value."""
    file_str = str(plugin_json_path)
    try:
        raw = plugin_json_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, DriftResult(
            file_str, "plugin-json-readable", False,
            f"could not read plugin.json: {exc}",
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, DriftResult(
            file_str, "plugin-json-parseable", False,
            f"plugin.json is not valid JSON: {exc}",
        )

    version = data.get("version")
    if not version:
        return None, DriftResult(
            file_str, "plugin-json-has-version", False,
            "plugin.json has no 'version' field",
        )

    return version, DriftResult(
        file_str, "plugin-json-has-version", True,
        f"canonical version is {version}",
    )


def check_marketplace_no_version(
    marketplace_json_path: Path, canonical: str
) -> list[DriftResult]:
    """marketplace.json must carry no version key (top-level or per-plugin)
    that disagrees with plugin.json's canonical version."""
    results: list[DriftResult] = []
    file_str = str(marketplace_json_path)

    try:
        raw = marketplace_json_path.read_text(encoding="utf-8")
    except OSError as exc:
        results.append(DriftResult(
            file_str, "marketplace-json-readable", False,
            f"could not read marketplace.json: {exc}",
        ))
        return results

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        results.append(DriftResult(
            file_str, "marketplace-json-parseable", False,
            f"marketplace.json is not valid JSON: {exc}",
        ))
        return results

    top_version = data.get("version")
    top_ok = top_version is None or top_version == canonical
    results.append(DriftResult(
        file_str, "marketplace-top-level-version", top_ok,
        "no top-level 'version' key (plugin.json is authoritative)"
        if top_version is None
        else (
            f"top-level version {top_version} matches canonical {canonical}"
            if top_ok
            else f"top-level version {top_version} disagrees with canonical {canonical}"
        ),
    ))

    for plugin in data.get("plugins", []):
        name = plugin.get("name", "<unnamed>")
        plugin_version = plugin.get("version")
        plugin_ok = plugin_version is None or plugin_version == canonical
        results.append(DriftResult(
            file_str, f"marketplace-plugin-version[{name}]", plugin_ok,
            f"plugin entry '{name}' carries no 'version' key"
            if plugin_version is None
            else (
                f"plugin entry '{name}' version {plugin_version} matches canonical {canonical}"
                if plugin_ok
                else f"plugin entry '{name}' version {plugin_version} disagrees with canonical {canonical}"
            ),
        ))

    return results


def check_scan_target(path: Path, canonical: str) -> list[DriftResult]:
    """Scan one file for plugin-version-shaped tokens (badge or explicit
    Version: label) and assert each equals canonical. Never blanket-greps
    every X.Y.Z-shaped string, so OWASP edition numbers are never flagged."""
    results: list[DriftResult] = []
    file_str = str(path)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        results.append(DriftResult(
            file_str, "scan-target-readable", False,
            f"could not read file: {exc}",
        ))
        return results

    matches: list[tuple[str, str]] = []
    for m in BADGE_VERSION_RE.finditer(text):
        matches.append(("badge-version-token", m.group(1)))
    for m in LABEL_VERSION_RE.finditer(text):
        matches.append(("version-label-line", m.group(1)))

    if not matches:
        results.append(DriftResult(
            file_str, "scan-target-no-drift", True,
            "no plugin-version-shaped token found (nothing to check)",
        ))
        return results

    for check_name, found_version in matches:
        ok = found_version == canonical
        results.append(DriftResult(
            file_str, check_name, ok,
            f"found version {found_version} matches canonical {canonical}"
            if ok
            else f"found version {found_version} disagrees with canonical {canonical}",
        ))

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that no version string in the repo disagrees "
                     "with plugin.json's canonical version (PKG-05/D-04).",
    )
    parser.add_argument(
        "targets", nargs="*",
        help="Additional file(s) to scan for version-shaped tokens "
             "(default: README.md at the repo root).",
    )
    parser.add_argument(
        "--plugin-json", default=str(DEFAULT_PLUGIN_JSON),
        help="Path to the canonical plugin.json (default: .claude-plugin/plugin.json).",
    )
    parser.add_argument(
        "--marketplace-json", default=str(DEFAULT_MARKETPLACE_JSON),
        help="Path to marketplace.json (default: .claude-plugin/marketplace.json).",
    )
    parser.add_argument(
        "--format", choices=("json", "text"), default="json",
        help="Output format. JSON (default) for machine consumption; text for humans.",
    )
    args = parser.parse_args()

    all_results: list[DriftResult] = []

    canonical, plugin_result = load_canonical_version(Path(args.plugin_json))
    all_results.append(plugin_result)

    if canonical is None:
        any_failed = True
        return _emit(all_results, 0, args.format, any_failed)

    all_results.extend(
        check_marketplace_no_version(Path(args.marketplace_json), canonical)
    )

    targets = [Path(t) for t in args.targets] if args.targets else DEFAULT_SCAN_TARGETS
    for target in targets:
        all_results.extend(check_scan_target(target, canonical))

    any_failed = any(not r.passed for r in all_results)
    return _emit(all_results, len(targets), args.format, any_failed)


def _emit(results: list[DriftResult], files_scanned: int, fmt: str, any_failed: bool) -> int:
    if fmt == "json":
        json.dump(
            {
                "files_scanned": files_scanned,
                "results": [asdict(r) for r in results],
                "passed": not any_failed,
            },
            sys.stdout,
            indent=2,
        )
        print()
    else:
        print(f"Scanned {files_scanned} target file(s) for version drift.")
        for r in results:
            mark = "PASS" if r.passed else "FAIL"
            print(f"  [{mark}] {r.file} :: {r.check} — {r.message}")
        if any_failed:
            print("\nRESULT: FAIL — one or more checks failed.")
        else:
            print("\nRESULT: PASS — all checks passed.")

    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
