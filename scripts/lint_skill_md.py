#!/usr/bin/env python3
"""Lint SKILL.md frontmatter against the Anthropic Agent Skills spec.

Verifies FMT-01 (name/description limits), FMT-02 (body-line guidance), and
FMT-05 (byte-0 frontmatter start, no angle brackets, only allowed bundled
directories) for every `SKILL.md` under a given path.

Design rules:
- Stdlib only (re, sys, pathlib, argparse, dataclasses). PyYAML is not
  installed in the verified target environment, so frontmatter is extracted
  with a regex on the leading fenced block rather than a YAML parser.
- Each check is soft: append a pass/fail result, never raise, so one file's
  failure does not abort the run.
- Output is JSON to stdout by default; `--format text` prints a human
  summary instead.
- Exit code is 0 when every check passed, 1 when any check failed.

Usage:
    python3 lint_skill_md.py <path>
    python3 lint_skill_md.py <path> --format text
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

# The three bundled-subdirectory names the Agent Skills convention allows
# under a skill directory (docs/SKILL-STRUCTURE.md, D-07).
ALLOWED_BUNDLED_DIRS = {"references", "scripts", "assets"}

MAX_BODY_LINES = 500
MAX_NAME_LEN = 64
MAX_DESC_LEN = 1024
RESERVED_WORDS = ("claude", "anthropic")

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
NAME_RE = re.compile(r"^name:\s*(.*)$", re.MULTILINE)
DESC_RE = re.compile(r"^description:\s*(.*)$", re.MULTILINE | re.DOTALL)


@dataclass
class LintResult:
    file: str
    check: str
    passed: bool
    message: str


def lint_file(path: Path) -> list[LintResult]:
    results: list[LintResult] = []
    file_str = str(path)

    try:
        raw = path.read_bytes()
    except OSError as exc:
        results.append(LintResult(file_str, "readable", False, f"could not read file: {exc}"))
        return results

    # FMT-05: byte-0 frontmatter start — first 3 bytes must be the fence,
    # no BOM, no leading blank line.
    starts_at_byte0 = raw[:3] == b"---"
    results.append(LintResult(
        file_str, "byte0-start", starts_at_byte0,
        "frontmatter starts at byte 0" if starts_at_byte0
        else "file does not start with '---' at byte 0 (BOM or leading blank line?)",
    ))

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        results.append(LintResult(file_str, "utf8-decode", False, f"not valid UTF-8: {exc}"))
        return results

    # Frontmatter block present.
    match = FRONTMATTER_RE.match(content)
    has_frontmatter = match is not None
    results.append(LintResult(
        file_str, "frontmatter-present", has_frontmatter,
        "frontmatter block found" if has_frontmatter else "no leading '---'...'---' frontmatter block found",
    ))
    if not has_frontmatter:
        return results

    fm = match.group(1)

    # name checks
    name_match = NAME_RE.search(fm)
    name = name_match.group(1).strip() if name_match else ""
    has_name = bool(name)
    results.append(LintResult(
        file_str, "name-present", has_name,
        "name field found" if has_name else "no 'name:' field in frontmatter",
    ))

    if has_name:
        name_len_ok = len(name) <= MAX_NAME_LEN
        results.append(LintResult(
            file_str, "name-length", name_len_ok,
            f"name length {len(name)} <= {MAX_NAME_LEN}" if name_len_ok
            else f"name exceeds {MAX_NAME_LEN} chars ({len(name)})",
        ))

        name_charset_ok = bool(re.fullmatch(r"[a-z0-9-]+", name))
        results.append(LintResult(
            file_str, "name-charset", name_charset_ok,
            "name uses only lowercase letters, digits, hyphens" if name_charset_ok
            else "name contains characters outside [a-z0-9-]",
        ))

        has_reserved = any(word in name for word in RESERVED_WORDS)
        results.append(LintResult(
            file_str, "name-no-reserved-word", not has_reserved,
            "name contains no reserved word" if not has_reserved
            else f"name contains a reserved word ({RESERVED_WORDS})",
        ))

        # D-07: name must exactly equal the parent directory name.
        parent_dir = path.parent.name
        name_matches_parent = name == parent_dir
        results.append(LintResult(
            file_str, "name-matches-parent-dir", name_matches_parent,
            f"name '{name}' matches parent directory" if name_matches_parent
            else f"name '{name}' != parent directory '{parent_dir}' (D-07)",
        ))

    # description checks
    desc_match = DESC_RE.search(fm)
    desc = desc_match.group(1).strip() if desc_match else ""
    has_desc = bool(desc)
    results.append(LintResult(
        file_str, "description-present", has_desc,
        "description field found and non-empty" if has_desc else "no non-empty 'description:' field in frontmatter",
    ))

    if has_desc:
        desc_len_ok = len(desc) <= MAX_DESC_LEN
        results.append(LintResult(
            file_str, "description-length", desc_len_ok,
            f"description length {len(desc)} <= {MAX_DESC_LEN}" if desc_len_ok
            else f"description exceeds {MAX_DESC_LEN} chars ({len(desc)})",
        ))

    # FMT-05: no literal angle brackets anywhere in the frontmatter block.
    no_angle_brackets = "<" not in fm and ">" not in fm
    results.append(LintResult(
        file_str, "no-angle-brackets", no_angle_brackets,
        "frontmatter contains no angle brackets" if no_angle_brackets
        else "frontmatter contains a literal '<' or '>' character",
    ))

    # FMT-02: body-line advisory — warn, do not fail, if body exceeds guidance.
    body = content[match.end():]
    body_lines = len(body.splitlines())
    body_ok = body_lines <= MAX_BODY_LINES
    results.append(LintResult(
        file_str, "body-line-guidance", body_ok,
        f"body is {body_lines} lines (<= {MAX_BODY_LINES} guidance)" if body_ok
        else f"body is {body_lines} lines, exceeds {MAX_BODY_LINES}-line guidance (advisory only)",
    ))

    # FMT-05: only allowed bundled directories under the skill directory.
    skill_dir = path.parent
    bundled_dirs = sorted(
        d.name for d in skill_dir.iterdir() if d.is_dir()
    )
    disallowed = [d for d in bundled_dirs if d not in ALLOWED_BUNDLED_DIRS]
    bundled_dirs_ok = not disallowed
    results.append(LintResult(
        file_str, "allowed-bundled-dirs", bundled_dirs_ok,
        f"only allowed bundled dirs present ({bundled_dirs})" if bundled_dirs_ok
        else f"disallowed subdirectory names present: {disallowed}",
    ))

    return results


def iter_skill_md(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.name == "SKILL.md":
            yield root
        return
    yield from sorted(root.rglob("SKILL.md"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lint SKILL.md frontmatter against the Agent Skills spec "
                     "(FMT-01/FMT-02/FMT-05).",
    )
    parser.add_argument("path", help="File or directory to lint (searches recursively for SKILL.md).")
    parser.add_argument(
        "--format", choices=("json", "text"), default="json",
        help="Output format. JSON (default) for machine consumption; text for humans.",
    )
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    all_results: list[LintResult] = []
    files_checked = 0
    for skill_md in iter_skill_md(root):
        files_checked += 1
        all_results.extend(lint_file(skill_md))

    any_failed = any(not r.passed for r in all_results)

    if args.format == "json":
        json.dump(
            {
                "files_checked": files_checked,
                "results": [asdict(r) for r in all_results],
                "passed": not any_failed,
            },
            sys.stdout,
            indent=2,
        )
        print()
    else:
        print(f"Checked {files_checked} SKILL.md file(s).")
        for r in all_results:
            mark = "PASS" if r.passed else "FAIL"
            print(f"  [{mark}] {r.file} :: {r.check} — {r.message}")
        if any_failed:
            print("\nRESULT: FAIL — one or more checks failed.")
        else:
            print("\nRESULT: PASS — all checks passed.")

    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
