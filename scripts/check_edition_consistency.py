#!/usr/bin/env python3
"""Check that OWASP edition statements agree across the repo (SWEEP-01, SWEEP-02, D-14).

Checks performed:
- Mirror: each skills/*/SKILL.md `description:` line appears exactly once, byte for byte, in docs/SKILL-STRUCTURE.md.
- Stale patterns: every tracked text line is matched against RULES (LLM, MASVS, K8s, ASVS 4.0.3, Top 10 2021); history sits in ALLOW.
- README matrix: each coverage-matrix row's edition and `retrieved` date equal its reference file's banner.

Design rules:
- Stdlib only; each check is soft (appends results, never raises); allow-listed hits print as PASS. JSON by default;
  `python3 scripts/check_edition_consistency.py --format text` ends with a RESULT line. Exit 0 if all passed, else 1.
- Excludes itself from any scan; never executes file-derived content (regex only, no eval or exec).
- The stale scan lists tracked files with one fixed-argv `git ls-files -z` (no shell), or walks a snapshot that has
  no `.git`, so its scope equals `git grep`'s. A missing or failing git fails closed; it never walks.
"""
from __future__ import annotations

import argparse, json, re, subprocess, sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
DOCS_MIRROR = "docs/SKILL-STRUCTURE.md"
SKIP_DIRS = {".git", ".planning", ".claude", "node_modules", "__pycache__"}
FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
DESC_LINE_RE = re.compile(r"^description:.*$", re.MULTILINE)  # single-line: DOTALL would swallow the closing fence
_A = "skills/owasp-security-audit/references/"


@dataclass
class CheckResult:
    file: str
    check: str
    passed: bool
    message: str


# (name, regex, only): `only` is None for every file, else a tuple of repo paths.
RULES = [
    ("llm-2025-code", re.compile(r"LLM\d{2}:2025"), None),  # LLM category code on the superseded 2025 edition
    ("llm-2025-label", re.compile(r"LLM(?: Top ?10)?(?: \(|\s)2025\b"), None),  # LLM label naming the 2025 edition
    ("llm-readme-row", re.compile(r"LLM Top 10\*\*\s*\|\s*2025\b"), None),  # README matrix LLM row still on 2025
    ("masvs-tier-label", re.compile(r"\*\*L[123]\*\*|\(L3 ?/ ?R\)"), (_A + "masvs.md",)),  # not asvs.md: real ASVS levels
    ("masvs-level", re.compile(r"MASVS[ -]L[123]\b"), None),  # MASVS defines no levels (MAS profiles are MAS-L1, MAS-L2, MAS-R)
    ("k8s-2025-code", re.compile(r"\b2025 K(?:0[1-9]|10)\b|\bK(?:0[1-9]|10):2025\b"), None),  # 2022 stays the K8s anchor
    ("asvs-4.0.3", re.compile(r"4\.0\.3"), None),  # live ASVS 4.0.3 reference; the 5.0.0 mapping history is in ALLOW
    ("asvs-4-edition", re.compile(r"ASVS\s*v?4(?:\.\d)?\b", re.I), None),  # ASVS v4 edition label, never allow-listed
    ("top10-2021-label", re.compile(r"A04 Insecure Design|Vulnerable (?:&|and) Outdated"), None),  # 2021-era Top 10 labels
]
# (rule, path, kind, matcher, reason). kind `file`: whole file (matcher None); `line`: regex searched in the hit line;
# `section`: hit under a `## ` heading starting with the matcher string. Never by line number or whole repo.
ALLOW = [
    ("llm-2025-label", _A + "llm.md", "line", re.compile(r"Bump Chart\.svg"), "upstream figure file name (2025 → 2026 crosswalk)"),
    ("k8s-2025-code", _A + "kubernetes-top10.md", "section", "Appendix: 2022", "labeled 2022 → 2025 appendix; 2022 stays the anchor"),
    ("asvs-4.0.3", _A + "asvs.md", "line", re.compile(r"mapping_v(?:4\.0\.3_to_v5\.0\.0|5\.0\.0_to_v4\.0\.3)\.yml"), "official mapping-file name"),
    ("asvs-4.0.3", _A + "asvs.md", "section", "Translating 4.0.3 IDs", "intentional 4.0.3 to 5.0.0 translation guidance (D-13)"),
    ("asvs-4.0.3", _A + "owasp-urls.json", "line", re.compile(r'"asvs_5_0_0_source"'), "the mapping-file citation (D-13)"),
    ("top10-2021-label", _A + "top10.md", "file", None, "2021 → 2025 crosswalk and A03 note keep 2021 labels as history"),
]
# (README row label, reference path, expected edition)
README_MATRIX = [
    ("OWASP Top 10", _A + "top10.md", "2025"), ("OWASP ASVS", _A + "asvs.md", "5.0.0"),
    ("OWASP MASVS", _A + "masvs.md", "2.1.0"), ("OWASP API Security Top 10", _A + "api-top10.md", "2023"),
    ("OWASP Kubernetes Top 10", _A + "kubernetes-top10.md", "2022"), ("OWASP LLM Top 10", _A + "llm.md", "2026"),
    ("OWASP Agentic Applications Top 10", _A + "agentic.md", "2026"),
    ("Secure Coding Practices", "skills/secure-coding-practices/references/scp-checklist.md", "Living-source derivation"),
]


def _read(root: Path, rel: str) -> str | None:
    """Text of a regular UTF-8 file inside the repo root, else None (never raises)."""
    try:
        p = (root / rel).resolve()
        return p.read_text(encoding="utf-8") if p.is_relative_to(root.resolve()) and p.is_file() else None
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def check_mirror(root: Path) -> list[CheckResult]:
    """Each SKILL.md description line appears exactly once in the docs mirror."""
    mirror, out = _read(root, DOCS_MIRROR) or "", []
    for path in sorted(root.glob("skills/*/SKILL.md")):
        rel = path.relative_to(root).as_posix()
        fm = FRONTMATTER_RE.match(_read(root, rel) or "")
        desc = DESC_LINE_RE.search(fm.group(1)) if fm else None
        n = mirror.count(desc.group(0)) if desc else 0  # 0 also covers an unreadable file or missing frontmatter
        msg = ("description line appears exactly once, byte for byte, in " + DOCS_MIRROR if n == 1 else
               f"description line appears {n} time(s) in {DOCS_MIRROR}; expected exactly one byte-identical copy")
        out.append(CheckResult(rel, "mirror-byte-identical", n == 1, msg))
    return out


def _scan_paths(root: Path) -> tuple[str, list[str]]:
    """Source label and sorted repo-relative paths: `git ls-files`, or a walk when there is no `.git`."""
    if (root / ".git").exists():
        try:  # Fixed argv, no shell, no file-derived value. Fail closed: never fall back to a walk.
            run = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False)
            if run.returncode:
                raise OSError(f"git exited {run.returncode}: {run.stderr.decode(errors='replace').strip()[:80]}")
        except OSError as exc:
            raise ValueError(str(exc)) from exc
        source, names = "git ls-files", [n.decode("utf-8", "surrogateescape") for n in run.stdout.split(b"\0") if n]
    else:
        source, names = "a directory walk", [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    return source, sorted(n for n in names if not SKIP_DIRS & set(n.split("/")) and (root / n).resolve() != SELF)


def _allowed(rule: str, rel: str, lines: list[str], i: int) -> str | None:
    """The ALLOW reason covering line i of file rel for rule, else None."""
    head = next((h for h in reversed(lines[:i + 1]) if h.startswith("## ")), "")[3:]
    for r, path, kind, match, why in ALLOW:
        if r == rule and path == rel and (kind == "file" or (kind == "line" and match.search(lines[i]))
                                          or (kind == "section" and head.startswith(match))):
            return why
    return None


def check_stale_patterns(root: Path) -> list[CheckResult]:
    """No scanned line matches a RULES denylist pattern unless ALLOW covers it."""
    try:
        source, paths = _scan_paths(root)
    except ValueError as exc:
        return [CheckResult(".", "stale-patterns", False, f"cannot list tracked files: {exc}")]
    out, scanned = [], 0
    for rel in paths:
        text = _read(root, rel)
        scanned += text is not None
        lines = (text or "").split("\n")
        for i, line in enumerate(lines):
            for name, rx, only in RULES:
                if (only is None or rel in only) and rx.search(line):
                    why = _allowed(name, rel, lines, i)
                    msg = f"allow-listed: {why}" if why else f"stale pattern: {line.strip()[:80]}"
                    out.append(CheckResult(f"{rel}:{i + 1}", name, bool(why), msg))
    out.append(CheckResult(".", "stale-patterns", True,
                           f"scanned {scanned} text file(s) from {source} against {len(RULES)} rule(s); "
                           f"{len(paths) - scanned} file(s) skipped (non-UTF-8, not a regular file, or outside the repo root)"))
    return out


def check_readme_matrix(root: Path) -> list[CheckResult]:
    """Each README matrix row's edition and retrieval date equal its reference banner (exactly one row each)."""
    readme, out = _read(root, "README.md") or "", []
    R = lambda ok, msg: CheckResult("README.md", "readme-matrix", ok, msg)
    for label, ref, edition in README_MATRIX:
        need = 2 if label == "OWASP MASVS" else 1  # MASVS also checks its MASWE companion date
        rows = re.findall(r"(?m)^\| \*\*" + re.escape(label) + r"\*\*[^|]* \| ([^|]*) \|(.*)$", readme)
        banner = re.findall(r"Retrieved (\d{4}-\d{2}-\d{2})", _read(root, ref) or "")
        if len(rows) != 1 or len(banner) < need:
            out += [R(False, f"{label}: {len(rows)} row(s) found, expected exactly one; {len(banner)} banner date(s) in {ref}")] * need
            continue
        cell = rows[0][0].strip()
        got = [(re.findall(r"retrieved (\d{4}-\d{2}-\d{2})", t) or [None])[0] for t in (cell, rows[0][1])]
        ok = re.match(re.escape(edition) + r"(?![\w.])", cell) is not None and got[0] == banner[0]
        out.append(R(ok, f"{label}: README says {cell[:24]!r}, retrieved {got[0]}; expected {edition}, retrieved {banner[0]}"))
        if need == 2:
            out.append(R(got[1] == banner[1], f"MASWE companion: README retrieved {got[1]}; masvs.md MASWE banner {banner[1]}"))
    return out


CHECKS = [check_mirror, check_stale_patterns, check_readme_matrix]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--format", choices=["json", "text"], default="json")
    return _emit([r for check in CHECKS for r in check(REPO_ROOT)], parser.parse_args().format)


def _emit(results: list[CheckResult], fmt: str) -> int:
    failed = any(not r.passed for r in results)
    if fmt == "json":
        print(json.dumps({"results": [asdict(r) for r in results], "passed": not failed}, indent=2))
    else:
        print(f"Edition consistency: {len(results)} result(s).")
        for r in results:
            print(f"  [{'PASS' if r.passed else 'FAIL'}] {r.file} :: {r.check} — {r.message}")
        print("\nRESULT: " + ("FAIL — one or more checks failed." if failed else "PASS — all checks passed."))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
