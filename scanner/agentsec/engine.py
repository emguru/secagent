from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from agentsec.models import Finding, Severity
from agentsec.rules.autogen import iter_autogen_findings
from agentsec.rules.ci_workflows import iter_github_workflow_findings, iter_gitlab_ci_findings
from agentsec.rules.detect import detect_frameworks
from agentsec.rules.execution import iter_execution_findings
from agentsec.rules.frameworks import framework_context_finding
from agentsec.rules.langchain import iter_langchain_findings
from agentsec.rules.mcp_config import iter_mcp_findings
from agentsec.rules.secrets import iter_secret_findings_for_file
from agentsec.targets import normalize_declared

# When scanning this tool's own source tree, skip stack-specific heuristics on bundled rule modules
# (they contain illustrative patterns that trigger self-matches).
_VENDOR_RULE_FILENAMES = frozenset(
    {
        "autogen.py",
        "langchain.py",
        "ci_workflows.py",
        "secrets.py",
        "execution.py",
        "mcp_config.py",
        "frameworks.py",
        "detect.py",
    }
)


def _skip_stack_rules_for_path(root: Path, file_path: Path) -> bool:
    try:
        rel = file_path.relative_to(root)
    except ValueError:
        return False
    parts = rel.parts
    if len(parts) < 2 or parts[-2] != "rules":
        return False
    return parts[-1] in _VENDOR_RULE_FILENAMES


_TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".cfg",
    ".ini",
    ".env",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".kts",
    ".gradle",
    ".xml",
    ".properties",
    ".sh",
    ".bash",
    ".ps1",
    ".sql",
    ".html",
    ".css",
    ".scss",
}


def _skip_dir(name: str) -> bool:
    n = name.lower()
    return n in {
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        "target",
        ".gradle",
        ".idea",
        ".vs",
    }


def iter_project_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        base = Path(dirpath)
        for fn in filenames:
            yield base / fn


def _declared_gap_findings(root: Path, declared: list[str], detected: list[str]) -> list[Finding]:
    dset = set(detected)
    out: list[Finding] = []
    for tid in declared:
        if tid in dset:
            continue
        out.append(
            Finding(
                rule_id=f"target_not_detected_{tid}",
                title=f"Declared stack not detected in project tree: {tid}",
                severity=Severity.INFO,
                path=str(root.resolve()).replace("\\", "/"),
                line=None,
                evidence=None,
                recommendation="Confirm the scan path is the repo root, or that manifests exist. If this stack is used indirectly, keep it declared for focused rules; otherwise remove it from the selection.",
                framework=tid,
                tags=["targets", "inventory"],
                target_ids=[tid],
            )
        )
    return out


def _apply_focus(findings: list[Finding], declared: list[str], focus: bool) -> list[Finding]:
    if not focus or not declared:
        return findings
    allow = set(declared)
    return [f for f in findings if not f.target_ids or (set(f.target_ids) & allow)]


def scan_path(
    root: Path,
    *,
    declared_targets: list[str] | None = None,
    focus: bool = False,
    on_progress: Callable[[int, int, str], None] | None = None,
    on_begin: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[Finding], list[str], list[str], list[str]]:
    """
    Returns (findings, detected_frameworks, declared_known_targets, unknown_declared_names).
    """
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(str(root))

    detected = detect_frameworks(root)
    declared_known, unknown_names = normalize_declared(declared_targets)
    effective = sorted(set(detected) | set(declared_known))

    if on_begin:
        on_begin(
            {
                "detected_frameworks": detected,
                "declared_targets": declared_known,
                "unknown_declared": unknown_names,
                "effective_targets": effective,
                "focus": focus,
            }
        )

    findings: list[Finding] = list(framework_context_finding(root))
    findings.extend(_declared_gap_findings(root, declared_known, detected))

    files = [p for p in iter_project_files(root) if p.is_file()]
    total = len(files)
    for i, file_path in enumerate(files, start=1):
        if on_progress:
            rel = str(file_path.relative_to(root)).replace("\\", "/")
            on_progress(i, total, rel)

        suffix = file_path.suffix.lower()
        if file_path.name in {"AGENTS.md", "CLAUDE.md", "GEMINI.md"}:
            pass
        elif suffix not in _TEXT_EXTENSIONS and file_path.name not in {
            "AGENTS.md",
            "Dockerfile",
            "hooks.json",
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
        }:
            continue

        findings.extend(iter_secret_findings_for_file(root, file_path))
        findings.extend(iter_execution_findings(root, file_path))
        findings.extend(iter_mcp_findings(root, file_path))
        skip_vendor = _skip_stack_rules_for_path(root, file_path)
        if not skip_vendor:
            findings.extend(iter_langchain_findings(root, file_path))
            findings.extend(iter_autogen_findings(root, file_path))
        findings.extend(iter_github_workflow_findings(root, file_path))
        findings.extend(iter_gitlab_ci_findings(root, file_path))

    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.evidence, f.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    unique = _apply_focus(unique, declared_known, focus)
    unique.sort(key=lambda x: (_severity_rank(x.severity), x.path, x.line or 0))
    return unique, detected, declared_known, unknown_names


def _severity_rank(s: Severity) -> int:
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    return order.index(s)
