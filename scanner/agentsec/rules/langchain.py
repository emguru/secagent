from __future__ import annotations

import re
from pathlib import Path

from agentsec.models import Finding, Severity

_LC_HINT = re.compile(r"(?i)langchain|langgraph|langsmith")


def _relevant_file(path: Path) -> bool:
    return path.suffix.lower() in {".py", ".ts", ".js", ".tsx", ".jsx"}


def check_langchain_patterns(rel_path: str, text: str) -> list[Finding]:
    if not _LC_HINT.search(text):
        return []
    findings: list[Finding] = []
    lines = text.splitlines()

    if re.search(r"(?i)pickle\.loads?\s*\(", text):
        line_no = next(
            (
                i
                for i, ln in enumerate(lines, 1)
                if re.search(r"(?i)pickle\.loads?\s*\(", ln)
                and "r\"" not in ln
                and "r'" not in ln
                and not re.search(r"(?i)re\.(search|match|sub|compile)\s*\(", ln)
            ),
            None,
        )
        if line_no is None:
            pass
        else:
            ev = lines[line_no - 1].strip()[:200]
            findings.append(
                Finding(
                    rule_id="langchain_pickle",
                    title="pickle usage near LangChain-style code",
                    severity=Severity.HIGH,
                    path=rel_path,
                    line=line_no,
                    evidence=ev,
                    recommendation="Avoid pickle for agent data; use JSON, Pydantic models, or explicit schemas. If unavoidable, strictly validate and isolate sources.",
                    framework="langchain",
                    tags=["langchain", "deserialization"],
                    target_ids=["langchain"],
                )
            )

    for i, line in enumerate(lines, 1):
        if re.search(r"(?i)yaml\.load\s*\(\s*[^,\)]+\)\s*$", line) and "SafeLoader" not in line and "safe_load" not in line.lower():
            findings.append(
                Finding(
                    rule_id="langchain_yaml_load",
                    title="yaml.load without SafeLoader",
                    severity=Severity.MEDIUM,
                    path=rel_path,
                    line=i,
                    evidence=line.strip()[:200],
                    recommendation="Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader) so prompts or tool outputs cannot execute arbitrary types.",
                    framework="langchain",
                    tags=["langchain", "yaml"],
                    target_ids=["langchain"],
                )
            )
            break

    if re.search(r"(?i)eval\s*\(\s*[^)]*\)", text) and _LC_HINT.search(text):
        line_no = next(
            (
                i
                for i, ln in enumerate(lines, 1)
                if re.search(r"(?i)\beval\s*\(", ln)
                and "re.search" not in ln
                and "re.match" not in ln
                and "r\"" not in ln
                and "r'" not in ln
                and "title=" not in ln
                and "rule_id=" not in ln
            ),
            None,
        )
        if line_no is not None:
            ev = lines[line_no - 1].strip()[:220]
            findings.append(
                Finding(
                    rule_id="langchain_eval",
                    title="eval() with LangChain-related code",
                    severity=Severity.HIGH,
                    path=rel_path,
                    line=line_no,
                    evidence=ev,
                    recommendation="Remove eval; use ast.literal_eval for constants only, or structured tool arguments.",
                    framework="langchain",
                    tags=["langchain", "rce"],
                    target_ids=["langchain"],
                )
            )

    return findings


def iter_langchain_findings(root: Path, file_path: Path) -> list[Finding]:
    if not _relevant_file(file_path):
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if len(text) > 1_500_000:
        return []
    rel = str(file_path.relative_to(root)).replace("\\", "/")
    return check_langchain_patterns(rel, text)
