from __future__ import annotations

import re
from pathlib import Path

from agentsec.models import Finding, Severity

_DANGEROUS_SHELL = [
    (
        "exec_shell_rm_rf",
        r"(?i)(?:subprocess\.|os\.system\(|ProcessBuilder|Runtime\.getRuntime\(\)\.exec\(|shell_exec\().{0,80}(rm\s+-rf|del\s+/f|rmdir\s+/s)",
        Severity.CRITICAL,
        "Destructive shell command may be invoked programmatically. Gate with explicit user confirmation, allow-lists, and sandboxing; avoid passing raw model output to system/exec.",
    ),
    (
        "exec_curl_pipe_bash",
        r"(?i)curl\s+[^\n|]+\|\s*(?:ba)?sh",
        Severity.HIGH,
        "curl | bash is unsafe for agent-driven automation. Download with integrity checks, verify signatures, and use package managers.",
    ),
    (
        "eval_or_exec_string",
        r"(?i)\b(?:eval|exec)\s*\(\s*['\"]",
        Severity.MEDIUM,
        "Dynamic eval/exec on string literals can become RCE if fed untrusted input. Prefer structured parsing and safe APIs.",
    ),
]


def check_dangerous_execution(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    joined = text
    for rule_id, pattern, severity, rec in _DANGEROUS_SHELL:
        if re.search(pattern, joined):
            line_no: int | None = None
            evidence: str | None = None
            for i, line in enumerate(lines, start=1):
                if re.search(pattern, line):
                    line_no = i
                    evidence = line.strip()[:200]
                    break
            if evidence is None:
                evidence = "match spans multiple lines"
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title="Dangerous execution pattern",
                    severity=severity,
                    path=rel_path,
                    line=line_no,
                    evidence=evidence,
                    recommendation=rec,
                    tags=["execution", "rce"],
                )
            )
    return findings


def iter_execution_findings(root: Path, file_path: Path) -> list[Finding]:
    suffix = file_path.suffix.lower()
    if suffix not in {".py", ".sh", ".bash", ".ps1", ".js", ".ts", ".java", ".gradle", ".kts", ".json", ".yaml", ".yml", ".md"}:
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if len(text) > 2_000_000:
        return []
    rel = str(file_path.relative_to(root)).replace("\\", "/")
    return check_dangerous_execution(rel, text)
