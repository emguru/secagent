from __future__ import annotations

import re
from pathlib import Path

from agentsec.models import Finding, Severity

_AG_HINT = re.compile(r"(?i)autogen|agentchat|pyautogen|AssistantAgent|UserProxyAgent")


def iter_autogen_findings(root: Path, file_path: Path) -> list[Finding]:
    if file_path.suffix.lower() != ".py":
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if len(text) > 1_500_000 or not _AG_HINT.search(text):
        return []
    rel = str(file_path.relative_to(root)).replace("\\", "/")
    findings: list[Finding] = []
    lines = text.splitlines()

    if re.search(r"(?i)code_execution\s*=\s*True", text):
        line_no = next(
            (
                i
                for i, ln in enumerate(lines, 1)
                if re.search(r"(?i)code_execution\s*=\s*True", ln)
                and "evidence=" not in ln
                and 'evidence="' not in ln
            ),
            None,
        )
        if line_no is None:
            pass
        else:
            ev = lines[line_no - 1].strip()[:220]
            findings.append(
                Finding(
                    rule_id="autogen_code_execution",
                    title="AutoGen code execution enabled",
                    severity=Severity.HIGH,
                    path=rel,
                    line=line_no,
                    evidence=ev,
                    recommendation="Run code in a sandboxed container with no secrets, read-only FS, and network egress blocked unless required. Disable in production unless tightly controlled.",
                    framework="autogen",
                    tags=["autogen", "execution"],
                    target_ids=["autogen"],
                )
            )

    if re.search(r"(?i)DockerExecutor|docker_executor", text):
        findings.append(
            Finding(
                rule_id="autogen_docker_executor",
                title="AutoGen Docker executor referenced",
                severity=Severity.MEDIUM,
                path=rel,
                line=None,
                evidence="Docker-based execution detected — verify image pinning and resource limits.",
                recommendation="Pin images by digest, run as non-root, mount minimal volumes, and avoid mounting Docker socket into agent containers.",
                framework="autogen",
                tags=["autogen", "docker"],
                target_ids=["autogen"],
            )
        )

    return findings
