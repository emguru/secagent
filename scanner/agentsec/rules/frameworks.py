from __future__ import annotations

from pathlib import Path

from agentsec.models import Finding, Severity

# (target_id, relative path, recommendation)
_MARKERS: list[tuple[str, str, str]] = [
    ("cursor", ".cursor/rules", "Cursor rules or hooks present — review for over-broad tool permissions and secret exposure in rules."),
    ("cursor", ".cursor/hooks.json", "Cursor hooks detected — ensure hooks cannot exfiltrate data or run untrusted commands from model output."),
    ("copilot", ".github/copilot-instructions.md", "GitHub Copilot instructions found — treat as prompt surface; avoid embedding secrets."),
    ("cline", ".clinerules", "Cline rules directory may exist — verify tool allow-lists."),
    ("agents_md", "AGENTS.md", "AGENTS.md guides agent behavior — document security boundaries and forbidden actions explicitly."),
]


def framework_context_finding(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for tid, rel, rec in _MARKERS:
        p = root / rel
        if p.exists():
            findings.append(
                Finding(
                    rule_id=f"framework_{tid}",
                    title=f"Agent framework artifact: {rel}",
                    severity=Severity.INFO,
                    path=str(p.relative_to(root)).replace("\\", "/"),
                    line=None,
                    evidence=None,
                    recommendation=rec,
                    framework=tid,
                    tags=["framework", "inventory"],
                    target_ids=[tid],
                )
            )
    return findings
