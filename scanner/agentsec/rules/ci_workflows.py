from __future__ import annotations

import re
from pathlib import Path

from agentsec.models import Finding, Severity


def iter_github_workflow_findings(root: Path, file_path: Path) -> list[Finding]:
    try:
        rel = file_path.relative_to(root)
    except ValueError:
        return []
    parts = {p.lower() for p in rel.parts}
    if ".github" not in parts or "workflows" not in parts:
        return []
    if file_path.suffix.lower() not in {".yml", ".yaml"}:
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel_s = str(rel).replace("\\", "/")
    findings: list[Finding] = []
    lines = text.splitlines()

    # Unpinned third-party actions (branch or moving tag)
    for i, line in enumerate(lines, 1):
        m = re.search(r"uses:\s*([^#]+)", line)
        if not m:
            continue
        ref = m.group(1).strip()
        if re.match(r"^actions/(checkout|setup-node|cache)@[a-f0-9]{40}\b", ref):
            continue
        if re.match(r"^[^@\s]+@[a-f0-9]{40}\b", ref):
            continue
        if re.match(r"^[^@\s]+@(v?\d+\.\d+\.\d+)$", ref):
            continue
        if "@" in ref and not re.search(r"@[a-f0-9]{40}\b", ref) and not re.match(r".*@(v?\d+\.\d+\.\d+)$", ref):
            if ref.startswith("docker://") or ref.startswith("./"):
                continue
            findings.append(
                Finding(
                    rule_id="ci_action_unpinned",
                    title="GitHub Action may be unpinned (not commit SHA)",
                    severity=Severity.MEDIUM,
                    path=rel_s,
                    line=i,
                    evidence=line.strip()[:200],
                    recommendation="Pin actions to a full commit SHA for supply-chain safety. Avoid @main or floating tags for untrusted actions.",
                    framework="ci_github",
                    tags=["ci", "supply-chain"],
                    target_ids=["ci_github"],
                )
            )
            break

    if re.search(r"(?m)^\s*echo\s+.*\$\{\{\s*secrets\.", text):
        findings.append(
            Finding(
                rule_id="ci_secret_echo",
                title="Possible secret echoed in workflow logs",
                severity=Severity.HIGH,
                path=rel_s,
                line=None,
                evidence="echo with secrets.* context can leak into CI logs.",
                recommendation="Never print secrets. Use env vars only for tool inputs and enable log masking; prefer OIDC over long-lived tokens.",
                framework="ci_github",
                tags=["ci", "secrets"],
                target_ids=["ci_github"],
            )
        )

    if re.search(r"(?i)OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY\s*:", text):
        line_no = next(
            (
                i
                for i, ln in enumerate(lines, 1)
                if re.search(r"(?i)OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY\s*:", ln)
            ),
            None,
        )
        ev_line = lines[line_no - 1].strip()[:200] if line_no else None
        findings.append(
            Finding(
                rule_id="ci_inline_secret_name",
                title="Workflow references common secret env names (verify not hardcoded)",
                severity=Severity.LOW,
                path=rel_s,
                line=line_no,
                evidence=ev_line,
                recommendation="Use ${{ secrets.* }} or provider OIDC; rotate any key ever committed to the workflow file.",
                framework="ci_github",
                tags=["ci", "secrets"],
                target_ids=["ci_github"],
            )
        )

    return findings


def iter_gitlab_ci_findings(root: Path, file_path: Path) -> list[Finding]:
    if file_path.name not in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel_s = str(file_path.relative_to(root)).replace("\\", "/")
    findings: list[Finding] = []

    if re.search(r"(?m)^\s*-\s*echo\s+.*\$[A-Z0-9_]*(KEY|SECRET|TOKEN)", text):
        findings.append(
            Finding(
                rule_id="gitlab_secret_echo",
                title="GitLab CI may echo sensitive variable names",
                severity=Severity.MEDIUM,
                path=rel_s,
                line=None,
                evidence="Review scripts for accidental secret printing in job logs.",
                recommendation="Use masked CI variables, limit job log access, and avoid echoing credential material.",
                framework="ci_gitlab",
                tags=["ci", "secrets"],
                target_ids=["ci_gitlab"],
            )
        )

    return findings
