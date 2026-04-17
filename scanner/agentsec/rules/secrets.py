from __future__ import annotations

import re
from pathlib import Path

from agentsec.models import Finding, Severity

# High-signal patterns; tuned to reduce noise vs. obvious placeholders
_PATTERNS: list[tuple[str, str, Severity, str]] = [
    (
        "secret_openai_key",
        r"(?i)(?:OPENAI_API_KEY|sk-[a-zA-Z0-9]{20,}T3BlbkFJ)",
        Severity.HIGH,
        "OpenAI-style API material detected. Move secrets to a secret manager or environment variables; never commit real keys.",
    ),
    (
        "secret_anthropic_key",
        r"(?i)(?:ANTHROPIC_API_KEY|sk-ant-api[a-zA-Z0-9\-_]{10,})",
        Severity.HIGH,
        "Anthropic API key pattern detected. Rotate the key if this is real, store only in env/secret store, and scrub git history if committed.",
    ),
    (
        "secret_aws_key",
        r"(?i)(?:AKIA[0-9A-Z]{16}|(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{20,})",
        Severity.CRITICAL,
        "AWS credential material may be present. Revoke/rotate keys, use IAM roles or OIDC, and remove from the repo.",
    ),
    (
        "secret_generic_bearer",
        r"(?i)bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        Severity.HIGH,
        "JWT/Bearer token pattern in source. Tokens in files leak via git; use short-lived tokens from env and never commit them.",
    ),
    (
        "secret_slack_token",
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        Severity.HIGH,
        "Slack token pattern. Revoke in Slack admin if real; use bot tokens via env only.",
    ),
    (
        "secret_github_pat",
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        Severity.CRITICAL,
        "GitHub PAT pattern. Revoke the token in GitHub settings and use fine-grained tokens from CI secrets.",
    ),
]


def _should_skip_path(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if any(
        x in parts
        for x in (
            "node_modules",
            ".git",
            "venv",
            ".venv",
            "__pycache__",
            "dist",
            "build",
            "target",
            ".gradle",
        )
    ):
        return True
    return False


def is_pattern_definition_line(line: str) -> bool:
    """Avoid flagging regex / scanner source lines as credential leaks."""
    s = line.strip()
    if s.startswith('r"') or s.startswith("r'") or s.startswith('r"""') or s.startswith("r'''"):
        return True
    if "re.compile" in s or "_PATTERNS" in s:
        return True
    if "re.search" in s and ("API_KEY" in s or "SECRET" in s):
        return True
    return False


def _is_likely_pattern_source_line(line: str) -> bool:
    return is_pattern_definition_line(line)


def check_secrets_in_text(
    rel_path: str,
    text: str,
    *,
    max_line_preview: int = 120,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule_id, pattern, severity, rec in _PATTERNS:
        for i, line in enumerate(lines, start=1):
            if _is_likely_pattern_source_line(line):
                continue
            if re.search(pattern, line):
                snippet = line.strip()
                if len(snippet) > max_line_preview:
                    snippet = snippet[:max_line_preview] + "…"
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=f"Possible secret: {rule_id}",
                        severity=severity,
                        path=rel_path,
                        line=i,
                        evidence=snippet,
                        recommendation=rec,
                        tags=["secret", "credentials"],
                    )
                )
    return findings


def iter_secret_findings_for_file(root: Path, file_path: Path) -> list[Finding]:
    if _should_skip_path(file_path):
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(file_path.relative_to(root)).replace("\\", "/")
    # Skip huge binaries / minified blobs
    if len(text) > 2_000_000:
        return []
    return check_secrets_in_text(rel, text)
