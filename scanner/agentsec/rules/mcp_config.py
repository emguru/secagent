from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.models import Finding, Severity


def _parse_json_loose(text: str) -> dict | list | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def check_mcp_and_hooks_json(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    data = _parse_json_loose(text)
    if data is None:
        return findings

    lowered = rel_path.lower()
    is_hooks = ".cursor" in lowered and "hooks" in lowered
    is_mcp = "mcp" in lowered or "mcps" in lowered

    def walk(obj: object, path: str = "$") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_l = str(k).lower()
                if key_l in ("command", "script", "args", "url", "endpoint", "server"):
                    if isinstance(v, str):
                        if key_l == "url" or key_l == "endpoint":
                            if re.match(r"https?://", v) and "localhost" not in v.lower():
                                findings.append(
                                    Finding(
                                        rule_id="mcp_remote_endpoint",
                                        title="Remote MCP or hook endpoint",
                                        severity=Severity.MEDIUM,
                                        path=rel_path,
                                        line=None,
                                        evidence=f"{path}.{k} = {v[:120]}",
                                        recommendation="Verify trust and TLS for remote MCP servers. Prefer local stdio transports or pinned, audited endpoints; log tool calls.",
                                        framework="mcp",
                                        tags=["mcp", "network"],
                                        target_ids=["mcp", "cursor"],
                                    )
                                )
                        if key_l == "command" and re.search(r"(?i)(?:curl|wget|powershell|bash|cmd\.exe)", v):
                            findings.append(
                                Finding(
                                    rule_id="hook_shell_command",
                                    title="Hook invokes shell-oriented command",
                                    severity=Severity.MEDIUM,
                                    path=rel_path,
                                    line=None,
                                    evidence=f"{path}.{k} = {v[:200]}",
                                    recommendation="Prefer explicit executables with argument arrays. Avoid piping model output into shells; validate inputs.",
                                    framework="cursor-hooks",
                                    tags=["hooks", "execution"],
                                    target_ids=["cursor", "mcp"],
                                )
                            )
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    if is_hooks or is_mcp:
        walk(data)

    # Cursor MCP folder: warn on wildcard or http without pinning
    if is_mcp and isinstance(data, dict):
        raw = text.lower()
        if "insecure" in raw or "rejectunauthorized\":false" in raw.replace(" ", ""):
            findings.append(
                Finding(
                    rule_id="mcp_tls_insecure",
                    title="MCP config may disable TLS verification",
                    severity=Severity.HIGH,
                    path=rel_path,
                    line=None,
                    evidence="TLS verification disabled or 'insecure' flag suggested",
                    recommendation="Never disable TLS verification for production MCP clients. Use proper CAs and rotate credentials.",
                    framework="mcp",
                    tags=["mcp", "tls"],
                    target_ids=["mcp", "cursor"],
                )
            )

    return findings


def iter_mcp_findings(root: Path, file_path: Path) -> list[Finding]:
    suffix = file_path.suffix.lower()
    if suffix != ".json":
        return []
    lowered = str(file_path).lower()
    if ".cursor" not in lowered and "mcp" not in lowered:
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(file_path.relative_to(root)).replace("\\", "/")
    return check_mcp_and_hooks_json(rel, text)
