from __future__ import annotations

import os
import re
from pathlib import Path

from agentsec.targets import TARGET_CATALOG

_MANIFEST_NAMES = (
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
)

_LANGCHAIN_RE = re.compile(
    r"(?i)langchain|langgraph|langsmith|@langchain/",
)
# Avoid matching ".autogen" in imports like agentsec.rules.autogen
_AUTOGEN_RE = re.compile(
    r"(?i)pyautogen|autogen-agentchat|autogen-ext|^\s*autogen[=<>]|\bagentchat\b",
)
_CREWAI_RE = re.compile(r"(?i)\bcrewai\b")
_LITELLM_RE = re.compile(r"(?i)\blitellm\b")
_VERTEX_RE = re.compile(r"(?i)vertexai|google\.cloud\.aiplatform|vertex_ai")
_BEDROCK_RE = re.compile(r"(?i)bedrock|amazon\.bedrock")
_SEMANTIC_KERNEL_RE = re.compile(r"(?i)Microsoft\.SemanticKernel|semantic-kernel|semantic_kernel")


def _read_small(path: Path, limit: int = 400_000) -> str | None:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
        return data if len(data) <= limit else data[:limit]
    except OSError:
        return None


def _scan_manifests_for_pattern(root: Path, pattern: re.Pattern[str]) -> bool:
    for dirpath, dirnames, filenames in os.walk(root):
        # skip heavy dirs
        dirnames[:] = [
            d
            for d in dirnames
            if d.lower()
            not in {"node_modules", ".git", "venv", ".venv", "__pycache__", "target", "dist", "build"}
        ]
        for fn in filenames:
            if fn not in _MANIFEST_NAMES and not fn.endswith(".csproj"):
                continue
            text = _read_small(Path(dirpath) / fn, 800_000)
            if text and pattern.search(text):
                return True
    return False


def _any_py_imports(root: Path, pattern: re.Pattern[str]) -> bool:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if d.lower() not in {"node_modules", ".git", "venv", ".venv", "__pycache__", "target"}
        ]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = Path(dirpath) / fn
            text = _read_small(p, 120_000)
            if text and pattern.search(text):
                return True
    return False


def _has_csproj_semantic_kernel(root: Path) -> bool:
    for p in root.rglob("*.csproj"):
        try:
            if p.is_file() and _SEMANTIC_KERNEL_RE.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _github_workflows_dir(root: Path) -> Path | None:
    d = root / ".github" / "workflows"
    return d if d.is_dir() else None


def _gitlab_ci(root: Path) -> bool:
    return (root / ".gitlab-ci.yml").is_file() or (root / ".gitlab-ci.yaml").is_file()


def _workflow_suggests_agent(root: Path) -> bool:
    wd = _github_workflows_dir(root)
    if wd is None:
        return False
    agentish = re.compile(
        r"(?i)openai|anthropic|langchain|autogen|copilot|codex|claude|chatgpt|llm|agent|aider|cursor",
    )
    for yml in list(wd.glob("*.yml")) + list(wd.glob("*.yaml")):
        text = _read_small(yml, 500_000)
        if text and agentish.search(text):
            return True
    return len(list(wd.glob("*.yml"))) + len(list(wd.glob("*.yaml"))) > 0


def detect_frameworks(root: Path) -> list[str]:
    """Filesystem + light manifest heuristics. IDs must exist in TARGET_CATALOG."""
    found: set[str] = set()

    markers: list[tuple[str, str]] = [
        ("cursor", ".cursor/rules"),
        ("cursor", ".cursor/hooks.json"),
        ("copilot", ".github/copilot-instructions.md"),
        ("cline", ".clinerules"),
        ("agents_md", "AGENTS.md"),
    ]
    for tid, rel in markers:
        if (root / rel).exists():
            found.add(tid)

    if (root / "package.json").exists():
        found.add("node")
    if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
        found.add("python")
    if (root / "pom.xml").exists() or (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        found.add("jvm")

    if _scan_manifests_for_pattern(root, _LANGCHAIN_RE) or _any_py_imports(root, re.compile(r"(?i)from\s+langchain|import\s+langchain")):
        found.add("langchain")
    _autogen_import = re.compile(
        r"(?im)^\s*from\s+autogen\.|^\s*from\s+autogen\s+import|^\s*import\s+autogen\.|^\s*import\s+autogen\s",
    )
    if _scan_manifests_for_pattern(root, _AUTOGEN_RE) or _any_py_imports(root, _autogen_import):
        found.add("autogen")
    if _scan_manifests_for_pattern(root, _CREWAI_RE):
        found.add("crewai")
    if _scan_manifests_for_pattern(root, _LITELLM_RE):
        found.add("litellm")
    if _scan_manifests_for_pattern(root, _VERTEX_RE):
        found.add("vertex_ai")
    if _scan_manifests_for_pattern(root, _BEDROCK_RE):
        found.add("bedrock")
    if _has_csproj_semantic_kernel(root) or _scan_manifests_for_pattern(root, _SEMANTIC_KERNEL_RE):
        found.add("semantic_kernel")

    # MCP configs often live under .cursor or mcps (Cursor)
    for pattern in ("**/mcp.json", "**/mcp_config.json", "**/.cursor/mcp.json"):
        if any(root.glob(pattern)):
            found.add("mcp")
            break
    if (root / ".cursor").is_dir():
        for p in (root / ".cursor").rglob("*.json"):
            if "mcp" in p.name.lower():
                found.add("mcp")
                break

    if _github_workflows_dir(root) is not None:
        found.add("ci_github")
        if _workflow_suggests_agent(root):
            pass  # already flagged ci_github
    if _gitlab_ci(root):
        found.add("ci_gitlab")

    # Only return catalog keys
    valid = set(TARGET_CATALOG.keys())
    return sorted(found & valid)
