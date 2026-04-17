"""Canonical target IDs for agent stacks and CI — keep in sync with Java AgentTarget."""

from __future__ import annotations

from typing import Any

# id -> { "label", "description", "category" }
TARGET_CATALOG: dict[str, dict[str, str]] = {
    "cursor": {
        "label": "Cursor",
        "description": "Cursor IDE rules, hooks, MCP configs",
        "category": "IDE",
    },
    "copilot": {
        "label": "GitHub Copilot",
        "description": "Copilot instructions and GitHub agent surfaces",
        "category": "IDE",
    },
    "cline": {
        "label": "Cline",
        "description": "Cline / .clinerules",
        "category": "IDE",
    },
    "mcp": {
        "label": "MCP servers",
        "description": "Model Context Protocol configs and remote tools",
        "category": "Tools",
    },
    "agents_md": {
        "label": "AGENTS.md / agent docs",
        "description": "Repo-level agent instruction files",
        "category": "Docs",
    },
    "langchain": {
        "label": "LangChain / LangGraph",
        "description": "langchain, langgraph, langsmith in Python or JS",
        "category": "Framework",
    },
    "autogen": {
        "label": "AutoGen / AgentChat",
        "description": "Microsoft AutoGen, pyautogen, autogen-agentchat",
        "category": "Framework",
    },
    "crewai": {
        "label": "CrewAI",
        "description": "crewai multi-agent framework",
        "category": "Framework",
    },
    "semantic_kernel": {
        "label": "Semantic Kernel",
        "description": ".NET / Python Semantic Kernel",
        "category": "Framework",
    },
    "litellm": {
        "label": "LiteLLM",
        "description": "LiteLLM proxy / gateway usage",
        "category": "Framework",
    },
    "vertex_ai": {
        "label": "Google Vertex AI",
        "description": "vertexai, google-cloud-aiplatform",
        "category": "Cloud",
    },
    "bedrock": {
        "label": "AWS Bedrock",
        "description": "boto3 bedrock, amazon bedrock agents",
        "category": "Cloud",
    },
    "ci_github": {
        "label": "GitHub Actions",
        "description": "Workflows that may run agents or LLM steps",
        "category": "CI",
    },
    "ci_gitlab": {
        "label": "GitLab CI",
        "description": ".gitlab-ci.yml pipelines",
        "category": "CI",
    },
    "node": {
        "label": "Node / npm",
        "description": "package.json present",
        "category": "Runtime",
    },
    "python": {
        "label": "Python",
        "description": "Python packaging present",
        "category": "Runtime",
    },
    "jvm": {
        "label": "JVM (Maven/Gradle)",
        "description": "Java/Kotlin build files",
        "category": "Runtime",
    },
}


def valid_target_ids() -> frozenset[str]:
    return frozenset(TARGET_CATALOG.keys())


def normalize_declared(raw: list[str] | None) -> tuple[list[str], list[str]]:
    """Returns (known_ids, unknown_ids)."""
    if not raw:
        return [], []
    valid = valid_target_ids()
    known: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for item in raw:
        tid = (item or "").strip().lower().replace(" ", "_").replace("-", "_")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        if tid in valid:
            known.append(tid)
        else:
            unknown.append(item.strip())
    return sorted(known), unknown


def catalog_for_api() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tid in sorted(TARGET_CATALOG.keys()):
        meta = TARGET_CATALOG[tid]
        out.append(
            {
                "id": tid,
                "label": meta["label"],
                "description": meta["description"],
                "category": meta["category"],
            }
        )
    return out
