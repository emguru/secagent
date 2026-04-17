from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    path: str
    line: int | None
    evidence: str | None
    recommendation: str
    framework: str | None = None
    tags: list[str] = field(default_factory=list)
    # If set, finding applies to these stacks; None means universal (always included unless focus excludes non-matching).
    target_ids: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "framework": self.framework,
            "tags": self.tags,
        }
        if self.target_ids:
            d["target_ids"] = self.target_ids
        return d
