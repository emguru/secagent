from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Any, TextIO

from agentsec.models import Finding, Severity


def emit_ndjson(obj: dict[str, Any], stream: TextIO = sys.stdout) -> None:
    stream.write(json.dumps(obj, ensure_ascii=False) + "\n")
    stream.flush()


def summary_for_findings(findings: list[Finding]) -> dict[str, Any]:
    by_sev = Counter(f.severity.value for f in findings)
    return {
        "total": len(findings),
        "by_severity": dict(by_sev),
    }
