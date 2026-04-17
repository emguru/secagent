from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentsec import __version__
from agentsec.engine import scan_path
from agentsec.reporters import emit_ndjson, summary_for_findings
from agentsec.targets import catalog_for_api


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentsec", description="Scan agent projects for security issues.")
    p.add_argument("--path", help="Project root directory to scan")
    p.add_argument(
        "--format",
        choices=("ndjson", "json"),
        default="ndjson",
        help="Output format (ndjson streams events for live UIs)",
    )
    p.add_argument(
        "--targets",
        default="",
        help="Comma-separated stack IDs used to build the agent (see --dump-targets). Enables gap hints and optional --focus.",
    )
    p.add_argument(
        "--focus",
        action="store_true",
        help="Only report universal findings plus issues tagged for the declared --targets.",
    )
    p.add_argument("--dump-targets", action="store_true", help="Print target catalog JSON and exit")
    p.add_argument("--version", action="store_true", help="Print version and exit")
    args = p.parse_args(argv)

    if args.dump_targets:
        json.dump(catalog_for_api(), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0

    if args.version:
        print(__version__)
        return 0

    if not args.path:
        p.error("--path is required unless using --dump-targets or --version")

    root = Path(args.path)
    raw_targets = [s.strip() for s in args.targets.split(",") if s.strip()]

    if args.format == "ndjson":

        def on_progress(done: int, total: int, current: str) -> None:
            pct = int(100 * done / total) if total else 100
            emit_ndjson(
                {
                    "type": "progress",
                    "done": done,
                    "total": total,
                    "percent": pct,
                    "current_path": current,
                }
            )

        def on_begin(info: dict) -> None:
            emit_ndjson(
                {
                    "type": "started",
                    "path": str(root.resolve()),
                    "version": __version__,
                    **info,
                }
            )

        findings, detected, declared_known, unknown_names = scan_path(
            root,
            declared_targets=raw_targets,
            focus=args.focus,
            on_progress=on_progress,
            on_begin=on_begin,
        )

        for f in findings:
            emit_ndjson({"type": "finding", "finding": f.to_dict()})
        emit_ndjson(
            {
                "type": "done",
                "detected_frameworks": detected,
                "declared_targets": declared_known,
                "unknown_declared": unknown_names,
                "effective_targets": sorted(set(detected) | set(declared_known)),
                "focus": args.focus,
                "frameworks": detected,
                "summary": summary_for_findings(findings),
            }
        )
        return 0

    findings, detected, declared_known, unknown_names = scan_path(
        root,
        declared_targets=raw_targets,
        focus=args.focus,
    )
    blob = {
        "path": str(root.resolve()),
        "version": __version__,
        "detected_frameworks": detected,
        "declared_targets": declared_known,
        "unknown_declared": unknown_names,
        "effective_targets": sorted(set(detected) | set(declared_known)),
        "focus": args.focus,
        "frameworks": detected,
        "findings": [f.to_dict() for f in findings],
        "summary": summary_for_findings(findings),
    }
    json.dump(blob, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
