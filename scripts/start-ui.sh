#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/scanner"
python3 -m pip install -e . -q 2>/dev/null || python -m pip install -e . -q
cd "$ROOT/ui-server"
exec "$ROOT/scripts/ensure-maven.sh" spring-boot:run
