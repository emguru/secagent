#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/.tools"
MVN_HOME="$TOOLS/apache-maven-3.9.6"
MVN_BIN="$MVN_HOME/bin/mvn"

if [[ ! -x "$MVN_BIN" ]]; then
  echo "Downloading Maven 3.9.6 to $TOOLS ..."
  mkdir -p "$TOOLS"
  ZIP="$(mktemp)"
  curl -fsSL "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip" -o "$ZIP"
  unzip -q "$ZIP" -d "$TOOLS"
  rm -f "$ZIP"
  chmod +x "$MVN_BIN" || true
fi

exec "$MVN_BIN" "$@"
