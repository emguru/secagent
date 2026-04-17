# Install Python scanner (editable), then start Spring Boot UI on http://localhost:8080
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $root "scanner")
python -m pip install -e . -q
Set-Location (Join-Path $root "ui-server")
& (Join-Path $root "scripts\ensure-maven.ps1") "spring-boot:run"
