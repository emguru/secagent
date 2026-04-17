# Downloads Apache Maven into ..\.tools if bin\mvn.cmd is missing, then runs mvn with passed args.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root ".tools"
$mvnHome = Join-Path $tools "apache-maven-3.9.6"
$mvnCmd = Join-Path $mvnHome "bin\mvn.cmd"

if (-not (Test-Path $mvnCmd)) {
    Write-Host "Downloading Maven 3.9.6 to $tools ..."
    New-Item -ItemType Directory -Force -Path $tools | Out-Null
    $zip = Join-Path $env:TEMP "apache-maven-3.9.6-bin.zip"
    Invoke-WebRequest -Uri "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $tools -Force
}

& $mvnCmd @args
