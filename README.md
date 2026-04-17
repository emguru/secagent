# AgentSec

AgentSec is a local security scanner for AI-agent projects. It includes:

- a Python scanning engine (`scanner/`) with a CLI (`agentsec`)
- a Spring Boot web UI and API (`ui-server/`)
- helper scripts (`scripts/`) to bootstrap Maven and run the full stack

The scanner inspects project files for risky patterns across agent configs, MCP usage, CI workflows, and framework integrations, then reports findings with severity and remediation guidance.

## Getting Started in 60 Seconds

From repository root:

Windows (PowerShell):

```powershell
.\scripts\start-ui.ps1
```

Linux/macOS:

```bash
./scripts/start-ui.sh
```

Then open [http://localhost:8080](http://localhost:8080), enter the path to a project folder, and click **Scan**.

## CLI in 60 Seconds

From repository root:

```bash
cd scanner
python -m pip install -e .
agentsec --path . --format json
```

Use `--format ndjson` for streaming output.

## Repository Layout

- `scanner/` - Python package (`agentsec-scanner`) and rules engine
- `ui-server/` - Spring Boot backend serving REST APIs + static frontend
- `scripts/` - startup/bootstrap scripts for Windows and Unix
- `.tools/` - local tool cache (Maven is downloaded here by helper scripts)

## Prerequisites

### Required

- Python 3.10+
- Java 17+

### Required for UI startup scripts

- Windows: PowerShell 5+ (or PowerShell 7+) and internet access (first run downloads Maven if not present)
- Linux/macOS: Bash, `curl`, and `unzip` (first run downloads Maven if not present)

## Quick Start

### Option A: Start the full UI stack (recommended)

From repository root:

Windows (PowerShell):

```powershell
.\scripts\start-ui.ps1
```

Linux/macOS:

```bash
./scripts/start-ui.sh
```

What this does:

1. installs the Python scanner in editable mode (`pip install -e .`) from `scanner/`
2. starts Spring Boot in `ui-server/` using Maven (`spring-boot:run`)
3. serves the app on `http://localhost:8080`

Then open [http://localhost:8080](http://localhost:8080).

### Option B: Run scanner CLI only

```bash
cd scanner
python -m pip install -e .
agentsec --path /path/to/project --format json
```

## Scanner CLI Usage

After installing from `scanner/` (`pip install -e .`), use:

```bash
agentsec --path <project-root> [options]
```

### Core flags

- `--path` (required unless using `--version` or `--dump-targets`): project directory to scan
- `--format {ndjson,json}`: output mode (default: `ndjson`)
- `--targets <csv>`: declared stack target IDs (for targeted hints/rules)
- `--focus`: only emit universal findings + findings matching selected targets
- `--dump-targets`: print supported target catalog JSON and exit
- `--version`: print scanner version and exit

### Examples

Stream scan events (good for automation/UIs):

```bash
agentsec --path . --format ndjson
```

Single JSON payload:

```bash
agentsec --path . --format json
```

Target-aware focused scan:

```bash
agentsec --path . --targets cursor,mcp,langchain --focus --format json
```

Inspect available target IDs:

```bash
agentsec --dump-targets
```

## Web UI and API Usage

When running on `http://localhost:8080`:

- `/` - interactive web UI
- `/api/health` - backend health and scanner root
- `/api/targets` - supported target catalog
- `/api/scan` - NDJSON streaming scan endpoint

### API details

#### `GET /api/health`

Response:

```json
{
  "status": "ok",
  "scannerRoot": "C:/path/to/secagent/scanner"
}
```

#### `GET /api/targets`

Returns list of target metadata:

```json
[
  {
    "id": "cursor",
    "label": "Cursor",
    "description": "Cursor IDE rules, hooks, MCP configs",
    "category": "IDE"
  }
]
```

#### `POST /api/scan`

Request body:

```json
{
  "path": "C:/path/to/project",
  "targets": ["cursor", "mcp", "langchain"],
  "focusTargets": true
}
```

Response:

- content type: `application/x-ndjson`
- streamed events: `started`, `progress`, `finding`, `done`
- error events are emitted as `{ "type": "error", "message": "..." }`

`curl` example:

```bash
curl -N -X POST "http://localhost:8080/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"path":"C:/path/to/project","targets":["cursor","mcp"],"focusTargets":false}'
```

## Configuration

### Server port

Configured in `ui-server/src/main/resources/application.properties`:

```properties
server.port=8080
```

Override at runtime:

```bash
# Linux/macOS
SERVER_PORT=9090 ./scripts/start-ui.sh
```

```powershell
# Windows PowerShell
$env:SERVER_PORT="9090"; .\scripts\start-ui.ps1
```

### Scanner root override

If the Python scanner is not located at the default sibling path, set:

- property: `agentsec.scanner-root`

Example:

```bash
cd ui-server
../scripts/ensure-maven.sh spring-boot:run -Dspring-boot.run.arguments="--agentsec.scanner-root=/absolute/path/to/scanner"
```

## Development Workflow

### Start UI in dev mode

Use the startup scripts above. Spring Boot serves static assets from `ui-server/src/main/resources/static/`.

### Run UI tests (Java)

```bash
cd ui-server
../scripts/ensure-maven.sh test
```

Windows PowerShell:

```powershell
cd ui-server
..\scripts\ensure-maven.ps1 test
```

### Build UI jar

```bash
cd ui-server
../scripts/ensure-maven.sh clean package
```

Output jar will be in `ui-server/target/`.

## Deployment

This project is designed to run where the scanner can access local repositories on disk. Typical deployment models:

### 1) Local workstation deployment (recommended)

- install Python and Java
- clone repo
- run `scripts/start-ui.ps1` (Windows) or `scripts/start-ui.sh` (Linux/macOS)
- access via browser on localhost

Best for individual developer usage and private code scanning.

### 2) Self-hosted internal server

- build the Spring Boot jar (`mvn package`)
- install Python scanner package on the same host
- start Java service with `agentsec.scanner-root` pointing to scanner install path
- expose server behind internal reverse proxy (Nginx/Traefik/IIS) with network access controls

Recommended hardening:

- run with least-privileged OS user
- limit scan root directories to trusted locations
- place behind VPN or internal network only
- terminate TLS at reverse proxy
- add request logging and process monitoring

### 3) Containerized deployment (custom)

No container files are currently included, but deployment is straightforward if you package:

- Java 17 runtime + built `ui-server` jar
- Python 3.10+ + installed `agentsec` package
- shared filesystem access to scanned repositories

## Troubleshooting

### Python not found

If `/api/scan` reports Python launcher errors:

- ensure `python` or `python3` works on PATH
- on Windows ensure `py -3` is available
- confirm Python version is 3.10+

### Maven command unavailable

Use provided scripts (`ensure-maven.ps1` / `ensure-maven.sh`), which auto-download Maven 3.9.6 into `.tools/`.

### `Not a directory` scan error

The `path` in scan request must be an existing directory on the server host.

### UI starts but scan fails

Check `/api/health` and verify `scannerRoot` points to the intended `scanner/` location.

## Versioning

Current scanner version: `0.1.0`.

## License

No project license file is currently present in this repository. Add one before external distribution.
