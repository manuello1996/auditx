# auditx

Extensible Python CLI to run performance/security/configuration checks. One file = one check.
Dynamic discovery of checks & providers. Facts collected per tech (no targets).

## Quickstart

### Install (standard)
```bash
pip install -e .
auditx run --format table
```

### Run **without installing** (dev mode)
From repo root, useful to test without `pip install`.

**Wrapper — uses local virtualenv automatically**
- macOS / Linux
  ```bash
  ./auditx run --format table
  ./auditx docs --output checks.md
  ./auditx docs --tech linux --output linux-checks.md  # optional filter
  ./auditx docs --include hostname --exclude slowqueries
  ./auditx docs --format table
  ./auditx facts --format json  # collects all providers by default
  ```

**Option A — Inline PYTHONPATH (recommended)**
- macOS / Linux
  ```bash
  PYTHONPATH=src python3 -m auditx.cli run --format table
  PYTHONPATH=src python3 -m auditx.cli docs --output checks.md
  ```
- Windows (PowerShell)
  ```powershell
  $env:PYTHONPATH="src"; python -m auditx.cli run --format table
  $env:PYTHONPATH="src"; python -m auditx.cli docs --output checks.md
  ```

> **Tip:** Running `python3 src/auditx/cli.py ...` directly raises `ImportError: attempted relative import with no known parent package` because the package context is missing. Always invoke the CLI via `python -m auditx.cli` with `PYTHONPATH=src` when working from the repository.

> **Color:** Table output is colorized by default. Add `--no-color` to disable ANSI styles (for CI/logs) or `--color` to force color when piping.

**Option B — Export PYTHONPATH once per shell**
- macOS / Linux
  ```bash
  export PYTHONPATH=src
  python3 -m auditx.cli run --format table
  python3 -m auditx.cli docs --output checks.md
  ```
- Windows (PowerShell)
  ```powershell
  $env:PYTHONPATH="src"
  python -m auditx.cli run --format table
  python -m auditx.cli docs --output checks.md
  ```

**Optional: local virtualenv**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt  # extras: -r requirements-mysql.txt / -r requirements-zabbix.txt
python3 src/auditx/cli.py run --format table
```

## Configuration

Configuration files are loaded in the following order (later entries override earlier ones):

1. `~/.auditx/*.yaml`
2. `config/*.yaml` relative to the current working directory
3. Direct file references provided via `AUDITX_CONFIG_DIR` (either a directory containing YAML files or a YAML file path)
4. Explicit `--config path.yaml` options provided on the CLI (can be repeated; merged last)

Copy `config/auditx.yaml.default` or rely on the built-in template and place your customized YAML under one of the directories above (for global usage, prefer `~/.auditx`). You can override any value with env `AUDITX__...`, `--vars-file path.yml`, or `--set key=value`. Secrets support `${env:VAR}` and `${file:/path}`.

```yaml
mysql:
  host: db1.example.com
  user: auditor
  password: ${env:MYSQL_AUDITOR_PASS}
  database: appdb

zabbix:
  api_url: https://zabbix.example.com/api_jsonrpc.php
  api_token: ""  # optional; overrides username/password when provided
  username: auditor
  password: ${env:ZABBIX_PASS}
  unsupported_item_threshold_minutes: 60  # adjust to change the unsupported item check window

linux:
  method: local
```
All `.yaml` / `.yml` files you create in `config/` are merged in lexicographic order.
If you run the CLI without any configuration files, it will guide you through an interactive setup (only when running in a TTY).

> **Tip:** Every CLI command (`run`, `facts`, `docs`) accepts one or more `--config path.yaml` options. These files are resolved after the standard search paths, making it easy to target ad-hoc configurations without moving them into `config/` or `~/.auditx/`.

## Providers (facts)

Providers under `auditx/providers/*.py` (or external plugins via entry point `auditx.providers`) are
auto-discovered at runtime; they register facts per tech. Facts are cached in-memory and optionally
persisted with `--facts-cache` (+ TTL via `--facts-ttl`).

## Development

- Code style: black + ruff, type hints, mypy (strict)
- Tests: pytest
