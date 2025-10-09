from __future__ import annotations

import json
import re
from pathlib import Path
import sys

from typer.testing import CliRunner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from auditx.cli import app

runner = CliRunner()

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _ensure_min_config(monkeypatch):
    monkeypatch.setenv("AUDITX__linux__method", "local")


def test_run_outputs_colored_table(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    _ensure_min_config(monkeypatch)
    result = runner.invoke(app, ["run", "--color", "--tech", "linux", "--no-parallel"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "\x1b[" in result.stdout


def test_run_no_color_disables_styles(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    _ensure_min_config(monkeypatch)
    result = runner.invoke(app, ["run", "--no-color", "--tech", "linux", "--no-parallel"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "\x1b[" not in result.stdout


def test_facts_json(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    _ensure_min_config(monkeypatch)
    result = runner.invoke(app, ["facts", "--format", "json", "--no-color"], catch_exceptions=False)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "linux" in payload
    assert isinstance(payload["linux"], dict)
    assert all(isinstance(v, dict) for v in payload.values())


def test_facts_table(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    _ensure_min_config(monkeypatch)
    result = runner.invoke(app, ["facts", "--tech", "linux", "--no-color"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "AuditX Facts" in result.stdout
    assert "linux" in result.stdout


def test_run_collects_registered_providers(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)

    import auditx.cli as cli_mod
    from auditx.checks.linux.hostname_check import HostnameCheck

    monkeypatch.setattr(cli_mod.cfg, "load_project_config", lambda: {})
    monkeypatch.setattr(cli_mod, "_ensure_config", lambda cfg: {})
    monkeypatch.setattr(cli_mod, "iter_local_checks", lambda: [HostnameCheck])
    monkeypatch.setattr(cli_mod, "iter_entrypoint_checks", lambda: [])
    monkeypatch.setattr(cli_mod, "registered_techs", lambda: {"linux"})

    calls: list[str] = []

    def fake_collect(tech: str, params: dict, store, reporter=None) -> None:
        calls.append(tech)
        if tech == "linux":
            store.set_namespace("linux", {"linux.uname": {"system": "Linux", "node": "test"}})
        else:
            store.set_namespace(tech, {f"{tech}.dummy": True})

    monkeypatch.setattr(cli_mod, "collect_facts", fake_collect)

    result = runner.invoke(app, ["run", "--no-parallel"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "Hostname is" in result.stdout
    assert "linux" in calls


def test_run_without_config_prompts(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    monkeypatch.delenv("AUDITX__linux__method", raising=False)
    result = runner.invoke(app, ["run", "--no-parallel"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "AuditX Report" in result.stdout


def test_docs_filters_by_tech(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    result = runner.invoke(app, ["docs", "--tech", "linux", "--format", "markdown"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "## linux.hostname.sanity" in result.stdout
    assert "mysql.slowqueries.threshold" not in result.stdout


def test_docs_include_exclude(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    result = runner.invoke(
        app,
        [
            "docs",
            "--include",
            "hostname",
            "--exclude",
            "slowqueries",
            "--format",
            "markdown",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    body = result.stdout
    assert "linux.hostname.sanity" in body
    assert "mysql.slowqueries.threshold" not in body


def test_docs_table_format(monkeypatch):
    monkeypatch.chdir(PROJECT_ROOT)
    monkeypatch.setenv("COLUMNS", "180")
    result = runner.invoke(app, ["docs"], catch_exceptions=False)
    assert result.exit_code == 0
    clean = _strip_ansi(result.stdout)
    assert "AuditX Checks" in clean
    assert "Hostname sanity" in clean
