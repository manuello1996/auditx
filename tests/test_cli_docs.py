from __future__ import annotations

import json
import re

from typer.testing import CliRunner

from auditx.cli import app
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class _DocCheck(BaseCheck):
    """Dummy check for docs testing."""

    meta = CheckMeta(
        id="dummy.docs",
        name="Docs Dummy",
        version="1.0.0",
        tech="dummy",
        severity=Severity.MEDIUM,
        tags={"test"},
        description="Ensure docs output includes all advisory fields.",
        explanation="This is why the check matters.",
        remediation="Take this remediation step.",
    )

    def run(self, ctx: RunContext):  # pragma: no cover - not needed for docs tests
        return CheckResult(meta=self.meta, status=Status.PASS, summary="ok")


def test_docs_markdown_includes_fields(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DocCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    result = runner.invoke(app, ["docs", "--format", "markdown"])

    assert result.exit_code == 0
    output = result.stdout
    assert "**Explanation:** This is why the check matters." in output
    assert "**Remediation:** Take this remediation step." in output
    assert "### Guidance" not in output
    assert "### Docstring" not in output


def test_docs_table_includes_columns(monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv("COLUMNS", "200")

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DocCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    result = runner.invoke(app, ["docs", "--format", "table"])  # rich table output captured as text

    assert result.exit_code == 0
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    # Header columns
    assert "Explanation" in output
    assert "Remediation" in output
    # Row content
    assert "This is why the check matters." in output
    assert "Take this remediation step." in output
    assert "Why:" not in output


def test_docs_json_includes_advisory_fields(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DocCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    result = runner.invoke(app, ["docs", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert payload
    entry = payload[0]
    assert entry["explanation"] == "This is why the check matters."
    assert entry["remediation"] == "Take this remediation step."
    assert "guidance" not in entry
    assert "docstring" not in entry


def test_docs_html_includes_card_content(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DocCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    result = runner.invoke(app, ["docs", "--format", "html"])

    assert result.exit_code == 0
    output = result.stdout
    assert "<!DOCTYPE html>" in output
    assert "AuditX Checks Documentation" in output
    assert "Docs Dummy" in output
    assert "This is why the check matters." in output
    assert "Take this remediation step." in output
    assert "Docstring" not in output


def test_docs_config_option_passes_explicit_files(monkeypatch, tmp_path):
    runner = CliRunner()
    captured: dict[str, object] = {}

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DocCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    def fake_load(*_args, **kwargs):
        captured["kwargs"] = kwargs
        return {}

    monkeypatch.setattr("auditx.cli.cfg.load_project_config", fake_load)

    config_path = tmp_path / "docs-config.yaml"
    config_path.write_text("dummy: {}\n")

    result = runner.invoke(app, ["docs", "--format", "json", "--config", str(config_path)])

    assert result.exit_code == 0
    assert captured["kwargs"].get("explicit_files") == [config_path]