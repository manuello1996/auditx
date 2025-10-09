from __future__ import annotations

from typer.testing import CliRunner

from auditx.cli import app, cfg
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class _DummyCheck(BaseCheck):
    meta = CheckMeta(
        id="dummy.check",
        name="Dummy",
        version="1.0.0",
        tech="dummy",
        severity=Severity.LOW,
        tags=set(),
        description="Ensure dummy check wiring.",
        inputs=(),
        required_facts=(),
        explanation="Dummy explanation",
        remediation="Dummy remediation",
    )

    def run(self, ctx: RunContext) -> CheckResult:  # pragma: no cover - never executed in this test
        return CheckResult(meta=self.meta, status=Status.PASS, summary="ok")


def test_run_with_unknown_include_skips_provider_collection(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    def forbidden_collect(*_args, **_kwargs):  # pragma: no cover - should not run
        raise AssertionError("collect_facts must not be called when no checks match")

    def forbidden_config(*_args, **_kwargs):  # pragma: no cover - should not run
        raise AssertionError("config loading must not occur when no checks match")

    monkeypatch.setattr("auditx.cli.collect_facts", forbidden_collect)
    monkeypatch.setattr(cfg, "load_project_config", forbidden_config)
    monkeypatch.setattr("auditx.cli.registered_techs", lambda: set())

    result = runner.invoke(app, ["run", "--include", "missing", "--no-color"])

    assert result.exit_code == 0
    assert "No checks matched the requested --include filters" in result.stdout


def test_run_list_checks(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    def forbidden_collect(*_args, **_kwargs):  # pragma: no cover - should not run
        raise AssertionError("collect_facts must not be called when listing checks")

    def forbidden_config(*_args, **_kwargs):  # pragma: no cover - should not run
        raise AssertionError("config loading must not occur when listing checks")

    monkeypatch.setattr("auditx.cli.collect_facts", forbidden_collect)
    monkeypatch.setattr(cfg, "load_project_config", forbidden_config)
    monkeypatch.setattr("auditx.cli.registered_techs", lambda: set())

    result = runner.invoke(app, ["run", "--list-checks", "--no-color"])

    assert result.exit_code == 0
    assert "dummy.check" in result.stdout


def test_run_outputs_elapsed_time_by_default(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])
    monkeypatch.setattr("auditx.cli.collect_facts", lambda *args, **kwargs: None)
    monkeypatch.setattr(cfg, "load_project_config", lambda *_args, **_kwargs: {"dummy": {}})
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)
    monkeypatch.setattr("auditx.cli.run_all", lambda *_args, **_kwargs: [
        CheckResult(meta=_DummyCheck.meta, status=Status.PASS, summary="ok")
    ])

    result = runner.invoke(
        app,
        ["run", "--tech", "dummy", "--no-parallel", "--no-color"],
    )

    assert result.exit_code == 0
    assert "Elapsed time:" in result.stdout


def test_run_no_show_duration_disables_elapsed_output(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])
    monkeypatch.setattr("auditx.cli.collect_facts", lambda *args, **kwargs: None)
    monkeypatch.setattr(cfg, "load_project_config", lambda *_args, **_kwargs: {"dummy": {}})
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)
    monkeypatch.setattr("auditx.cli.run_all", lambda *_args, **_kwargs: [
        CheckResult(meta=_DummyCheck.meta, status=Status.PASS, summary="ok")
    ])

    result = runner.invoke(
        app,
        [
            "run",
            "--tech",
            "dummy",
            "--no-parallel",
            "--no-color",
            "--no-show-duration",
        ],
    )

    assert result.exit_code == 0
    assert "Elapsed time:" not in result.stdout


def test_run_progress_option_emits_messages(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])
    monkeypatch.setattr("auditx.cli.collect_facts", lambda *args, **kwargs: None)
    monkeypatch.setattr(cfg, "load_project_config", lambda *_args, **_kwargs: {"dummy": {}})
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)
    monkeypatch.setattr("auditx.cli.run_all", lambda *_args, **_kwargs: [
        CheckResult(meta=_DummyCheck.meta, status=Status.PASS, summary="ok")
    ])

    result = runner.invoke(
        app,
        [
            "run",
            "--tech",
            "dummy",
            "--no-parallel",
            "--no-color",
            "--progress",
        ],
    )

    assert result.exit_code == 0
    assert "Collecting facts for 'dummy'" in result.stdout
    assert "Summary:" in result.stdout


def test_run_progress_reports_fact_steps(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])

    def fake_collect(_tech, _params, _store, reporter=None):
        if reporter:
            reporter("Step one")
            reporter("Step two")

    monkeypatch.setattr("auditx.cli.collect_facts", fake_collect)
    monkeypatch.setattr(cfg, "load_project_config", lambda *_args, **_kwargs: {"dummy": {}})
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)
    monkeypatch.setattr(
        "auditx.cli.run_all",
        lambda *_args, **_kwargs: [CheckResult(meta=_DummyCheck.meta, status=Status.PASS, summary="ok")],
    )

    result = runner.invoke(
        app,
        [
            "run",
            "--tech",
            "dummy",
            "--no-parallel",
            "--no-color",
            "--progress",
        ],
    )

    assert result.exit_code == 0
    assert "Collecting facts for 'dummy' – Step one" in result.stdout
    assert "Collecting facts for 'dummy' – Step two" in result.stdout


def test_run_includes_explanation_and_remediation_in_details(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])
    monkeypatch.setattr("auditx.cli.collect_facts", lambda *args, **kwargs: None)
    monkeypatch.setattr(cfg, "load_project_config", lambda *_args, **_kwargs: {"dummy": {}})
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)
    monkeypatch.setattr(
        "auditx.cli.run_all",
        lambda *_args, **_kwargs: [
            CheckResult(
                meta=_DummyCheck.meta,
                status=Status.FAIL,
                summary="failure",
                explanation="Because",
                remediation="Fix it",
            )
        ],
    )

    result = runner.invoke(
        app,
        [
            "run",
            "--tech",
            "dummy",
            "--no-parallel",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert "Because" in result.stdout
    assert "Remediation: Fix it" in result.stdout


def test_run_config_option_passes_explicit_files(monkeypatch, tmp_path):
    runner = CliRunner()
    captured: dict[str, object] = {}

    monkeypatch.setattr("auditx.cli.iter_local_checks", lambda: [_DummyCheck])
    monkeypatch.setattr("auditx.cli.iter_entrypoint_checks", lambda: [])
    monkeypatch.setattr("auditx.cli.collect_facts", lambda *args, **kwargs: None)

    def fake_load_project_config(*_args, **kwargs):
        captured["kwargs"] = kwargs
        return {"dummy": {"method": "local"}}

    monkeypatch.setattr(cfg, "load_project_config", fake_load_project_config)
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)
    monkeypatch.setattr(
        "auditx.cli.run_all",
        lambda *_args, **_kwargs: [CheckResult(meta=_DummyCheck.meta, status=Status.PASS, summary="ok")],
    )

    custom_config = tmp_path / "custom.yaml"
    custom_config.write_text("dummy: {}\n")

    result = runner.invoke(
        app,
        [
            "run",
            "--tech",
            "dummy",
            "--no-parallel",
            "--no-color",
            "--config",
            str(custom_config),
        ],
    )

    assert result.exit_code == 0
    assert captured["kwargs"].get("explicit_files") == [custom_config]