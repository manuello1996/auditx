from __future__ import annotations

from typer.testing import CliRunner

from auditx.cli import app, cfg


def test_facts_config_option_passes_explicit_files(monkeypatch, tmp_path):
    runner = CliRunner()
    captured: dict[str, object] = {}

    monkeypatch.setattr("auditx.cli.registered_techs", lambda: {"dummy"})

    def fake_collect(tech, params, store, reporter=None):
        store.set_namespace(tech, {f"{tech}.value": 1})

    monkeypatch.setattr("auditx.cli.collect_facts", fake_collect)

    def fake_load_project_config(*_args, **kwargs):
        captured["kwargs"] = kwargs
        return {"dummy": {"method": "local"}}

    monkeypatch.setattr(cfg, "load_project_config", fake_load_project_config)
    monkeypatch.setattr(cfg, "merge_overrides", lambda data, *, vars_file, set_kv, env: data)
    monkeypatch.setattr(cfg, "resolve_secrets", lambda data, *, ask: data)

    config_path = tmp_path / "facts-config.yaml"
    config_path.write_text("dummy: {}\n")

    result = runner.invoke(app, ["facts", "--format", "json", "--config", str(config_path)])

    assert result.exit_code == 0
    assert captured["kwargs"].get("explicit_files") == [config_path]
    assert "dummy.value" in result.stdout
