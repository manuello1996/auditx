from __future__ import annotations

from pathlib import Path

import pytest

from auditx.core import config as cfg


def _patch_home(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: path))


def test_load_project_config_prefers_local_over_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    home_cfg_dir = home / ".auditx"
    home_cfg_dir.mkdir(parents=True)
    (home_cfg_dir / "base.yaml").write_text("mysql:\n  host: home-value\n")

    work = tmp_path / "work"
    work.mkdir()
    local_cfg_dir = work / "config"
    local_cfg_dir.mkdir()
    (local_cfg_dir / "override.yaml").write_text("mysql:\n  host: local-value\n")

    _patch_home(monkeypatch, home)
    monkeypatch.chdir(work)
    monkeypatch.delenv("AUDITX_CONFIG_DIR", raising=False)

    loaded = cfg.load_project_config()
    assert loaded["mysql"]["host"] == "local-value"


def test_load_project_config_uses_env_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _patch_home(monkeypatch, home)

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)

    env_dir = tmp_path / "shared"
    env_dir.mkdir()
    (env_dir / "settings.yaml").write_text("mysql:\n  host: env-value\n")

    monkeypatch.setenv("AUDITX_CONFIG_DIR", str(env_dir))

    loaded = cfg.load_project_config()
    assert loaded["mysql"]["host"] == "env-value"


def test_load_default_template_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _patch_home(monkeypatch, home)

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.delenv("AUDITX_CONFIG_DIR", raising=False)

    template = cfg.load_default_template()

    assert template["mysql"]["host"] == "db1.example.com"
    assert template["zabbix"]["config_file"] == "/etc/zabbix/zabbix_server.conf"
