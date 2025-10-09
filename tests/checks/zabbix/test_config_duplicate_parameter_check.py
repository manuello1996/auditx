from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from auditx.checks.zabbix.config_duplicate_parameter_check import ZabbixConfigDuplicateParameterCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:  # pragma: no cover - not used but keeps interface consistent
        return self.values.get(key)


def make_ctx(config: Dict[str, Any]) -> RunContext:
    return RunContext(tech_filter={"zabbix"}, config=config, env={}, facts=DummyFacts({}))


def write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_skip_when_config_file_missing() -> None:
    ctx = make_ctx({})
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "Missing" in result.summary


def test_skip_when_path_does_not_exist(tmp_path: Path) -> None:
    config_file = tmp_path / "zabbix_agentd.conf"
    ctx = make_ctx({"zabbix": {"config_file": str(config_file)}})
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.SKIP
    assert str(config_file) in result.summary


def test_pass_without_duplicates(tmp_path: Path) -> None:
    main = write(
        tmp_path / "zabbix_agentd.conf",
        """
# comment
LogFileSize=10
Include=conf.d/extra.conf
""".strip()
    )
    include_dir = tmp_path / "conf.d"
    include_dir.mkdir()
    write(include_dir / "extra.conf", "Server=example.com\n")

    ctx = make_ctx({"zabbix": {"config_file": str(main)}})
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.PASS
    assert "No duplicate" in result.summary
    assert str(main.resolve()) in result.details["files_scanned"]


def test_fail_when_duplicates_detected(tmp_path: Path) -> None:
    main = write(
        tmp_path / "zabbix_agentd.conf",
        """
Server=first
### Some comment
Server=second
""".strip()
    )

    ctx = make_ctx({"zabbix": {"config_file": str(main)}})
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "Server" in result.summary
    assert "duplicate" in result.summary.lower()
    assert len(result.details["duplicates"]["Server"]) == 2


def test_fail_when_include_overrides_parameter(tmp_path: Path) -> None:
    main = write(
        tmp_path / "zabbix_agentd.conf",
        "Include=conf.d/extra.conf\nServer=primary\n",
    )
    include_dir = tmp_path / "conf.d"
    include_dir.mkdir()
    write(include_dir / "extra.conf", "Server=override\n")

    ctx = make_ctx({"zabbix": {"config_file": str(main)}})
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "Server" in result.details["duplicates"]


def test_pass_when_duplicates_are_allowed(tmp_path: Path) -> None:
    main = write(
        tmp_path / "zabbix_agentd.conf",
        """
UserParameter=foo[*],echo 1
Include=extra.conf
""".strip()
    )
    write(tmp_path / "extra.conf", "UserParameter=bar[*],echo 2\n")

    ctx = make_ctx({
        "zabbix": {
            "config_file": str(main),
            "config_duplicate_ignore_keys": ["UserParameter"],
        }
    })
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.PASS
    assert "duplicates" not in result.details or "UserParameter" not in result.details.get("duplicates", {})


def test_warn_when_include_missing(tmp_path: Path) -> None:
    main = write(
        tmp_path / "zabbix_agentd.conf",
        "Include=missing.conf\nServer=example\n",
    )
    ctx = make_ctx({"zabbix": {"config_file": str(main)}})
    result = ZabbixConfigDuplicateParameterCheck().run(ctx)
    assert result.status is Status.WARN
    assert "Include" in result.summary
    assert "missing.conf" in "".join(result.details["missing_includes"])