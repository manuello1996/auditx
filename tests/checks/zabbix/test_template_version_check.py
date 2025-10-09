from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence

from auditx.checks.zabbix.template_version_check import ZabbixTemplateVersionCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:  # pragma: no cover
        return self.values.get(key)


def make_ctx(
    templates: Sequence[Mapping[str, Any]] | None,
    config: Dict[str, Any] | None = None,
    *,
    server_version: str | None = "7.0.0",
) -> RunContext:
    facts: Dict[str, Any] = {}
    if templates is not None:
        facts["zabbix.templates"] = list(templates)
    if server_version is not None:
        facts["zabbix.api.version"] = server_version
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts))


def template(
    name: str,
    *,
    version: str | None,
    groups: Iterable[Mapping[str, Any]] | None = None,
    vendor_name: str | None = "Zabbix",
    raw_version: str | None = None,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "id": name,
        "name": name,
    }
    if raw_version is not None:
        record["version"] = raw_version
    if version is not None:
        record["vendor_version"] = version
    if vendor_name is not None:
        record["vendor_name"] = vendor_name
    if groups is not None:
        record["groups"] = list(groups)
    return record


def test_skip_when_no_templates() -> None:
    ctx = make_ctx(None)
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No template facts" in result.summary


def test_pass_when_all_templates_align_with_server() -> None:
    ctx = make_ctx([
        template("Template OS Linux", version="7.0-0"),
        template("Template App HTTPS", version="7.2-0"),
    ], server_version="7.0.0")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.PASS
    assert "Zabbix server 7.0.0" in result.summary


def test_fail_when_version_old_but_missing_ignored() -> None:
    ctx = make_ctx([
        template("Old Template", version="6.2-5"),
        template("Legacy Template", version=None),
        template("Modern Template", version="6.4-3"),
    ], server_version="7.0.0")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.FAIL
    assert {entry["name"] for entry in result.details["outdated_templates"]} == {
        "Old Template",
        "Modern Template",
    }
    assert result.details["ignored_templates_no_version"][0]["name"] == "Legacy Template"
    assert result.details["outdated_template_names"] == ["Old Template (6.2-5)", "Modern Template (6.4-3)"]
    assert "older than Zabbix server 7.0.0" in result.summary
    assert "Old Template (6.2-5)" in result.summary


def test_skip_when_only_templates_without_version() -> None:
    ctx = make_ctx([
        template("Custom Template", version=None),
        template("Another", version=None),
    ], server_version="7.0.0")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No templates evaluated" in result.summary
    assert len(result.details["ignored_templates_no_version"]) == 2


def test_warn_when_version_unparsable() -> None:
    ctx = make_ctx([
        template("Custom Template", version="custom"),
    ], server_version="7.0.0")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.WARN
    assert "non-standard" in result.summary
    assert result.details["unparsable_templates"][0]["name"] == "Custom Template"


def test_skip_when_all_templates_ignored() -> None:
    ctx = make_ctx([
        template("Old Template", version="6.0-0"),
    ], {"zabbix": {"template_version_ignore": "Old Template"}}, server_version="7.0.0")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.SKIP
    assert result.details["evaluated_templates"] == 0
    assert result.details["ignored_templates"] == ["old template"]

def test_fail_when_server_minor_higher() -> None:
    ctx = make_ctx([
        template("Latest Template", version="7.4-0"),
        template("Slightly Old", version="7.0-0"),
    ], server_version="7.3.1")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "older than Zabbix server 7.3.1" in result.summary
    assert result.details["outdated_templates"][0]["name"] == "Slightly Old"
    assert result.details["outdated_template_names"] == ["Slightly Old (7.0-0)"]
    assert "Slightly Old (7.0-0)" in result.summary


def test_skip_when_server_version_missing() -> None:
    ctx = make_ctx([
        template("Template", version="7.0-0"),
    ], server_version=None)
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "server version is unavailable" in result.summary


def test_fail_when_template_version_has_suffix() -> None:
    ctx = make_ctx([
        template("Custom Template", version="custom build 6.4-0 beta"),
        template("Modern", version="7.4-1"),
    ], server_version="7.4.2")
    result = ZabbixTemplateVersionCheck().run(ctx)
    assert result.status is Status.FAIL
    names = {entry["name"] for entry in result.details["outdated_templates"]}
    assert "Custom Template" in names
    assert result.details["outdated_template_names"] == ["Custom Template (custom build 6.4-0 beta)"]
    assert "Custom Template (custom build 6.4-0 beta)" in result.summary