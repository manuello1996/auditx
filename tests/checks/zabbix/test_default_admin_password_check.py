from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from auditx.checks.zabbix.default_admin_password_check import DefaultAdminPasswordCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(value: Any) -> RunContext:
    facts: Dict[str, Any] = {}
    if value is not None:
        facts["zabbix.admin.default_password_valid"] = value
    return RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts(facts))


def test_skip_when_fact_missing() -> None:
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts({}))
    result = DefaultAdminPasswordCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "Unable to determine" in result.summary


def test_error_when_fact_not_boolean() -> None:
    ctx = make_ctx("yes")
    result = DefaultAdminPasswordCheck().run(ctx)
    assert result.status is Status.ERROR
    assert "Unexpected fact format" in result.summary


def test_fail_when_default_password_active() -> None:
    ctx = make_ctx(True)
    result = DefaultAdminPasswordCheck().run(ctx)
    assert result.status is Status.FAIL
    assert result.details["default_password_accepted"] is True
    assert "factory password" in result.summary


def test_pass_when_default_password_disabled() -> None:
    ctx = make_ctx(False)
    result = DefaultAdminPasswordCheck().run(ctx)
    assert result.status is Status.PASS
    assert result.details["default_password_accepted"] is False
    assert "has been changed" in result.summary


def test_skip_includes_warning_detail() -> None:
    facts = DummyFacts({"zabbix.warning.admin_default_password": "API unavailable"})
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    result = DefaultAdminPasswordCheck().run(ctx)
    assert result.status is Status.SKIP
    assert result.details["warning"] == "API unavailable"