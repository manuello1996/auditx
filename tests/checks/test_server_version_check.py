from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from auditx.checks.zabbix.server_version_check import ZabbixVersionCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(values: Dict[str, Any]) -> RunContext:
    return RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts(values))


@pytest.mark.parametrize("version", ["6.0.0", "6.2"])
def test_zabbix_version_pass(version: str):
    ctx = make_ctx({"zabbix.api.version": version})
    res = ZabbixVersionCheck().run(ctx)
    assert res.status is Status.PASS
    assert res.explanation == ZabbixVersionCheck.meta.explanation
    assert res.remediation == ZabbixVersionCheck.meta.remediation


@pytest.mark.parametrize("version", ["5.4", "4.0"])
def test_zabbix_version_warn(version: str):
    ctx = make_ctx({"zabbix.api.version": version})
    res = ZabbixVersionCheck().run(ctx)
    assert res.status is Status.WARN
    assert "support" in (res.explanation or "").lower()
    assert (
        res.remediation
        == "Plan an in-place upgrade to 6.0+ and document API changes for integrations."
    )
