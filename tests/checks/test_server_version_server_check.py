from auditx.checks.zabbix.server_version_server_check import ZabbixServerVersionCheck
from auditx.core.models import RunContext, Status
from dataclasses import dataclass
from typing import Any, Dict
import pytest

@dataclass
class DummyFacts:
    values: Dict[str, Any]
    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)

def make_ctx(values: Dict[str, Any]) -> RunContext:
    return RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts(values))

def test_zabbix_server_version_pass():
    ctx = make_ctx({"zabbix.server.version": "6.0.1"})
    res = ZabbixServerVersionCheck().run(ctx)
    assert res.status is Status.PASS
    assert res.summary.startswith("Zabbix server version is 6.0.1")

def test_zabbix_server_version_warn():
    ctx = make_ctx({"zabbix.server.version": "5.4.0"})
    res = ZabbixServerVersionCheck().run(ctx)
    assert res.status is Status.WARN
    assert "prior to 6.0" in (res.explanation or "")
    assert res.remediation == "Plan an in-place upgrade to Zabbix server 6.0+ and document any configuration changes."
