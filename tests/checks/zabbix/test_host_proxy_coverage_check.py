from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Sequence

import pytest

from auditx.checks.zabbix.host_proxy_coverage_check import ZabbixHostProxyCoverageCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(hosts: Sequence[Dict[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    facts_dict: Dict[str, Any] = {}
    if hosts is not None:
        facts_dict["zabbix.hosts"] = list(hosts)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts_dict))


def host(
    name: str,
    *,
    status: str = "0",
    proxy_ids: Sequence[str] | None = None,
    proxy_group_ids: Sequence[str] | None = None,
    monitored_by: str | None = None,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "id": name,
        "name": name,
        "status": status,
    }
    if proxy_ids is not None:
        record["proxy_ids"] = list(proxy_ids)
    if proxy_group_ids is not None:
        record["proxy_group_ids"] = list(proxy_group_ids)
    if monitored_by is not None:
        record["monitored_by"] = monitored_by
    return record


def test_skip_when_no_hosts() -> None:
    ctx = make_ctx(None)
    result = ZabbixHostProxyCoverageCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No host facts" in result.summary


def test_pass_when_ratio_within_threshold() -> None:
    hosts = [
        host("server-host", monitored_by="0"),
        host("proxy-host-1", proxy_ids=["2001"], monitored_by="1"),
        host("proxy-host-2", proxy_group_ids=["3001"], monitored_by="2"),
        host("proxy-host-3", proxy_ids=["2002"], monitored_by="1"),
        host("proxy-host-4", proxy_ids=["2003"], monitored_by="1"),
        host("proxy-host-5", proxy_group_ids=["3002"], monitored_by="2"),
        host("proxy-host-6", proxy_ids=["2004"], monitored_by="1"),
        host("proxy-host-7", proxy_group_ids=["3003"], monitored_by="2"),
        host("proxy-host-8", proxy_ids=["2005"], monitored_by="1"),
        host("proxy-host-9", proxy_ids=["2006"], monitored_by="1"),
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostProxyCoverageCheck().run(ctx)
    assert result.status is Status.PASS
    assert "within the allowed" in result.summary
    assert result.details["server_monitored_ratio"] == pytest.approx(0.1)


def test_fail_when_server_ratio_exceeds_threshold() -> None:
    hosts = [
        host("server-1", monitored_by="0"),
        host("server-2", monitored_by="0"),
        host("server-3", monitored_by="0"),
        host("proxy-1", proxy_ids=["2001"], monitored_by="1"),
    ]
    ctx = make_ctx(hosts, {"zabbix": {"server_monitored_ratio_threshold": 0.25}})
    result = ZabbixHostProxyCoverageCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "exceeding the allowed" in result.summary
    assert result.details["server_monitored_ratio"] == pytest.approx(0.75)
    assert result.details["allowed_ratio"] == pytest.approx(0.25)


def test_warn_when_unknown_monitoring() -> None:
    hosts = [
        host("server", monitored_by="0"),
        host("mystery", monitored_by=""),
        host("proxy", proxy_ids=["2001"], monitored_by="1"),
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostProxyCoverageCheck().run(ctx)
    assert result.status is Status.WARN
    assert "unknown monitoring topology" in result.summary
    assert result.details["unknown_hosts"] == ["mystery"]