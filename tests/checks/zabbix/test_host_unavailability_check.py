from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Sequence

import pytest

from auditx.checks.zabbix.host_unavailability_check import ZabbixHostUnavailabilityCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(hosts: Sequence[Dict[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    facts_data = {}
    if hosts is not None:
        facts_data["zabbix.hosts"] = list(hosts)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts_data))


def build_host(
    *,
    name: str,
    available: str,
    status: str = "0",
    unavailable_since: float | None = None,
    agent_errors_from: float | None = None,
    snmp_errors_from: float | None = None,
    agent_disable_until: float | None = None,
) -> Dict[str, Any]:
    availability = {
        "agent": available if available in {"0", "1", "2"} else "0",
        "snmp": "2" if snmp_errors_from else "0",
        "ipmi": "0",
        "jmx": "0",
    }
    interfaces = [
        {
            "type": "agent",
            "available": availability["agent"],
            "errors_from": agent_errors_from,
            "disable_until": agent_disable_until,
            "ip": "",
            "dns": "",
            "port": "10050",
            "error": "",
        }
    ]

    if snmp_errors_from is not None:
        interfaces.append(
            {
                "type": "snmp",
                "available": "2",
                "errors_from": snmp_errors_from,
                "disable_until": None,
                "ip": "",
                "dns": "",
                "port": "161",
                "error": "",
            }
        )

    return {
        "name": name,
        "status": status,
        "available": available,
        "availability": availability,
        "unavailable_since": unavailable_since,
        "errors_from": agent_errors_from,
        "snmp_errors_from": snmp_errors_from,
        "ipmi_errors_from": None,
        "jmx_errors_from": None,
        "interfaces": interfaces,
    }


def test_skip_when_no_facts() -> None:
    ctx = make_ctx(None)
    result = ZabbixHostUnavailabilityCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No host facts" in result.summary


def test_pass_when_all_hosts_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 1_000_000.0)
    hosts = [
        build_host(name="agent-1", available="1"),
        build_host(name="agent-2", available="1"),
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostUnavailabilityCheck().run(ctx)
    assert result.status is Status.PASS
    assert "All" in result.summary


def test_fail_when_unavailable_exceeds_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 1_000_000.0)
    hosts = [
        build_host(
            name="db01",
            available="2",
            unavailable_since=1_000_000.0 - 200_000.0,
            agent_errors_from=1_000_000.0 - 200_000.0,
        ),
        build_host(name="api01", available="1"),
    ]
    ctx = make_ctx(hosts, {"zabbix": {"hosts_unavailable_threshold_hours": 24}})
    result = ZabbixHostUnavailabilityCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "unavailable longer" in result.summary
    assert result.details["offenders"][0]["name"] == "db01"
    assert "db01 (55.56h)" in result.summary
    assert "api01" not in result.summary


def test_warn_when_unavailable_but_within_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 5_000.0)
    hosts = [
        build_host(
            name="web01",
            available="2",
            unavailable_since=5_000.0 - 3_600.0,
            agent_errors_from=5_000.0 - 3_600.0,
        )
    ]
    ctx = make_ctx(hosts, {"zabbix": {"hosts_unavailable_threshold_hours": 24}})
    result = ZabbixHostUnavailabilityCheck().run(ctx)
    assert result.status is Status.WARN
    assert "within" in result.summary
    assert "web01 (1h)" in result.summary


def test_warn_when_timestamp_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 10_000.0)
    hosts = [
        build_host(name="metric01", available="2", agent_errors_from=None)
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostUnavailabilityCheck().run(ctx)
    assert result.status is Status.WARN
    assert "timestamp" in result.summary
    assert "metric01" in result.summary


def test_fail_ignores_future_disable_until(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 2_000_000.0
    monkeypatch.setattr(time, "time", lambda: now)
    hosts = [
        build_host(
            name="router01",
            available="2",
            unavailable_since=now - 200_000.0,
            agent_errors_from=now - 200_000.0,
            agent_disable_until=now + 10_000.0,
        )
    ]
    ctx = make_ctx(hosts, {"zabbix": {"hosts_unavailable_threshold_hours": 24}})
    result = ZabbixHostUnavailabilityCheck().run(ctx)
    assert result.status is Status.FAIL
    assert result.details["offenders"][0]["name"] == "router01"
    assert "router01" in result.summary