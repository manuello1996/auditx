from __future__ import annotations

from auditx.checks.zabbix.poller_utilization_check import (
    POLLER_DISPLAY_NAMES,
    ZabbixPollerUtilizationCheck,
)
from auditx.core.facts import FactStore
from auditx.core.models import RunContext, Status


def make_ctx(poller_data: dict | None = None, config: dict | None = None) -> RunContext:
    facts = FactStore()
    if poller_data is not None:
        facts.set_namespace("zabbix", {"zabbix.process.pollers": poller_data})
    return RunContext(
        tech_filter={"zabbix"},
        config=config or {},
        env={},
        facts=facts,
    )


def test_poller_utilization_skip_no_facts():
    ctx = make_ctx(poller_data=None)
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No poller process facts collected" in result.summary


def test_poller_utilization_skip_invalid_structure():
    ctx = make_ctx(poller_data="invalid")
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "Unexpected poller process facts structure" in result.summary


def test_poller_utilization_skip_no_valid_data():
    poller_data = {
        "poller": "not a dict",
        "snmp_poller": {"missing_busy": 10.0},
    }
    ctx = make_ctx(poller_data=poller_data)
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No valid poller utilization data" in result.summary


def test_poller_utilization_pass_all_within_range():
    poller_data = {
        "poller": {"busy_percent": 45.0},
        "snmp_poller": {"busy_percent": 55.0},
        "http_poller": {"busy_percent": 50.0},
    }
    ctx = make_ctx(poller_data=poller_data)
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.PASS
    assert "All 3 Zabbix poller processes" in result.summary
    assert result.details["problem_pollers"] == 0
    assert not result.details["problems"]


def test_poller_utilization_fail_over_utilized():
    poller_data = {
        "poller": {"busy_percent": 82.0},
        "snmp_poller": {"busy_percent": 60.0},
    }
    ctx = make_ctx(poller_data=poller_data)
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.WARN
    assert "poller utilization issues" in result.summary
    assert "1 out of 2 poller processes" in result.summary
    poller_label = POLLER_DISPLAY_NAMES["poller"]
    assert f"{poller_label}: 82.0% (over-utilized)" in result.summary
    assert result.details["pollers"]["poller"]["status"] == "over-utilized"
    assert result.details["pollers"]["poller"]["display_name"] == poller_label
    assert result.details["pollers"]["snmp_poller"]["status"] == "ok"
    assert result.remediation is not None


def test_poller_utilization_custom_thresholds():
    poller_data = {
        "poller": {"busy_percent": 5.0},
    }
    config = {
        "zabbix.pollers.min_busy_percent": 10.0,
        "zabbix.pollers.max_busy_percent": 60.0,
    }
    ctx = make_ctx(poller_data=poller_data, config=config)
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.WARN
    poller_label = POLLER_DISPLAY_NAMES["poller"]
    assert f"{poller_label}: 5.0% (under-utilized)" in result.summary
    assert result.details["problems"] == [f"{poller_label}: 5.0% (under-utilized)"]


def test_poller_utilization_invalid_thresholds():
    poller_data = {
        "poller": {"busy_percent": 40.0},
    }
    config = {
        "zabbix.pollers.min_busy_percent": 80.0,
        "zabbix.pollers.max_busy_percent": 60.0,
    }
    ctx = make_ctx(poller_data=poller_data, config=config)
    result = ZabbixPollerUtilizationCheck().run(ctx)
    assert result.status is Status.ERROR
    assert "Invalid configuration" in result.summary
