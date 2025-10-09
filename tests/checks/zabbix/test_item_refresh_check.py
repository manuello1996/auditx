from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from auditx.checks.zabbix.item_refresh_check import ZabbixItemRefreshRateCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(items: Sequence[Dict[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    facts_store: Dict[str, Any] = {}
    if items is not None:
        facts_store["zabbix.items"] = list(items)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts_store))


def item(
    name: str,
    delay_seconds: float | None,
    *,
    hosts: List[str] | None = None,
    key: str | None = None,
    delay: str | None = None,
) -> Dict[str, Any]:
    if delay is None:
        delay = str(delay_seconds) if delay_seconds is not None else "{$MACRO}"
    return {
        "id": name,
        "name": name,
        "delay_seconds": delay_seconds,
        "delay": delay,
        "key": key or name,
        "hosts": hosts or [],
    }


def test_skip_when_no_items() -> None:
    ctx = make_ctx(None)
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No item facts" in result.summary


def test_skip_when_only_dependent_items() -> None:
    ctx = make_ctx([
        item("dependent", 0, hosts=["agent-1"], key="system.dependent"),
    ])
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.SKIP
    assert result.details["ignored_zero_delay_items"][0]["name"] == "dependent"


def test_pass_when_all_items_slow_enough() -> None:
    ctx = make_ctx([
        item("cpu", 60, hosts=["agent-1"], key="system.cpu"),
        item("memory", 120, hosts=["agent-2"], key="vm.memory"),
    ])
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.PASS
    assert "slower than" in result.summary
    assert result.details["sample_size"] == 2


def test_fail_when_item_too_fast() -> None:
    ctx = make_ctx(
        [
            item("cpu", 10, hosts=["agent-1"], key="system.cpu"),
            item("memory", 90, hosts=["agent-2"], key="vm.memory"),
        ],
        {"zabbix": {"item_min_refresh_seconds": 60}},
    )
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.FAIL
    assert any(entry["name"] == "cpu" for entry in result.details["offending_items"])
    assert "cpu (hosts: agent-1, key: system.cpu, delay: 10s)" in result.summary


def test_warn_when_item_delay_unknown() -> None:
    ctx = make_ctx([
        item("macro", None, hosts=["agent-1"], key="system.macro", delay="{$UPDATE_INTERVAL}"),
    ])
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.WARN
    assert "non-numeric" in result.summary
    assert "macro" in result.summary


def test_warn_when_missing_hosts() -> None:
    ctx = make_ctx([
        item("orph", 90, hosts=[], key="system.orphan"),
        item("cpu", 90, hosts=["agent-1"], key="system.cpu"),
    ])
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.WARN
    assert "missing host binding" in result.summary
    assert "orph" in result.summary
    assert result.details["sample_size"] == 1


def test_pass_when_item_excluded_by_key() -> None:
    ctx = make_ctx(
        [
            item("uptime", 30, hosts=["agent-1"], key="system.uptime"),
            item("cpu", 90, hosts=["agent-1"], key="system.cpu"),
        ],
        {"zabbix": {"item_refresh_excluded_keys": ["system.uptime"], "item_min_refresh_seconds": 60}},
    )
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.PASS
    assert "uptime" not in result.summary
    assert any(entry["key"] == "system.uptime" for entry in result.details["excluded_items"])
    assert result.details["sample_size"] == 1


def test_skip_when_all_items_excluded() -> None:
    ctx = make_ctx(
        [
            item("uptime", 30, hosts=["agent-1"], key="system.uptime"),
        ],
        {"zabbix": {"item_refresh_excluded_keys": ["system.uptime"], "item_min_refresh_seconds": 60}},
    )
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No items" in result.summary
    assert result.details["excluded_items"][0]["key"] == "system.uptime"


def test_cli_style_comma_separated_exclusions() -> None:
    ctx = make_ctx(
        [
            item("uptime", 30, hosts=["agent-1"], key="system.uptime"),
            item("swap", 30, hosts=["agent-1"], key="system.swap.size"),
            item("cpu", 90, hosts=["agent-1"], key="system.cpu"),
        ],
        {"zabbix": {"item_refresh_excluded_keys": "system.uptime, system.swap.size", "item_min_refresh_seconds": 60}},
    )
    result = ZabbixItemRefreshRateCheck().run(ctx)
    assert result.status is Status.PASS
    excluded_keys = {entry["key"] for entry in result.details["excluded_items"]}
    assert excluded_keys == {"system.uptime", "system.swap.size"}
    assert result.details["sample_size"] == 1