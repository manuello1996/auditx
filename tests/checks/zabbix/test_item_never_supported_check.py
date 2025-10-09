from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from auditx.checks.zabbix.item_never_supported_check import ZabbixItemNeverSupportedCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(items: Sequence[Dict[str, Any]] | None) -> RunContext:
    facts_store: Dict[str, Any] = {}
    if items is not None:
        facts_store["zabbix.items"] = list(items)
    return RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts(facts_store))


def item(
    name: str,
    *,
    state: str,
    status: str,
    last_clock: Any,
    hosts: List[str] | None = None,
    key: str | None = None,
) -> Dict[str, Any]:
    return {
        "id": name,
        "name": name,
        "state": state,
        "status": status,
        "last_clock": last_clock,
        "hosts": hosts or [],
        "key": key or name,
    }


def test_skip_when_no_item_facts() -> None:
    ctx = make_ctx(None)
    result = ZabbixItemNeverSupportedCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No item facts" in result.summary


def test_pass_when_no_never_supported_items() -> None:
    ctx = make_ctx([
        item("cpu", state="0", status="0", last_clock=100, hosts=["agent-1"]),
        item("disk", state="1", status="0", last_clock=1700000000, hosts=["agent-2"]),
    ])
    result = ZabbixItemNeverSupportedCheck().run(ctx)
    assert result.status is Status.PASS
    assert "No enabled not-supported" in result.summary
    assert result.details["never_supported_count"] == 0


def test_fail_when_timestamp_zero() -> None:
    ctx = make_ctx([
        item("cpu", state="1", status="0", last_clock=0, hosts=["agent-1"], key="system.cpu"),
    ])
    result = ZabbixItemNeverSupportedCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "since creation" in result.summary
    assert "cpu" in result.summary
    assert "system.cpu" in result.summary
    assert result.details["never_supported_items"][0]["last_clock"] == 0


def test_ignore_disabled_items() -> None:
    ctx = make_ctx([
        item("cpu", state="1", status="1", last_clock=0, hosts=["agent-1"]),
    ])
    result = ZabbixItemNeverSupportedCheck().run(ctx)
    assert result.status is Status.PASS
    assert result.details["never_supported_count"] == 0


def test_support_string_timestamp_zero() -> None:
    ctx = make_ctx([
        item("cpu", state="1", status="0", last_clock="0", hosts=["agent-1"]),
    ])
    result = ZabbixItemNeverSupportedCheck().run(ctx)
    assert result.status is Status.FAIL
    assert result.details["never_supported_count"] == 1
