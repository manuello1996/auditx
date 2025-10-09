from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

import pytest

from auditx.checks.zabbix.item_unsupported_check import ZabbixItemUnsupportedDurationCheck
from auditx.core.models import RunContext, Status

NOW = 1_000_000.0


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:  # pragma: no cover - simple forwarding helper
        return self.values.get(key)


def make_ctx(items: Sequence[Dict[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    facts_store: Dict[str, Any] = {}
    if items is not None:
        facts_store["zabbix.items"] = list(items)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts_store))


def item(
    name: str,
    *,
    state: str,
    status: str,
    last_clock: float | None,
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


def set_fixed_time(monkeypatch: pytest.MonkeyPatch, value: float) -> None:
    monkeypatch.setattr("auditx.checks.zabbix.item_unsupported_check.time.time", lambda: value)


def test_skip_when_no_item_facts() -> None:
    ctx = make_ctx(None)
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No item facts" in result.summary


def test_pass_when_all_items_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    set_fixed_time(monkeypatch, NOW)
    ctx = make_ctx([
        item("cpu", state="0", status="0", last_clock=NOW - 120, hosts=["agent-1"]),
        item("disk", state="0", status="0", last_clock=NOW - 300, hosts=["agent-2"]),
    ])
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.PASS
    assert result.summary == "No enabled items unsupported longer than 1h"
    assert result.details["unsupported_item_count"] == 0


def test_fail_when_item_unsupported_longer_than_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    set_fixed_time(monkeypatch, NOW)
    ctx = make_ctx([
        item("cpu", state="1", status="0", last_clock=NOW - 90 * 60, hosts=["agent-1"]),
    ])
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "longer than 1h" in result.summary
    assert "cpu" in result.summary
    entry = result.details["long_unsupported_items"][0]
    assert entry["age_minutes"] == pytest.approx(90.0)


def test_pass_when_item_recently_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    set_fixed_time(monkeypatch, NOW)
    ctx = make_ctx([
        item("cpu", state="1", status="0", last_clock=NOW - 30 * 60, hosts=["agent-1"]),
    ])
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.PASS
    assert "recently unsupported" in result.summary
    entry = result.details["recent_unsupported_items"][0]
    assert entry["age_minutes"] == pytest.approx(30.0)


def test_warn_when_timestamp_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    set_fixed_time(monkeypatch, NOW)
    ctx = make_ctx([
        item("cpu", state="1", status="0", last_clock=None, hosts=["agent-1"]),
    ])
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.WARN
    assert "lack a timestamp" in result.summary
    assert result.details["unsupported_without_timestamp"][0]["name"] == "cpu"


def test_threshold_override(monkeypatch: pytest.MonkeyPatch) -> None:
    set_fixed_time(monkeypatch, NOW)
    ctx = make_ctx(
        [
            item("cpu", state="1", status="0", last_clock=NOW - 45 * 60, hosts=["agent-1"]),
        ],
        {"zabbix": {"unsupported_item_threshold_minutes": 30}},
    )
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "longer than 30m" in result.summary


def test_ignore_disabled_items(monkeypatch: pytest.MonkeyPatch) -> None:
    set_fixed_time(monkeypatch, NOW)
    ctx = make_ctx([
        item("cpu", state="1", status="1", last_clock=NOW - 10 * 60, hosts=["agent-1"]),
    ])
    result = ZabbixItemUnsupportedDurationCheck().run(ctx)
    assert result.status is Status.PASS
    assert result.details["unsupported_item_count"] == 0
    assert result.summary == "No enabled items unsupported longer than 1h"
