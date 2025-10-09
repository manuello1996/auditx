from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from auditx.checks.zabbix.trigger_unknown_check import ZabbixTriggerUnknownStateCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:  # pragma: no cover - simple proxy
        return self.values.get(key)


def make_ctx(triggers: Sequence[Dict[str, Any]] | None) -> RunContext:
    facts_dict: Dict[str, Any] = {}
    if triggers is not None:
        facts_dict["zabbix.triggers"] = list(triggers)
    return RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts(facts_dict))


def trigger(
    name: str,
    *,
    state: str,
    hosts: List[str] | None = None,
    status: str = "0",
    value: str = "0",
) -> Dict[str, Any]:
    return {
        "id": name,
        "name": name,
        "state": state,
        "status": status,
        "value": value,
        "priority": 3,
        "hosts": hosts or [],
    }


def test_skip_when_no_trigger_facts() -> None:
    ctx = make_ctx(None)
    result = ZabbixTriggerUnknownStateCheck().run(ctx)
    assert result.status is Status.SKIP


def test_pass_when_no_unknown_triggers() -> None:
    ctx = make_ctx([
        trigger("cpu", state="0", hosts=["agent-1"], value="0"),
    ])
    result = ZabbixTriggerUnknownStateCheck().run(ctx)
    assert result.status is Status.PASS
    assert result.summary == "No triggers reported in unknown state"
    assert result.details["unknown_trigger_count"] == 0


def test_warn_lists_unknown_triggers() -> None:
    ctx = make_ctx([
        trigger("cpu", state="1", hosts=["agent-1"], value="0"),
        trigger("disk", state="1", hosts=[], value="1"),
    ])
    result = ZabbixTriggerUnknownStateCheck().run(ctx)
    assert result.status is Status.WARN
    assert "2 trigger(s) currently in unknown state" in result.summary
    assert "cpu (hosts: agent-1)" in result.summary
    assert "disk" in result.summary
    assert result.details["unknown_trigger_count"] == 2
    assert result.details["unknown_triggers"][0]["name"] == "cpu"