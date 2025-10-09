from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

import pytest

from auditx.checks.zabbix.lld_refresh_check import ZabbixLLDRefreshRateCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(rules: Sequence[Dict[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    facts_dict: Dict[str, Any] = {}
    if rules is not None:
        facts_dict["zabbix.discovery_rules"] = list(rules)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts_dict))


def rule(name: str, delay_seconds: float | None, *, hosts: List[str] | None = None) -> Dict[str, Any]:
    return {
        "id": name,
        "name": name,
        "delay_seconds": delay_seconds,
        "delay": str(delay_seconds) if delay_seconds is not None else "{$MACRO}",
        "hosts": hosts or [],
    }


def test_skip_when_no_rules() -> None:
    ctx = make_ctx(None)
    result = ZabbixLLDRefreshRateCheck().run(ctx)
    assert result.status is Status.SKIP


def test_skip_when_only_dependent_rules() -> None:
    ctx = make_ctx([
        rule("dependent-agent", 0, hosts=["agent-1"]),
    ])
    result = ZabbixLLDRefreshRateCheck().run(ctx)
    assert result.status is Status.SKIP
    assert result.details["sample_size"] == 0
    assert result.details["ignored_zero_delay_rules"][0]["name"] == "dependent-agent"


def test_pass_when_all_rules_slow_enough() -> None:
    ctx = make_ctx([
        rule("filesystem", 3600, hosts=["agent-1"]),
        rule("ports", 7200, hosts=["agent-2"]),
    ])
    result = ZabbixLLDRefreshRateCheck().run(ctx)
    assert result.status is Status.PASS
    assert "slower than" in result.summary
    assert result.details["sample_size"] == 2
    assert result.details["ignored_zero_delay_rules"] == []


def test_fail_when_rule_too_fast() -> None:
    ctx = make_ctx(
        [
            rule("filesystem", 1800, hosts=["agent-1"]),
            rule("ports", 3600, hosts=["agent-2"]),
        ],
        {"zabbix": {"lld_min_refresh_seconds": 3600}},
    )
    result = ZabbixLLDRefreshRateCheck().run(ctx)
    assert result.status is Status.FAIL
    assert any(r["name"] == "filesystem" for r in result.details["offending_rules"])
    assert result.details["sample_size"] == 2
    assert "filesystem (hosts: agent-1, delay: 30m)" in result.summary
    assert "ports" not in result.summary


def test_warn_when_rule_delay_unknown() -> None:
    ctx = make_ctx([
        rule("macro-driven", None, hosts=["agent-1"]),
    ])
    result = ZabbixLLDRefreshRateCheck().run(ctx)
    assert result.status is Status.WARN
    assert "non-numeric" in result.summary
    assert result.details["ignored_zero_delay_rules"] == []
    assert "macro-driven" in result.summary