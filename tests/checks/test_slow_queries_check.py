from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from auditx.checks.mysql.slow_queries_check import SlowQueriesCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(values: Dict[str, Any]) -> RunContext:
    return RunContext(tech_filter={"mysql"}, config={}, env={}, facts=DummyFacts(values))


def test_slow_queries_pass():
    ctx = make_ctx({"mysql.variables": {"slow_query_log": "ON", "long_query_time": "0.5"}})
    res = SlowQueriesCheck().run(ctx)
    assert res.status is Status.PASS
    assert res.explanation == SlowQueriesCheck.meta.explanation
    assert res.remediation == SlowQueriesCheck.meta.remediation


def test_slow_queries_fail_when_log_disabled():
    ctx = make_ctx({"mysql.variables": {"slow_query_log": "OFF", "long_query_time": "0.5"}})
    res = SlowQueriesCheck().run(ctx)
    assert res.status is Status.FAIL
    assert "disabled" in (res.explanation or "").lower()
    assert (
        res.remediation
        == "Set slow_query_log=ON in my.cnf (mysqld section) and reload MySQL to start capturing samples."
    )


@pytest.mark.parametrize("long_query_time", ["2", "3.5"])
def test_slow_queries_warn_on_threshold(long_query_time: str):
    ctx = make_ctx({"mysql.variables": {"slow_query_log": "ON", "long_query_time": long_query_time}})
    res = SlowQueriesCheck().run(ctx)
    assert res.status is Status.WARN
    assert "above" in (res.explanation or "").lower()
    assert (
        res.remediation
        == "Adjust long_query_time to 1.0 or lower and restart or apply SET GLOBAL long_query_time=1.0."
    )
