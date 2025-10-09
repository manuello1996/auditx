from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from auditx.checks.linux.hostname_check import HostnameCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(values: Dict[str, Any]) -> RunContext:
    return RunContext(tech_filter={"linux"}, config={}, env={}, facts=DummyFacts(values))


def test_hostname_pass_when_valid():
    ctx = make_ctx({"linux.uname": {"node": "valid-host"}})
    res = HostnameCheck().run(ctx)
    assert res.status is Status.PASS
    assert "valid-host" in res.summary
    assert res.explanation == HostnameCheck.meta.explanation
    assert res.remediation == HostnameCheck.meta.remediation


@pytest.mark.parametrize("node,expected", [("", Status.FAIL), ("HOST", Status.WARN)])
def test_hostname_handles_suspicious(node: str, expected: Status):
    ctx = make_ctx({"linux.uname": {"node": node}})
    res = HostnameCheck().run(ctx)
    assert res.status is expected
    assert res.explanation is not None
    assert res.remediation is not None


def test_hostname_skips_when_fact_missing():
    ctx = make_ctx({})
    res = HostnameCheck().run(ctx)
    assert res.status is Status.SKIP
    assert "Missing fact" in res.summary
    assert "linux.uname" in (res.explanation or "")
    assert "discovery" in (res.remediation or "")
