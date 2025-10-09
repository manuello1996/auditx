from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence

from auditx.checks.zabbix.host_encryption_check import ZabbixHostEncryptionCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:  # pragma: no cover - helper only
        return self.values.get(key)


def make_ctx(hosts: Sequence[Mapping[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    fact_values: Dict[str, Any] = {}
    if hosts is not None:
        fact_values["zabbix.hosts"] = list(hosts)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(fact_values))


def host(name: str, *, tls_connect: int | None, monitored_by: str | None = None, templates: Iterable[str] | None = None) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "id": name,
        "name": name,
        "tls_connect": tls_connect,
    }
    if monitored_by is not None:
        record["monitored_by"] = monitored_by
    if templates is not None:
        record["template_ids"] = list(templates)
    return record


def test_skip_when_no_hosts() -> None:
    ctx = make_ctx(None)
    result = ZabbixHostEncryptionCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No host facts" in result.summary


def test_pass_when_all_hosts_encrypted() -> None:
    hosts = [
        host("proxy-1", tls_connect=2, monitored_by="1", templates=["10001"]),
        host("server-1", tls_connect=4, monitored_by="0"),
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostEncryptionCheck().run(ctx)
    assert result.status is Status.PASS
    assert "encrypted" in result.summary.lower()
    assert result.details["evaluated_hosts"] == 2
    assert result.details["unencrypted_hosts"] == []


def test_fail_when_unencrypted_hosts_present() -> None:
    hosts = [
        host("legacy", tls_connect=1, monitored_by="0"),
        host("secure", tls_connect=2, monitored_by="1"),
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostEncryptionCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "without encryption" in result.summary.lower()
    assert "legacy" in result.summary
    assert len(result.details["unencrypted_hosts"]) == 1
    offending = result.details["unencrypted_hosts"][0]
    assert offending["name"] == "legacy"
    assert offending["tls_connect"] == 1


def test_warn_when_tls_mode_unknown() -> None:
    hosts = [
        host("mystery", tls_connect=None),
        host("strange", tls_connect=7),
    ]
    ctx = make_ctx(hosts)
    result = ZabbixHostEncryptionCheck().run(ctx)
    assert result.status is Status.WARN
    assert "unknown" in result.summary.lower()
    assert "mystery" in result.summary
    assert "strange" in result.summary
    assert len(result.details["unknown_hosts"]) == 2


def test_skip_when_all_hosts_ignored() -> None:
    hosts = [
        host("legacy", tls_connect=1),
        host("secure", tls_connect=2),
    ]
    ctx = make_ctx(hosts, {"zabbix": {"host_encryption_ignore_hosts": "legacy, secure"}})
    result = ZabbixHostEncryptionCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No hosts evaluated" in result.summary
    assert result.details["evaluated_hosts"] == 0
    assert sorted(result.details["ignored_hosts"]) == ["legacy", "secure"]