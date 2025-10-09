from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


@dataclass(frozen=True)
class HostRecord:
    """Minimal representation of a host encryption state."""

    id: str
    name: str
    tls_connect: int | None
    monitored_by: str | None
    source: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "HostRecord":
        identifier = str(payload.get("id") or payload.get("hostid") or payload.get("name") or "")
        name = str(payload.get("name") or payload.get("host") or identifier)
        tls_raw = payload.get("tls_connect")
        tls_connect: int | None
        try:
            tls_connect = int(tls_raw) if tls_raw is not None else None
        except (TypeError, ValueError):
            tls_connect = None
        monitored_by = str(payload.get("monitored_by") or "") or None
        return cls(id=identifier, name=name, tls_connect=tls_connect, monitored_by=monitored_by, source=payload)


class ZabbixHostEncryptionCheck(BaseCheck):
    """Highlight Zabbix hosts that do not enforce encrypted connections."""

    meta = CheckMeta(
        id="zabbix.hosts.encryption",
        name="Host encryption coverage",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.HIGH,
        tags={"security", "configuration"},
        description="Ensure all monitored hosts require encrypted (PSK or certificate) agent connections.",
        explanation="Plain-text agent traffic allows attackers to spoof metrics or inject commands into Zabbix.",
        remediation="Set TLS_connect to PSK or certificate for all agents and distribute keys securely.",
        required_facts=("zabbix.hosts",),
        inputs=(
            {
                "key": "zabbix.host_encryption_ignore_hosts",
                "required": False,
                "secret": False,
                "description": "Comma-separated list (or array) of host names to ignore when evaluating encryption.",
            },
        ),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        hosts_fact = ctx.facts.get("zabbix.hosts", tech="zabbix")
        if not hosts_fact:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No host facts available; ensure the Zabbix provider collected data.",
                explanation="Without host inventory data the check cannot verify TLS enforcement.",
                remediation="Collect zabbix.hosts facts by enabling host.get permissions for the audit account and rerun the check.",
            )

        if not isinstance(hosts_fact, Sequence):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Unexpected format for zabbix.hosts fact (expected sequence).",
                details={"type": type(hosts_fact).__name__},
                explanation="Malformed host data hides nodes that still allow plaintext agents.",
                remediation="Update provider output or API permissions to return a list of host records before rerunning.",
            )

        config_section = _section(ctx.config, "zabbix")
        ignored_hosts = _normalise_host_set(config_section.get("host_encryption_ignore_hosts"))

        unencrypted: List[Dict[str, Any]] = []
        unknown: List[Dict[str, Any]] = []
        evaluated = 0

        for raw_host in hosts_fact:
            if not isinstance(raw_host, Mapping):
                continue
            record = HostRecord.from_mapping(raw_host)
            name_key = record.name.strip().lower()
            if name_key and name_key in ignored_hosts:
                continue
            evaluated += 1
            mode, description = _tls_mode(record.tls_connect)
            if mode == "unencrypted":
                unencrypted.append(_build_host_detail(record, description))
            elif mode == "unknown":
                unknown.append(_build_host_detail(record, description))

        details: Dict[str, Any] = {
            "evaluated_hosts": evaluated,
            "ignored_hosts": sorted(ignored_hosts),
            "unencrypted_hosts": unencrypted,
        }
        if unknown:
            details["unknown_hosts"] = unknown

        if evaluated == 0:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No hosts evaluated after applying ignore filters.",
                details=details,
                explanation="Ignoring all hosts leaves gaps in encryption coverage.",
                remediation="Review zabbix.host_encryption_ignore_hosts to ensure only intentional exceptions remain.",
            )

        if unencrypted:
            host_list = _format_host_names(unencrypted)
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=(
                    f"{len(unencrypted)} host(s) are configured without encryption: {host_list}."
                ),
                details=details,
                remediation="Set TLS_connect to PSK or certificate for the listed hosts and redeploy their agents.",
                explanation="Unencrypted agents allow on-path attackers to spoof metrics and commands.",
            )

        if unknown:
            host_list = _format_host_names(unknown)
            return CheckResult(
                meta=self.meta,
                status=Status.WARN,
                summary=(
                    "Some hosts have unknown TLS settings; verify their encryption configuration: "
                    f"{host_list}."
                ),
                details=details,
                remediation="Review agent TLS parameters on the listed hosts or refresh facts if recently updated.",
                explanation="Unknown TLS modes may hide legacy agents communicating in clear text.",
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="All evaluated hosts require encrypted connections (PSK or certificate).",
            details=details,
        )


def _section(config: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = config.get(key)
    if isinstance(value, dict):
        return value
    return {}


def _normalise_host_set(raw: Any) -> Set[str]:
    if raw is None:
        return set()
    items: Iterable[str]
    if isinstance(raw, str):
        items = (segment.strip() for segment in raw.split(","))
    elif isinstance(raw, (list, tuple, set)):
        items = (str(entry).strip() for entry in raw)
    else:
        return set()
    return {item.lower() for item in items if item}


def _tls_mode(value: int | None) -> Tuple[str, str]:
    if value is None:
        return "unknown", "TLS mode not reported"
    mapping = {
        1: ("unencrypted", "TLS_connect=1 (unencrypted)"),
        2: ("encrypted", "TLS_connect=2 (PSK)"),
        4: ("encrypted", "TLS_connect=4 (certificate)"),
    }
    result = mapping.get(value)
    if result is None:
        return "unknown", f"Unrecognised TLS_connect value {value}"
    return result


def _build_host_detail(record: HostRecord, reason: str) -> Dict[str, Any]:
    detail = {
        "id": record.id,
        "name": record.name,
        "tls_connect": record.tls_connect,
        "monitored_by": record.monitored_by,
        "reason": reason,
    }
    templates = record.source.get("template_ids")
    if isinstance(templates, list):
        detail["template_ids"] = list(templates)
    return detail


def _format_host_names(entries: Sequence[Mapping[str, Any]]) -> str:
    names: List[str] = []
    for entry in entries:
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if name:
            names.append(name)
    if not names:
        return "<unknown>"
    return ", ".join(names)


__all__ = ["ZabbixHostEncryptionCheck"]
