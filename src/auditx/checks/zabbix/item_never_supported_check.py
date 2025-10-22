from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class ZabbixItemNeverSupportedCheck(BaseCheck):
    """Detect enabled items that have never produced data because their timestamp is zero."""

    meta = CheckMeta(
        id="zabbix.items.never_supported",
        name="Zabbix items never supported",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.HIGH,
        tags={"operations", "reliability"},
        description="List enabled items reported as not supported that never produced data (last clock equals zero).",
        explanation="Items that never produced data waste poller slots and hide telemetry gaps.",
        remediation="Fix the data source or disable the orphaned items so unsupported noise does not hide real issues.",
        inputs=(),
        required_facts=("zabbix.items",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        items_fact = ctx.facts.get("zabbix.items", tech="zabbix")
        if items_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No item facts collected from Zabbix provider",
                explanation="Without item inventory the check cannot spot unsupported metrics.",
                remediation="Grant the audit account item.get permissions and rerun discovery.",
            )
        if not isinstance(items_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected item facts structure from provider",
                explanation="Malformed item data hides unsupported checks.",
                remediation="Upgrade the provider or API call so zabbix.items returns a list of item objects.",
            )

        never_supported = [entry for entry in (_prepare_entry(item) for item in items_fact) if entry is not None]
        grouped = _group_by_host(never_supported)
        details = {
            "never_supported_items": never_supported,
            "never_supported_count": len(never_supported),
            "total_items": len(items_fact),
            "never_supported_by_host": grouped,
        }

        if not never_supported:
            return CheckResult(
                self.meta,
                Status.PASS,
                summary="No enabled not-supported items stuck with zero timestamp",
                details=details,
            )

        summary = _build_summary(never_supported)
        explanation = _format_by_host("Never-supported items by host", grouped) or None
        return CheckResult(
            self.meta,
            Status.FAIL,
            summary=summary,
            details=details,
            explanation=explanation,
            remediation=(
                "Investigate the affected items, fix their data sources, or disable them to prevent permanent unsupported state."
            )
        )


def _prepare_entry(item: Any) -> Dict[str, Any] | None:
    if not isinstance(item, Mapping):
        return None
    state = _coerce_str(item.get("state"))
    status = _coerce_str(item.get("status"))
    if state != "1" or status != "0":
        return None

    last_clock = item.get("last_clock")
    if not _is_zero_timestamp(last_clock):
        return None

    hosts = [str(host) for host in item.get("hosts") or [] if host]
    return {
        "id": item.get("id"),
        "name": item.get("name") or item.get("id"),
        "key": item.get("key"),
        "hosts": hosts,
        "status": status,
        "state": state,
        "last_clock": last_clock,
    }


def _build_summary(items: Sequence[MutableMapping[str, Any]]) -> str:
    prefix = f"{len(items)} enabled item(s) reported as not supported since creation"
    parts: list[str] = []
    for entry in items:
        name = str(entry.get("name") or entry.get("id") or "unknown-item")
        hosts = ", ".join(str(host) for host in entry.get("hosts") or [])
        host_fragment = f" (hosts: {hosts})" if hosts else ""
        key_segment = str(entry.get("key") or "")
        if key_segment:
            host_fragment += f", key: {key_segment}" if host_fragment else f" (key: {key_segment})"
        parts.append(f"{name}{host_fragment}")
    if parts:
        return f"{prefix}: {'; '.join(parts)}"
    return prefix


def _is_zero_timestamp(value: Any) -> bool:
    if value in (None, "", "None"):
        return False
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return False
    return numeric == 0.0


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _group_by_host(items: Sequence[Mapping[str, Any]]) -> Dict[str, list[Dict[str, Any]]]:
    grouped: Dict[str, list[Dict[str, Any]]] = {}
    for entry in items:
        hosts = entry.get("hosts") or []
        if not isinstance(hosts, Sequence):
            continue
        for host in hosts:
            host_name = str(host).strip()
            if not host_name:
                continue
            grouped.setdefault(host_name, []).append(dict(entry))
    return grouped


def _format_by_host(title: str, mapping: Mapping[str, Sequence[Mapping[str, Any]]], *, host_limit: int = 10, item_limit: int = 8) -> str:
    if not mapping:
        return ""
    lines: list[str] = [title + ":"]
    hosts = sorted(mapping.keys())
    extra_hosts = 0
    for idx, host in enumerate(hosts):
        if idx >= host_limit:
            extra_hosts = len(hosts) - host_limit
            break
        items = mapping[host]
        lines.append(f"- {host}:")
        extra_items = 0
        for jdx, item in enumerate(items):
            if jdx >= item_limit:
                extra_items = len(items) - item_limit
                break
            name = str(item.get("name") or item.get("id") or "item")
            lines.append(f"  - {name}")
        if extra_items:
            lines.append(f"  - … (+{extra_items} more)")
    if extra_hosts:
        lines.append(f"… (+{extra_hosts} more hosts)")
    return "\n".join(lines)


__all__ = ["ZabbixItemNeverSupportedCheck"]
