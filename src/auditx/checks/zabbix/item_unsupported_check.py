from __future__ import annotations

import time
from typing import Any, Dict, List, Mapping, MutableMapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

_DEFAULT_THRESHOLD_MINUTES = 60.0


class ZabbixItemUnsupportedDurationCheck(BaseCheck):
    """Highlight enabled items that stay unsupported for longer than the tolerated window."""

    meta = CheckMeta(
        id="zabbix.items.unsupported_duration",
        name="Zabbix unsupported item duration",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.HIGH,
        tags={"operations", "reliability"},
        description="Alert when Zabbix items remain in the unsupported state for an extended period.",
        explanation="Items stuck in unsupported state hide monitoring blind spots and generate alert noise.",
        remediation="Investigate failing endpoints quickly or disable stale items to keep alerts actionable.",
        inputs=(
            {
                "key": "zabbix.unsupported_item_threshold_minutes",
                "required": False,
                "secret": False,
                "description": "Maximum tolerated duration (in minutes) for an item to stay unsupported before failing the check.",
            },
        ),
        required_facts=("zabbix.items",),
    )

    def run(self, ctx: RunContext) -> CheckResult:  # noqa: D401 - intentional single-line summary
        items_fact = ctx.facts.get("zabbix.items", tech="zabbix")
        if items_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No item facts collected from Zabbix provider",
                explanation="Without item inventory you can't detect unsupported metrics.",
                remediation="Grant item.get permissions to the audit account and refresh facts before rerunning.",
            )
        if not isinstance(items_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected item facts structure from provider",
                explanation="Malformed item data masks unsupported durations.",
                remediation="Ensure the provider outputs a sequence of item objects for zabbix.items.",
            )

        threshold_minutes = _resolve_threshold_minutes(ctx.config)
        threshold_seconds = threshold_minutes * 60.0
        now = time.time()

        long_unsupported: List[Dict[str, Any]] = []
        recent_unsupported: List[Dict[str, Any]] = []
        missing_timestamp: List[Dict[str, Any]] = []

        for item in items_fact:
            if not isinstance(item, Mapping):
                continue
            state = str(item.get("state")) if item.get("state") is not None else "0"
            status = str(item.get("status")) if item.get("status") is not None else "0"
            if state != "1" or status != "0":
                continue

            entry = _build_entry(item)
            last_clock = _coerce_timestamp(item.get("last_clock"))
            if last_clock is None:
                missing_timestamp.append(entry)
                continue

            age_seconds = max(0.0, now - last_clock)
            entry["age_seconds"] = age_seconds
            entry["age_minutes"] = age_seconds / 60.0

            if age_seconds >= threshold_seconds:
                long_unsupported.append(entry)
            else:
                recent_unsupported.append(entry)

        total_considered = len(long_unsupported) + len(recent_unsupported) + len(missing_timestamp)
        long_by_host = _group_by_host(long_unsupported)
        recent_by_host = _group_by_host(recent_unsupported)
        missing_by_host = _group_by_host(missing_timestamp)
        details = {
            "threshold_minutes": threshold_minutes,
            "long_unsupported_items": long_unsupported,
            "recent_unsupported_items": recent_unsupported,
            "unsupported_without_timestamp": missing_timestamp,
            "unsupported_item_count": total_considered,
            "total_items": len(items_fact),
            "long_unsupported_by_host": long_by_host,
            "recent_unsupported_by_host": recent_by_host,
            "unsupported_without_timestamp_by_host": missing_by_host,
        }

        if long_unsupported:
            summary = _format_summary(
                f"{len(long_unsupported)} item(s) unsupported for longer than {_format_duration(threshold_minutes)}",
                long_unsupported,
            )
            explanation = _format_by_host("Unsupported (over threshold) by host", long_by_host) or None
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=summary,
                details=details,
                explanation=explanation,
                remediation=(
                    "Restore item functionality or disable the affected items once the underlying collection issues are solved."
                )
            )

        if missing_timestamp:
            summary = _format_summary(
                f"{len(missing_timestamp)} unsupported item(s) lack a timestamp to determine duration",
                missing_timestamp,
            )
            explanation = _format_by_host("Unsupported (no timestamp) by host", missing_by_host) or None
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details,
                explanation=explanation,
                remediation=(
                    "Verify item history retention and ensure unsupported items provide timing information for accurate diagnostics."
                )
            )

        summary = f"No enabled items unsupported longer than {_format_duration(threshold_minutes)}"
        if recent_unsupported:
            summary += f" ({len(recent_unsupported)} item(s) recently unsupported)"
        # For pass, optionally include a short grouping of recently unsupported to aid triage
        explanation = _format_by_host("Recently unsupported by host", recent_by_host) if recent_unsupported else None
        return CheckResult(
            self.meta,
            Status.PASS,
            summary=summary,
            details=details,
            explanation=explanation,
        )


def _build_entry(item: Mapping[str, Any]) -> Dict[str, Any]:
    hosts = [str(host) for host in item.get("hosts") or [] if host]
    entry: Dict[str, Any] = {
        "id": item.get("id"),
        "name": item.get("name") or item.get("id"),
        "key": item.get("key"),
        "hosts": hosts,
        "status": item.get("status"),
        "state": item.get("state"),
        "last_clock": item.get("last_clock"),
    }
    return entry


def _coerce_timestamp(value: Any) -> float | None:
    try:
        if value in (None, "", 0, "0"):
            return None
        numeric = float(value)
        if numeric <= 0:
            return None
        return numeric
    except (TypeError, ValueError):
        return None


def _resolve_threshold_minutes(config: Mapping[str, Any]) -> float:
    section = config.get("zabbix") if isinstance(config, Mapping) else None
    candidate = None
    if isinstance(section, Mapping):
        candidate = section.get("unsupported_item_threshold_minutes")
    try:
        if candidate is None:
            raise ValueError
        minutes = float(candidate)
        if minutes <= 0:
            raise ValueError
        return minutes
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD_MINUTES


def _format_summary(prefix: str, items: Sequence[MutableMapping[str, Any]]) -> str:
    descriptions: List[str] = []
    for item in items:
        name = str(item.get("name") or item.get("id") or "unknown-item")
        hosts = ", ".join(str(host) for host in item.get("hosts") or [])
        age_minutes = item.get("age_minutes")
        age_display = f", unsupported for {_format_duration(age_minutes)}" if isinstance(age_minutes, (int, float)) else ""
        host_part = f" (hosts: {hosts})" if hosts else ""
        descriptions.append(f"{name}{host_part}{age_display}")
    suffix = "; ".join(descriptions)
    if suffix:
        return f"{prefix}: {suffix}"
    return prefix


def _format_duration(value: Any) -> str:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if numeric % 60 == 0:
        hours = numeric / 60
        if hours % 24 == 0:
            days = hours / 24
            return f"{days:g}d"
        return f"{hours:g}h"
    return f"{numeric:g}m"


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
            age = item.get("age_minutes")
            suffix = f" (age: {_format_duration(age)})" if isinstance(age, (int, float)) else ""
            lines.append(f"  - {name}{suffix}")
        if extra_items:
            lines.append(f"  - … (+{extra_items} more)")
    if extra_hosts:
        lines.append(f"… (+{extra_hosts} more hosts)")
    return "\n".join(lines)


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


__all__ = ["ZabbixItemUnsupportedDurationCheck"]
