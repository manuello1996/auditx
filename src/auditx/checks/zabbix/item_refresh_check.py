from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

_DEFAULT_THRESHOLD_SECONDS = 60.0


class ZabbixItemRefreshRateCheck(BaseCheck):
    """Ensure regular items refresh no faster than the configured cadence."""

    meta = CheckMeta(
        id="zabbix.items.refresh_rate",
        name="Zabbix item refresh rate",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"performance", "operations"},
        description="Flag items whose polling interval is lower than the configured minimum.",
        explanation="Overly aggressive polling overloads pollers and dependent systems.",
        remediation="Raise delays for noisy items or aggregate metrics server-side to stay within capacity.",
        inputs=(
            {
                "key": "zabbix.item_min_refresh_seconds",
                "required": False,
                "secret": False,
                "description": "Minimum allowed refresh frequency for items (seconds).",
            },
        ),
        required_facts=("zabbix.items",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        items_fact = ctx.facts.get("zabbix.items", tech="zabbix")
        if items_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No item facts collected from Zabbix provider",
                explanation="Without item metadata you cannot detect high-frequency polling.",
                remediation="Ensure the API token can call item.get and refresh the facts cache before rerunning.",
            )
        if not isinstance(items_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected item facts structure from provider",
                explanation="Malformed item data prevents checking polling intervals.",
                remediation="Upgrade the provider export so zabbix.items returns a list of items.",
            )

        threshold = _resolve_threshold_seconds(ctx.config)
        excluded_keys = _resolve_excluded_keys(ctx.config)

        offending: list[Dict[str, Any]] = []
        unresolved: list[Dict[str, Any]] = []
        ignored_zero_delay: list[Dict[str, Any]] = []
        missing_hosts: list[Dict[str, Any]] = []
        excluded_items: list[Dict[str, Any]] = []
        considered_count = 0

        for item in items_fact:
            if not isinstance(item, Mapping):
                continue
            delay_seconds = item.get("delay_seconds")
            hosts = list(item.get("hosts") or [])
            item_key = _coerce_key(item.get("key"))
            details = {
                "id": item.get("id"),
                "name": item.get("name"),
                "key": item_key,
                "hosts": hosts,
                "delay_seconds": delay_seconds,
                "delay": item.get("delay"),
            }
            if not hosts:
                missing_hosts.append(details)
                continue
            if item_key and item_key in excluded_keys:
                excluded_items.append(details)
                continue
            if isinstance(delay_seconds, (int, float)):
                if float(delay_seconds) == 0:
                    ignored_zero_delay.append(details)
                    continue
                considered_count += 1
                if delay_seconds < threshold:
                    offending.append(details)
            else:
                unresolved.append(details)

        if considered_count == 0 and not unresolved:
            summary = "No items with refresh intervals to evaluate"
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary=summary,
                details={
                    "threshold_seconds": threshold,
                    "offending_items": offending,
                    "unresolved_items": unresolved,
                    "ignored_zero_delay_items": ignored_zero_delay,
                    "missing_host_bindings": missing_hosts,
                    "excluded_items": excluded_items,
                    "sample_size": considered_count,
                    "total_items": len(items_fact),
                },
                explanation="No evaluable items means the threshold is not applied to any workload.",
                remediation="Confirm polling intervals are numeric and hosts are linked to each item before retrying.",
            )

        details_payload = {
            "threshold_seconds": threshold,
            "offending_items": offending,
            "unresolved_items": unresolved,
            "ignored_zero_delay_items": ignored_zero_delay,
            "missing_host_bindings": missing_hosts,
            "excluded_items": excluded_items,
            "sample_size": considered_count,
            "total_items": len(items_fact),
        }

        if offending:
            fastest = min(offending, key=lambda entry: entry["delay_seconds"] or 0)
            offending_descriptions = "; ".join(_describe_item(entry) for entry in offending)
            summary = (
                f"{len(offending)} item(s) refresh faster than {_format_duration(threshold)} "
                f"(fastest {_format_duration(fastest['delay_seconds'])})"
            )
            if offending_descriptions:
                summary += f": {offending_descriptions}"
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=summary,
                details=details_payload,
                explanation="Fast polling starves other items and can overwhelm source systems.",
                remediation="Increase the delay for the listed items or move them to dependent metrics with preprocessing.",
            )

        if unresolved:
            unresolved_descriptions = "; ".join(_describe_item(entry) for entry in unresolved)
            summary = f"{len(unresolved)} item(s) have non-numeric refresh intervals"
            if unresolved_descriptions:
                summary += f": {unresolved_descriptions}"
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details_payload,
                explanation="Non-numeric delays hide actual polling frequency.",
                remediation="Normalize item delays to seconds or update templates to use supported interval syntax.",
            )

        if missing_hosts:
            missing_descriptions = "; ".join(_describe_item(entry) for entry in missing_hosts)
            summary = f"{len(missing_hosts)} item(s) skipped because of missing host binding"
            if missing_descriptions:
                summary += f": {missing_descriptions}"
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details_payload,
                explanation="Items with no hosts suggest mislinked templates.",
                remediation="Link the templates to hosts or remove orphaned items to keep polling predictable.",
            )

        summary = f"All items refresh slower than or equal to {_format_duration(threshold)}"
        return CheckResult(self.meta, Status.PASS, summary=summary, details=details_payload)


def _resolve_excluded_keys(config: Mapping[str, Any]) -> set[str]:
    section = config.get("zabbix") if isinstance(config, Mapping) else None
    if not isinstance(section, Mapping):
        return set()
    raw = section.get("item_refresh_excluded_keys")
    if raw is None:
        return set()
    if isinstance(raw, str):
        return _parse_key_string(raw)
    if isinstance(raw, Sequence):
        values: set[str] = set()
        for entry in raw:
            key = _coerce_key(entry)
            if key:
                values.add(key)
        return values
    key = _coerce_key(raw)
    return {key} if key else set()


def _resolve_threshold_seconds(config: Mapping[str, Any]) -> float:
    section = config.get("zabbix") if isinstance(config, Mapping) else None
    candidate: Any = None
    if isinstance(section, Mapping):
        candidate = section.get("item_min_refresh_seconds")
    try:
        if candidate is None:
            raise ValueError
        value = float(candidate)
        if value <= 0:
            raise ValueError
        return value
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD_SECONDS


def _describe_item(entry: Mapping[str, Any]) -> str:
    name = str(entry.get("name") or entry.get("id") or "unknown-item")
    key = entry.get("key")
    host_part = ", ".join(str(host) for host in entry.get("hosts") or [])
    delay = _format_duration(entry.get("delay_seconds"))
    components: list[str] = []
    if host_part:
        components.append(f"hosts: {host_part}")
    if key:
        components.append(f"key: {key}")
    components.append(f"delay: {delay}")
    return f"{name} ({', '.join(components)})"


def _format_duration(value: Any) -> str:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if seconds % 3600 == 0:
        hours = seconds / 3600
        return f"{hours:g}h"
    if seconds % 60 == 0:
        minutes = seconds / 60
        return f"{minutes:g}m"
    return f"{seconds:g}s"


def _coerce_key(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _parse_key_string(text: str) -> set[str]:
    stripped = text.strip()
    if not stripped:
        return set()
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes)):
                return {str(entry) for entry in parsed if str(entry).strip()}
        except json.JSONDecodeError:
            pass
        inner = stripped[1:-1]
        return {segment.strip() for segment in inner.split(",") if segment.strip()}
    if "," in stripped:
        return {segment.strip() for segment in stripped.split(",") if segment.strip()}
    return {stripped}


__all__ = ["ZabbixItemRefreshRateCheck"]
