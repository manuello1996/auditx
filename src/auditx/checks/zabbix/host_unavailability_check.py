from __future__ import annotations

import time
from typing import Any, Dict, Iterable, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

_DEFAULT_THRESHOLD_HOURS = 24


class ZabbixHostUnavailabilityCheck(BaseCheck):
    """Detect monitored hosts that remain unavailable beyond the configured window."""

    meta = CheckMeta(
        id="zabbix.hosts.unavailable_duration",
        name="Zabbix host unavailability",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"availability", "operations"},
        description="Alert when monitored hosts stay unavailable longer than the configured threshold.",
        explanation="Lingering outages erode monitoring coverage and delay incident handling.",
        remediation="Investigate hosts exceeding the downtime threshold and adjust maintenance windows as needed.",
        inputs=(
            {
                "key": "zabbix.hosts_unavailable_threshold_hours",
                "required": False,
                "secret": False,
                "description": "Maximum downtime window (hours) before flagging unavailable hosts.",
            },
        ),
        required_facts=("zabbix.hosts",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        hosts_fact = ctx.facts.get("zabbix.hosts", tech="zabbix")
        if hosts_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No host facts collected from Zabbix provider",
                explanation="Missing host data blocks detection of silent outages.",
                remediation="Grant the audit account access to host.get and refresh the facts cache before rerunning.",
            )
        if not isinstance(hosts_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected host facts structure from Zabbix provider",
                explanation="Malformed host data hides outages.",
                remediation="Upgrade the provider or ensure zabbix.hosts returns a list of host objects before rerunning.",
            )

        monitored_hosts = [h for h in hosts_fact if _is_monitored_host(h)]
        if not monitored_hosts:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No monitored hosts returned by Zabbix",
                explanation="If no hosts are monitored, availability cannot be enforced.",
                remediation="Verify the target Zabbix instance has active hosts and the audit credentials can see them.",
            )

        threshold_hours = _resolve_threshold_hours(ctx.config)
        threshold_seconds = threshold_hours * 3600
        now = time.time()

        offenders: list[Dict[str, Any]] = []
        recent: list[Dict[str, Any]] = []
        missing: list[str] = []

        for host in monitored_hosts:
            if not isinstance(host, Mapping):
                continue
            availability = str(host.get("available", ""))
            if availability == "1":  # already available
                continue

            unavailable_since = _extract_unavailable_since(host)
            host_name = _host_label(host)
            if unavailable_since is None:
                missing.append(host_name)
                continue

            downtime = max(0.0, now - unavailable_since)
            hours = downtime / 3600
            payload = {"name": host_name, "downtime_hours": round(hours, 2)}
            if downtime >= threshold_seconds:
                offenders.append(payload)
            else:
                recent.append(payload)

        details: Dict[str, Any] = {
            "threshold_hours": threshold_hours,
            "offenders": offenders,
            "recent_unavailable": recent,
            "missing_timestamps": missing,
            "sample_size": len(monitored_hosts),
        }

        if offenders:
            max_hours_value = max(item["downtime_hours"] for item in offenders)
            offender_descriptions = "; ".join(_describe_host(entry) for entry in offenders)
            summary = (
                f"{len(offenders)} host(s) unavailable longer than {threshold_hours:g}h "
                f"(max {_format_hours(max_hours_value)})"
            )
            if offender_descriptions:
                summary += f": {offender_descriptions}"
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=summary,
                details=details,
                explanation="Long-running outages degrade monitoring coverage and incident response.",
                remediation="Dispatch technicians to restore connectivity or schedule maintenance with documented approvals.",
            )

        if missing:
            missing_list = ", ".join(missing)
            summary = f"{len(missing)} host(s) unavailable but without timestamp metadata"
            if missing_list:
                summary += f": {missing_list}"
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details,
                explanation="Without timestamps you cannot triage how long hosts were offline.",
                remediation="Confirm agent error counters (errors_from) are collected and interfaces expose downtime metadata.",
            )

        if recent:
            max_recent_value = max(item["downtime_hours"] for item in recent)
            recent_descriptions = "; ".join(_describe_host(entry) for entry in recent)
            summary = (
                f"{len(recent)} host(s) currently unavailable but within {threshold_hours:g}h "
                f"(max {_format_hours(max_recent_value)})"
            )
            if recent_descriptions:
                summary += f": {recent_descriptions}"
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details,
                explanation="Active outages deserve follow-up before they exceed the threshold.",
                remediation="Notify on-call staff to investigate the affected hosts right away.",
            )

        summary = f"All {len(monitored_hosts)} monitored host(s) are available"
        return CheckResult(self.meta, Status.PASS, summary=summary, details=details)


def _resolve_threshold_hours(config: Mapping[str, Any]) -> float:
    zabbix_section = config.get("zabbix") if isinstance(config, Mapping) else None
    candidate: Any = None
    if isinstance(zabbix_section, Mapping):
        candidate = zabbix_section.get("hosts_unavailable_threshold_hours")
    try:
        if candidate is None:
            raise ValueError
        value = float(candidate)
        if value <= 0:
            raise ValueError
        return value
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD_HOURS


def _is_monitored_host(host: Any) -> bool:
    if not isinstance(host, Mapping):
        return False
    return str(host.get("status")) == "0"


def _host_label(host: Mapping[str, Any]) -> str:
    for key in ("name", "host", "id"):
        value = host.get(key)
        if value:
            return str(value)
    return "unknown-host"


def _describe_host(entry: Mapping[str, Any]) -> str:
    name = str(entry.get("name", "unknown-host"))
    downtime = entry.get("downtime_hours")
    return f"{name} ({_format_hours(downtime)})"


def _extract_unavailable_since(host: Mapping[str, Any]) -> float | None:
    timestamps: list[Any] = [
        host.get("unavailable_since"),
        host.get("errors_from"),
        host.get("snmp_errors_from"),
        host.get("ipmi_errors_from"),
        host.get("jmx_errors_from"),
    ]

    interfaces = host.get("interfaces")
    if isinstance(interfaces, Sequence):
        for interface in interfaces:
            if isinstance(interface, Mapping):
                timestamps.append(interface.get("errors_from"))

    parsed = [_coerce_timestamp(candidate) for candidate in timestamps]
    filtered = [value for value in parsed if value is not None and value > 0]
    if not filtered:
        return None
    return float(min(filtered))


def _coerce_timestamp(value: Any) -> float | None:
    try:
        if value in (None, "", "0", 0):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _format_hours(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "unknown"
    formatted = f"{number:.2f}".rstrip("0").rstrip(".")
    return f"{formatted}h"


__all__ = ["ZabbixHostUnavailabilityCheck"]
