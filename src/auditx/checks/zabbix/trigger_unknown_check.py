from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class ZabbixTriggerUnknownStateCheck(BaseCheck):
    """Report triggers currently stuck in the unknown state."""

    meta = CheckMeta(
        id="zabbix.triggers.unknown_state",
        name="Zabbix trigger unknown state",
        version="1.1.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"operations", "integrity"},
        description="List triggers currently reported in the unknown state.",
        explanation="Unknown triggers stop alert evaluation, leaving incidents undetected.",
        remediation="Repair the upstream items or dependencies keeping the trigger in the unknown state.",
        inputs=(),
        required_facts=("zabbix.triggers",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        triggers_fact = ctx.facts.get("zabbix.triggers", tech="zabbix")
        if triggers_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No trigger facts collected from Zabbix provider",
                explanation="Without trigger metadata you cannot spot unknown states.",
                remediation="Grant trigger.get access to the audit account and refresh the facts cache before rerunning.",
            )
        if not isinstance(triggers_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected trigger facts structure from Zabbix provider",
                explanation="Malformed trigger data hides stuck alarms.",
                remediation="Ensure zabbix.triggers returns a sequence of trigger objects from the provider.",
            )

        unknown_triggers: list[Dict[str, Any]] = []
        for trigger in triggers_fact:
            if not isinstance(trigger, Mapping):
                continue
            state = str(trigger.get("state"))
            if state != "1":
                continue
            hosts = [str(host) for host in trigger.get("hosts") or [] if host]
            unknown_triggers.append(
                {
                    "id": trigger.get("id"),
                    "name": trigger.get("name") or trigger.get("id"),
                    "hosts": hosts,
                    "status": trigger.get("status"),
                    "value": trigger.get("value"),
                    "priority": trigger.get("priority"),
                }
            )

        total_unknown = len(unknown_triggers)
        grouped = _group_by_host(unknown_triggers)
        details: Dict[str, Any] = {
            "unknown_triggers": unknown_triggers,
            "unknown_trigger_count": total_unknown,
            "unknown_by_host": grouped,
            "total_triggers": len(triggers_fact),
        }

        if total_unknown == 0:
            return CheckResult(
                self.meta,
                Status.PASS,
                summary="No triggers reported in unknown state",
                details=details,
            )

        summary_names = "; ".join(
            (
                f"{entry.get('name') or entry.get('id') or 'unknown-trigger'}"
                + (f" (hosts: {', '.join(entry['hosts'])})" if entry.get("hosts") else "")
            )
            for entry in unknown_triggers
        )
        summary = f"{total_unknown} trigger(s) currently in unknown state"
        if summary_names:
            summary += f": {summary_names}"

        explanation = _format_by_host("Unknown triggers by host", grouped) or None
        return CheckResult(
            self.meta,
            Status.WARN,
            summary=summary,
            details=details,
            explanation=explanation,
            remediation=(
                "Investigate the listed triggers in Zabbix and resolve the conditions that keep them in the unknown state."
            )
        )


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
            name = str(item.get("name") or item.get("id") or "trigger")
            lines.append(f"  - {name}")
        if extra_items:
            lines.append(f"  - … (+{extra_items} more)")
    if extra_hosts:
        lines.append(f"… (+{extra_hosts} more hosts)")
    return "\n".join(lines)


__all__ = ["ZabbixTriggerUnknownStateCheck"]
