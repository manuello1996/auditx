from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


def _codes(config: Mapping[str, Any]) -> set[str]:
    raw = (config.get("zabbix") or {}).get("team_codes") if isinstance(config, Mapping) else None
    if raw is None:
        return set()
    if isinstance(raw, str):
        entries: Iterable[str] = (seg.strip() for seg in raw.split(","))
    elif isinstance(raw, (list, tuple, set)):
        entries = (str(x).strip() for x in raw)
    else:
        return set()
    return {e.upper() for e in entries if e}


def _run_action_check(ctx: RunContext, *, eventsource_values: set[str], required_prefix: str, meta: CheckMeta) -> CheckResult:
    actions = ctx.facts.get("zabbix.actions", tech="zabbix")
    if not actions:
        return CheckResult(meta, Status.SKIP, summary="No actions inventory available")
    if not isinstance(actions, Sequence):
        return CheckResult(meta, Status.ERROR, summary="zabbix.actions not a sequence", details={"type": type(actions).__name__})

    codes = _codes(ctx.config)
    if not codes:
        return CheckResult(meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")

    invalid = []
    evaluated = 0
    for a in actions:
        if not isinstance(a, Mapping):
            continue
        es = str(a.get("eventsource") or "").strip()
        if es not in eventsource_values:
            continue
        name = str(a.get("name") or "").strip()
        if not name:
            continue
        evaluated += 1
        # Expect: "<RequiredPrefix> - <TEAM> - ..."
        parts = [p.strip() for p in name.split("-", 2)]
        if len(parts) < 2:
            invalid.append({"id": str(a.get("id") or ""), "name": name})
            continue
        prefix_ok = parts[0].lower() == required_prefix.lower()
        team_ok = parts[1].upper() in codes
        if not (prefix_ok and team_ok):
            invalid.append({"id": str(a.get("id") or ""), "name": name})

    if invalid:
        names = "\n".join(entry["name"] for entry in invalid if entry.get("name"))
        return CheckResult(
            meta,
            Status.FAIL,
            summary=f"{len(invalid)} action(s) do not follow '{required_prefix} - <TEAM> - ...' naming",
            details={"invalid_actions": invalid, "evaluated": evaluated, "team_codes": sorted(codes), "eventsource_filter": sorted(eventsource_values)},
            explanation=names or None,
        )

    return CheckResult(meta, Status.PASS, summary="All actions follow naming policy", details={"evaluated": evaluated, "eventsource_filter": sorted(eventsource_values)})


class ZabbixTriggerActionNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.actions.trigger",
        name="Action naming: Trigger",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure trigger actions are named 'Trigger - <TEAM> - ...'",
        explanation="Consistent names encode ownership and make audit simpler.",
        remediation="Rename non-compliant actions or extend zabbix.team_codes.",
        required_facts=("zabbix.actions",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        # eventsource: 0 (triggers)
        return _run_action_check(ctx, eventsource_values={"0"}, required_prefix="Trigger", meta=self.meta)


class ZabbixServiceActionNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.actions.service",
        name="Action naming: Service",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure service actions are named 'Service - <TEAM> - ...'",
        explanation="Consistent names encode ownership and make audit simpler.",
        remediation="Rename non-compliant actions or extend zabbix.team_codes.",
        required_facts=("zabbix.actions",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        # eventsource: '4' is service in newer Zabbix; include empty to be permissive if not set
        return _run_action_check(ctx, eventsource_values={"4"}, required_prefix="Service", meta=self.meta)


class ZabbixDiscoveryActionNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.actions.discovery",
        name="Action naming: Discovery",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure discovery actions are named 'Discovery - <TEAM> - ...'",
        explanation="Consistent names encode ownership and make audit simpler.",
        remediation="Rename non-compliant actions or extend zabbix.team_codes.",
        required_facts=("zabbix.actions",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        # eventsource: 1 (discovery)
        return _run_action_check(ctx, eventsource_values={"1"}, required_prefix="Discovery", meta=self.meta)


class ZabbixAutoregActionNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.actions.autoregistration",
        name="Action naming: Autoregistration",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure autoregistration actions are named 'Autoregistration - <TEAM> - ...'",
        explanation="Consistent names encode ownership and make audit simpler.",
        remediation="Rename non-compliant actions or extend zabbix.team_codes.",
        required_facts=("zabbix.actions",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        # eventsource: 2 (autoreg)
        return _run_action_check(ctx, eventsource_values={"2"}, required_prefix="Autoregistration", meta=self.meta)


__all__ = [
    "ZabbixTriggerActionNamingCheck",
    "ZabbixServiceActionNamingCheck",
    "ZabbixDiscoveryActionNamingCheck",
    "ZabbixAutoregActionNamingCheck",
]
