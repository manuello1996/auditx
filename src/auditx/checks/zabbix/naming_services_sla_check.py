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


class ZabbixServiceNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.services",
        name="Service naming policy",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure service names start with '<TEAM> - ...' using configured team codes.",
        explanation="Consistent names encode ownership and simplify SLA mapping.",
        remediation="Rename non-compliant services or extend zabbix.team_codes.",
        required_facts=("zabbix.services",),
        inputs=({"key": "zabbix.team_codes", "required": False, "secret": False, "description": "Team codes"},),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        services = ctx.facts.get("zabbix.services", tech="zabbix")
        if not services:
            return CheckResult(self.meta, Status.SKIP, summary="No services inventory available")
        if not isinstance(services, Sequence):
            return CheckResult(self.meta, Status.ERROR, summary="zabbix.services not a sequence", details={"type": type(services).__name__})
        codes = _codes(ctx.config)
        if not codes:
            return CheckResult(self.meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")
        invalid = []
        evaluated = 0
        for s in services:
            if not isinstance(s, Mapping):
                continue
            name = str(s.get("name") or "").strip()
            if not name:
                continue
            evaluated += 1
            prefix = name.split("-", 1)[0].strip().upper()
            if prefix not in codes:
                invalid.append({"id": str(s.get("id") or ""), "name": name})
        if invalid:
            names = "\n".join(entry["name"] for entry in invalid if entry.get("name"))
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"{len(invalid)} service(s) do not follow '<TEAM> - ...' naming",
                details={"invalid_services": invalid, "evaluated": evaluated, "team_codes": sorted(codes)},
                explanation=names or None,
            )
        return CheckResult(self.meta, Status.PASS, summary="All services follow naming policy", details={"evaluated": evaluated})


class ZabbixSLANamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.slas",
        name="SLA naming policy",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure SLA names start with '<TEAM> - ...' (if SLAs endpoint is available).",
        explanation="Consistent names encode ownership and simplify reporting.",
        remediation="Rename non-compliant SLAs or extend zabbix.team_codes.",
        required_facts=("zabbix.slas",),
        inputs=({"key": "zabbix.team_codes", "required": False, "secret": False, "description": "Team codes"},),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        slas = ctx.facts.get("zabbix.slas", tech="zabbix")
        if not slas:
            return CheckResult(self.meta, Status.SKIP, summary="No SLAs inventory available (or API not supported)")
        if not isinstance(slas, Sequence):
            return CheckResult(self.meta, Status.ERROR, summary="zabbix.slas not a sequence", details={"type": type(slas).__name__})
        codes = _codes(ctx.config)
        if not codes:
            return CheckResult(self.meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")
        invalid = []
        evaluated = 0
        for s in slas:
            if not isinstance(s, Mapping):
                continue
            name = str(s.get("name") or "").strip()
            if not name:
                continue
            evaluated += 1
            prefix = name.split("-", 1)[0].strip().upper()
            if prefix not in codes:
                invalid.append({"id": str(s.get("id") or ""), "name": name})
        if invalid:
            names = "\n".join(entry["name"] for entry in invalid if entry.get("name"))
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"{len(invalid)} SLA(s) do not follow '<TEAM> - ...' naming",
                details={"invalid_slas": invalid, "evaluated": evaluated, "team_codes": sorted(codes)},
                explanation=names or None,
            )
        return CheckResult(self.meta, Status.PASS, summary="All SLAs follow naming policy", details={"evaluated": evaluated})


__all__ = ["ZabbixServiceNamingCheck", "ZabbixSLANamingCheck"]
