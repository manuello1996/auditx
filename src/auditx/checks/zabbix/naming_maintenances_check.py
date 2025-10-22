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


class ZabbixMaintenanceNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.maintenances",
        name="Maintenance naming policy",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure maintenance names start with '<TEAM> - ...' using configured team codes.",
        explanation="Consistent names encode ownership and simplify scheduling/reporting.",
        remediation="Rename non-compliant maintenances or extend zabbix.team_codes.",
        required_facts=("zabbix.maintenances",),
        inputs=(
            {
                "key": "zabbix.team_codes",
                "required": False,
                "secret": False,
                "description": "List or comma-separated team codes (e.g., TEAM1, TEAM2, TEAM3)",
            },
        ),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        maints = ctx.facts.get("zabbix.maintenances", tech="zabbix")
        if not maints:
            return CheckResult(self.meta, Status.SKIP, summary="No maintenance inventory available")
        if not isinstance(maints, Sequence):
            return CheckResult(self.meta, Status.ERROR, summary="zabbix.maintenances not a sequence", details={"type": type(maints).__name__})

        codes = _codes(ctx.config)
        if not codes:
            return CheckResult(self.meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")

        invalid = []
        evaluated = 0
        for m in maints:
            if not isinstance(m, Mapping):
                continue
            name = str(m.get("name") or "").strip()
            if not name:
                continue
            evaluated += 1
            prefix = name.split("-", 1)[0].strip().upper()
            if prefix not in codes:
                invalid.append({"id": str(m.get("id") or ""), "name": name})

        if invalid:
            names = "\n".join(entry["name"] for entry in invalid if entry.get("name"))
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"{len(invalid)} maintenance object(s) do not follow '<TEAM> - ...' naming",
                details={"invalid_maintenances": invalid, "evaluated": evaluated, "team_codes": sorted(codes)},
                explanation=names or None,
            )

        return CheckResult(self.meta, Status.PASS, summary="All maintenances follow naming policy", details={"evaluated": evaluated})


__all__ = ["ZabbixMaintenanceNamingCheck"]
