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


class ZabbixDashboardNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.dashboards",
        name="Dashboard naming policy",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure dashboard names start with '<TEAM> - ...' using configured team codes.",
        explanation="Consistent names encode ownership and simplify filtering/reporting.",
        remediation="Rename non-compliant dashboards or extend zabbix.team_codes.",
        required_facts=("zabbix.dashboards",),
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
        dashboards = ctx.facts.get("zabbix.dashboards", tech="zabbix")
        if not dashboards:
            return CheckResult(self.meta, Status.SKIP, summary="No dashboard inventory available")
        if not isinstance(dashboards, Sequence):
            return CheckResult(self.meta, Status.ERROR, summary="zabbix.dashboards not a sequence", details={"type": type(dashboards).__name__})

        codes = _codes(ctx.config)
        if not codes:
            return CheckResult(self.meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")

        invalid = []
        evaluated = 0
        for d in dashboards:
            if not isinstance(d, Mapping):
                continue
            name = str(d.get("name") or "").strip()
            if not name:
                continue
            evaluated += 1
            prefix = name.split("-", 1)[0].strip().upper()
            if prefix not in codes:
                invalid.append({"id": str(d.get("id") or ""), "name": name})

        if invalid:
            names = "\n".join(entry["name"] for entry in invalid if entry.get("name"))
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"{len(invalid)} dashboard(s) do not follow '<TEAM> - ...' naming",
                details={"invalid_dashboards": invalid, "evaluated": evaluated, "team_codes": sorted(codes)},
                explanation=names or None,
            )

        return CheckResult(self.meta, Status.PASS, summary="All dashboards follow naming policy", details={"evaluated": evaluated})


__all__ = ["ZabbixDashboardNamingCheck"]
