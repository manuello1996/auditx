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


class ZabbixDiscoveryRuleNamingCheck(BaseCheck):
    meta = CheckMeta(
        id="zabbix.naming.discovery_rules",
        name="Discovery rule naming policy",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description="Ensure discovery rule names start with '<TEAM> - ...' using configured team codes.",
        explanation="Consistent names encode ownership and simplify filtering/reporting.",
        remediation="Rename non-compliant discovery rules or extend zabbix.team_codes.",
        required_facts=("zabbix.discovery_rules",),
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
        rules = ctx.facts.get("zabbix.discovery_rules", tech="zabbix")
        if not rules:
            return CheckResult(self.meta, Status.SKIP, summary="No discovery rules inventory available")
        if not isinstance(rules, Sequence):
            return CheckResult(self.meta, Status.ERROR, summary="zabbix.discovery_rules not a sequence", details={"type": type(rules).__name__})

        codes = _codes(ctx.config)
        if not codes:
            return CheckResult(self.meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")

        invalid = []
        evaluated = 0
        for r in rules:
            if not isinstance(r, Mapping):
                continue
            name = str(r.get("name") or "").strip()
            if not name:
                continue
            evaluated += 1
            prefix = name.split("-", 1)[0].strip().upper()
            if prefix not in codes:
                invalid.append({"id": str(r.get("id") or ""), "name": name})

        if invalid:
            names = "\n".join(entry["name"] for entry in invalid if entry.get("name"))
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"{len(invalid)} discovery rule(s) do not follow '<TEAM> - ...' naming",
                details={"invalid_discovery_rules": invalid, "evaluated": evaluated, "team_codes": sorted(codes)},
                explanation=names or None,
            )

        return CheckResult(self.meta, Status.PASS, summary="All discovery rules follow naming policy", details={"evaluated": evaluated})


__all__ = ["ZabbixDiscoveryRuleNamingCheck"]
