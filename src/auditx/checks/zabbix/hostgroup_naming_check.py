from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


def _normalise_codes(raw: Any) -> set[str]:
    """Normalise a config value (string or list) into a set of uppercase codes."""
    if raw is None:
        return set()
    entries: Iterable[str]
    if isinstance(raw, str):
        entries = (segment.strip() for segment in raw.split(","))
    elif isinstance(raw, (list, tuple, set)):
        entries = (str(item).strip() for item in raw)
    else:
        return set()
    return {entry.upper() for entry in entries if entry}


class ZabbixHostgroupNamingCheck(BaseCheck):
    """Ensure Zabbix host groups start with an approved team code prefix."""

    meta = CheckMeta(
        id="zabbix.hostgroups.naming",
        name="Host group naming policy",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"governance", "configuration"},
        description=(
            "Verify that every host group name starts with an allowed team code, "
            "optionally followed by '/...' (e.g., TEAM1, TEAM1/PROD)."
        ),
        explanation=(
            "Consistent host group prefixes encode ownership and simplify automation and reporting."
        ),
        remediation=(
            "Rename non-compliant host groups to start with one of the configured team codes, "
            "or update zabbix.team_codes if new teams are valid."
        ),
        required_facts=("zabbix.hostgroups",),
        inputs=(
            {
                "key": "zabbix.team_codes",
                "required": False,
                "secret": False,
                "description": "List or comma-separated codes (e.g., TEAM1, TEAM2, TEAM3)",
            },
        ),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        groups_fact = ctx.facts.get("zabbix.hostgroups", tech="zabbix")
        if not groups_fact:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary=(
                    "No host group facts available; ensure the Zabbix provider collected host groups."
                ),
                explanation="Missing host group inventory prevents evaluating naming compliance.",
                remediation="Grant hostgroup.get API access and refresh the discovery facts before rerunning.",
            )

        if not isinstance(groups_fact, Sequence):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Unexpected format for zabbix.hostgroups fact (expected sequence).",
                details={"type": type(groups_fact).__name__},
            )

        team_codes = _normalise_codes((ctx.config.get("zabbix") or {}).get("team_codes"))
        if not team_codes:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No team codes configured (zabbix.team_codes); nothing to validate.",
                remediation=(
                    "Add zabbix.team_codes in your config (list or comma-separated string) to enable this check."
                ),
            )

        invalid: list[dict[str, str]] = []
        evaluated = 0
        for entry in groups_fact:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            # Exclude default system groups like "Zabbix Defaults/*" from evaluation
            if name.lower().startswith("zabbix defaults/"):
                continue
            # Exclude default system groups like "general/*" from evaluation
            if name.lower().startswith("general/"):
                continue
            if name.lower().startswith("general"):
                continue
            evaluated += 1
            prefix = name.split("/", 1)[0].strip().upper()
            if prefix not in team_codes:
                invalid.append({"id": str(entry.get("id") or ""), "name": name})

        if not evaluated:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No host groups evaluated.",
            )

        if invalid:
            details: Dict[str, Any] = {
                "invalid_hostgroups": invalid,
                "team_codes": sorted(team_codes),
                "evaluated": evaluated,
                "non_compliant": len(invalid),
            }
            sample_names = ", ".join(x["name"] for x in invalid[:5])
            suffix = f": {sample_names}" if sample_names else ""
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=f"{len(invalid)} host group(s) do not follow naming policy{suffix}",
                details=details,
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="All evaluated host groups follow the naming policy.",
            details={"evaluated": evaluated, "team_codes": sorted(team_codes)},
        )


__all__ = ["ZabbixHostgroupNamingCheck"]
