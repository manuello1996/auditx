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


class ZabbixTemplateNamingCheck(BaseCheck):
    """Ensure templates under Templates/<TEAM> are named 'TEAM - ...'."""

    meta = CheckMeta(
        id="zabbix.naming.templates",
        name="Template naming under Templates/TEAM",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"governance", "naming"},
        description=(
            "For any template that belongs to a template group named 'Templates/<TEAM>', "
            "validate its name starts with '<TEAM> - '."
        ),
        explanation=(
            "Aligning template names with their team group encodes ownership and eases automation and reviews."
        ),
        remediation=(
            "Rename templates to start with the owning team code or move them under the appropriate 'Templates/<TEAM>' group."
        ),
        required_facts=("zabbix.templates",),
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
        templates = ctx.facts.get("zabbix.templates", tech="zabbix")
        if not templates:
            return CheckResult(self.meta, Status.SKIP, summary="No template inventory available")
        if not isinstance(templates, Sequence):
            return CheckResult(self.meta, Status.ERROR, summary="zabbix.templates not a sequence", details={"type": type(templates).__name__})

        codes = _codes(ctx.config)
        if not codes:
            return CheckResult(self.meta, Status.SKIP, summary="No team codes configured (zabbix.team_codes)")

        non_compliant: list[dict[str, Any]] = []
        evaluated = 0
        for t in templates:
            if not isinstance(t, Mapping):
                continue
            name = str(t.get("name") or "").strip()
            groups = t.get("groups")
            if not name or not isinstance(groups, Sequence):
                continue

            # Which team groups does this template belong to?
            group_names = [g.get("name") for g in groups if isinstance(g, Mapping)]
            team_groups = set()
            for gname in group_names:
                if not isinstance(gname, str):
                    continue
                lower = gname.strip().lower()
                # Match 'Templates/<TEAM>' (case-insensitive)
                for code in codes:
                    if lower.startswith(f"templates/{code.lower()}"):
                        team_groups.add(code)

            if not team_groups:
                # Not under any Templates/<TEAM> group → out of scope
                continue

            evaluated += 1
            name_prefix = name.split("-", 1)[0].strip().upper()
            if name_prefix not in team_groups:
                non_compliant.append({
                    "id": str(t.get("id") or ""),
                    "name": name,
                    "groups": group_names,
                    "allowed_team_codes": sorted(team_groups),
                })

        if non_compliant:
            names = "\n".join(entry["name"] for entry in non_compliant if entry.get("name"))
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"{len(non_compliant)} template(s) under Templates/<TEAM> do not start with '<TEAM> - ...'",
                details={"invalid_templates": non_compliant, "evaluated": evaluated, "team_codes": sorted(codes)},
                explanation=names or None,
            )

        if evaluated == 0:
            return CheckResult(self.meta, Status.SKIP, summary="No templates found under Templates/<TEAM>")

        return CheckResult(self.meta, Status.PASS, summary="All templates under Templates/<TEAM> follow naming policy", details={"evaluated": evaluated})


__all__ = ["ZabbixTemplateNamingCheck"]
