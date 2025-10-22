from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


def _normalise_codes(raw: Any) -> set[str]:
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


class ZabbixHostTemplateTeamLocationCheck(BaseCheck):
    """Report hosts that use templates not located under Templates/<TEAM>."""

    meta = CheckMeta(
        id="zabbix.hosts.templates.team_location",
        name="Host templates under Templates/TEAM",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"governance", "configuration"},
        description=(
            "Ensure each host's templates are located in template groups named 'Templates/<TEAM>' for configured teams."
        ),
        explanation=(
            "Placing templates under Templates/<TEAM> encodes ownership and streamlines lifecycle management."
        ),
        remediation=(
            "Move the listed templates to a Templates/<TEAM> group matching an allowed team code, "
            "or expand zabbix.team_codes if new teams are valid."
        ),
        required_facts=("zabbix.hosts", "zabbix.templates"),
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
        hosts = ctx.facts.get("zabbix.hosts", tech="zabbix")
        templates = ctx.facts.get("zabbix.templates", tech="zabbix")

        if not hosts or not templates:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="Missing host or template inventory; ensure provider collected both.",
            )
        if not isinstance(hosts, Sequence) or not isinstance(templates, Sequence):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Unexpected format for zabbix.hosts or zabbix.templates (expected sequences).",
                details={
                    "hosts_type": type(hosts).__name__,
                    "templates_type": type(templates).__name__,
                },
            )

        team_codes = _normalise_codes((ctx.config.get("zabbix") or {}).get("team_codes"))
        if not team_codes:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No team codes configured (zabbix.team_codes); nothing to validate.",
            )

        # Build index: template_id -> template record
        tmpl_index: Dict[str, Mapping[str, Any]] = {}
        for t in templates:
            if not isinstance(t, Mapping):
                continue
            tid = str(t.get("id") or t.get("templateid") or "").strip()
            if tid:
                tmpl_index[tid] = t

        offending_hosts: list[Dict[str, Any]] = []
        evaluated = 0
        for host in hosts:
            if not isinstance(host, Mapping):
                continue
            name = str(host.get("name") or "").strip()
            if not name:
                continue
            tmpl_ids = host.get("template_ids")
            if not isinstance(tmpl_ids, Sequence):
                continue
            evaluated += 1
            offending_templates: list[Dict[str, Any]] = []
            for tid in tmpl_ids:
                tid_text = str(tid)
                t = tmpl_index.get(tid_text)
                if not isinstance(t, Mapping):
                    # Unknown template; consider it offending as we cannot verify placement
                    offending_templates.append({"id": tid_text, "name": None, "groups": []})
                    continue
                groups = t.get("groups")
                group_names = [g.get("name") for g in groups if isinstance(g, Mapping)] if isinstance(groups, Sequence) else []
                # A template is compliant if any group matches Templates/<TEAM> prefix
                compliant = False
                for code in team_codes:
                    prefix = f"templates/{code.lower()}"
                    if any(isinstance(n, str) and n.lower().startswith(prefix) for n in group_names):
                        compliant = True
                        break
                if not compliant:
                    offending_templates.append({
                        "id": tid_text,
                        "name": str(t.get("name") or ""),
                        "groups": group_names,
                    })

            if offending_templates:
                offending_hosts.append({
                    "id": str(host.get("id") or ""),
                    "name": name,
                    "offending_templates": offending_templates,
                })

        if not evaluated:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No hosts evaluated.",
            )

        if offending_hosts:
            sample = ", ".join(h["name"] for h in offending_hosts[:5])
            suffix = f": {sample}" if sample else ""
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=f"{len(offending_hosts)} host(s) use templates outside Templates/<TEAM>{suffix}",
                details={
                    "hosts_with_offending_templates": offending_hosts,
                    "team_codes": sorted(team_codes),
                    "evaluated": evaluated,
                },
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="All evaluated hosts use templates under Templates/<TEAM>.",
            details={"evaluated": evaluated, "team_codes": sorted(team_codes)},
        )


__all__ = ["ZabbixHostTemplateTeamLocationCheck"]

