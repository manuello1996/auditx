from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class ZabbixHostGeneralGroupMembershipCheck(BaseCheck):
    """Report hosts not assigned to any General/* host group."""

    meta = CheckMeta(
        id="zabbix.hosts.general_group_membership",
        name="Hosts in General/* group",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"governance", "inventory"},
        description=(
            "Verify that every enabled host belongs to at least one host group whose name starts with 'General/'."
        ),
        explanation=(
            "Membership in a General/* group is required to ensure baseline visibility and policies apply to all hosts."
        ),
        remediation=(
            "Assign each host to at least one General/<subgroup> host group."
        ),
        required_facts=("zabbix.hosts",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        hosts = ctx.facts.get("zabbix.hosts", tech="zabbix")
        if not hosts:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No host inventory available; ensure Zabbix provider collected hosts.",
            )
        if not isinstance(hosts, Sequence):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Unexpected format for zabbix.hosts fact (expected sequence).",
                details={"type": type(hosts).__name__},
            )

        non_compliant: list[Dict[str, str]] = []
        evaluated = 0
        for host in hosts:
            if not isinstance(host, Mapping):
                continue
            name = str(host.get("name") or "").strip()
            groups = host.get("groups")
            if not name:
                continue
            if not isinstance(groups, Sequence):
                evaluated += 1
                non_compliant.append({"id": str(host.get("id") or ""), "name": name})
                continue
            evaluated += 1
            if not any(isinstance(g, str) and g.startswith("General/") for g in groups):
                non_compliant.append({"id": str(host.get("id") or ""), "name": name})

        if not evaluated:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No hosts evaluated.",
            )

        if non_compliant:
            sample = ", ".join(h["name"] for h in non_compliant[:5])
            suffix = f": {sample}" if sample else ""
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=f"{len(non_compliant)} host(s) missing membership in General/*{suffix}",
                details={
                    "hosts_missing_general": non_compliant,
                    "evaluated": evaluated,
                },
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="All evaluated hosts are members of at least one General/* group.",
            details={"evaluated": evaluated},
        )


__all__ = ["ZabbixHostGeneralGroupMembershipCheck"]

