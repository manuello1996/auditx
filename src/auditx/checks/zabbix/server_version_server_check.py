from __future__ import annotations
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

class ZabbixServerVersionCheck(BaseCheck):
    """Check that the Zabbix server version is >= 6.0 (using facts)."""

    meta = CheckMeta(
        id="zabbix.server.version",
        name="Zabbix Server version",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"availability"},
        description="Ensure Zabbix server is running a supported version (>= 6.0).",
        remediation="Plan an upgrade to Zabbix server 6.0 LTS or newer to benefit from supported security and features.",
        explanation="Zabbix server releases before 6.0 are out of full support and miss recent fixes and stability improvements.",
        required_facts=("zabbix.server.version",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        raw_version = ctx.facts.get("zabbix.server.version", tech="zabbix") or "0"
        version_text = str(raw_version).strip()
        components = [part for part in version_text.replace(" ", "").split(".") if part]
        try:
            major_str = next(("".join(filter(str.isdigit, comp)) for comp in components if comp), "")
        except StopIteration:  # pragma: no cover - defensive
            major_str = ""
        if not major_str:
            for ch in version_text:
                if ch.isdigit():
                    major_str += ch
                    break
        try:
            major = int(major_str) if major_str else int(components[0])
        except Exception:
            major = 0
        try:
            summary_version = version_text or "unknown"
        except Exception:  # pragma: no cover - fallback if non-string
            summary_version = "unknown"

        if major < 6:
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=f"Zabbix server version is {summary_version} (< 6.0)",
                explanation="Zabbix server releases prior to 6.0 lack long-term support and recent security fixes.",
                remediation="Plan an in-place upgrade to Zabbix server 6.0+ and document any configuration changes.",
            )
        return CheckResult(self.meta, Status.PASS, summary=f"Zabbix server version is {summary_version}")

__all__ = ["ZabbixServerVersionCheck"]
