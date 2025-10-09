from __future__ import annotations
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

class ZabbixVersionCheck(BaseCheck):
    """Check that Zabbix API is reachable and version is >= 6.0 (using facts)."""

    meta = CheckMeta(
        id="zabbix.api.version",
        name="Zabbix API version",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.LOW,
        tags={"availability"},
        description="Ensure Zabbix API is reachable and reports expected version.",
        remediation="Plan an upgrade to Zabbix 6.0 LTS or newer to benefit from supported security and API features.",
        explanation="Zabbix releases before 6.0 are out of full support and miss recent fixes and API stability guarantees.",
        inputs=(
            {"key": "zabbix.api_url", "required": True, "secret": False},
            {"key": "zabbix.api_token", "required": False, "secret": True, "description": "Preferred authentication method."},
            {"key": "zabbix.username", "required": False, "secret": False, "description": "Required if api_token absent."},
            {"key": "zabbix.password", "required": False, "secret": True, "description": "Required if api_token absent."},
        ),
        required_facts=("zabbix.api.version",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        v = (ctx.facts.get("zabbix.api.version", tech="zabbix") or "0").split(".")
        try:
            major = int(v[0])
        except Exception:
            major = 0
        if major < 6:
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=f"Zabbix API version is {'.'.join(v)} (< 6.0)",
                explanation="Zabbix releases prior to 6.0 lack long-term support and recent API security fixes.",
                remediation="Plan an in-place upgrade to 6.0+ and document API changes for integrations.",
            )
        return CheckResult(self.meta, Status.PASS, summary=f"Zabbix API version is {'.'.join(v)}")
__all__ = ["ZabbixVersionCheck"]
