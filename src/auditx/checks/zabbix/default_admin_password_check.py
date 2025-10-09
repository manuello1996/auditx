from __future__ import annotations

from typing import Any, Dict

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class DefaultAdminPasswordCheck(BaseCheck):
    """Ensure the Zabbix default Admin account no longer accepts the factory password."""

    meta = CheckMeta(
        id="zabbix.default_admin_password",
        name="Default admin password security check",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.CRITICAL,
        tags={"security", "authentication", "default-credentials"},
        description=(
            "Checks whether the Zabbix 'Admin' account still authenticates with the default password 'zabbix'."
        ),
        explanation="Leaving the factory Admin password in place gives attackers immediate privileged access.",
        remediation="Change the Admin account password and review other built-in accounts for default credentials.",
        required_facts=("zabbix.admin.default_password_valid",),
        inputs=(),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        fact_value = ctx.facts.get("zabbix.admin.default_password_valid", tech="zabbix")
        if fact_value is None:
            warning = ctx.facts.get("zabbix.warning.admin_default_password", tech="zabbix")
            details: Dict[str, Any] = {}
            if warning:
                details["warning"] = warning
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="Unable to determine whether the default Admin password is still valid.",
                details=details,
                remediation=(
                    "Verify API connectivity and ensure the provider can attempt to authenticate with the default credentials."
                ),
                explanation="The provider could not confirm whether the default credentials work, leaving a blind spot in the audit.",
            )

        if not isinstance(fact_value, bool):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Unexpected fact format for zabbix.admin.default_password_valid.",
                details={"type": type(fact_value).__name__},
                explanation="The fact should be a boolean outcome; malformed data prevents detecting unsafe credentials.",
                remediation="Check the provider version and regenerate facts to obtain a boolean result before retrying.",
            )

        if fact_value:
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary="Default Zabbix Admin account still accepts the factory password.",
                details={"default_password_accepted": True},
                remediation=(
                    "Change the Admin account password immediately or disable the account to prevent unauthorised access."
                ),
                explanation="Attackers routinely scan for the factory Admin/zabbix credential pair and can take control instantly if it works.",
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="Default Zabbix Admin password has been changed or the account is secured.",
            details={"default_password_accepted": False},
        )


__all__ = ["DefaultAdminPasswordCheck"]
