from __future__ import annotations

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

"""Default admin account check: Detect if the default Zabbix Admin account with default password exists.

The default Zabbix installation comes with an "Admin" user account which may still
have the default password "zabbix". This poses a significant security risk as
attackers can easily gain administrative access to the Zabbix instance.

This check verifies whether the default Admin account exists and if it does,
warns about the potential security risk. The check cannot verify the actual
password due to security limitations, but the presence of the default account
suggests it may still have default credentials.
"""


class DefaultAdminAccountCheck(BaseCheck):
    """Check if the default Zabbix Admin account exists, indicating potential security risk.
    
    Zabbix installations come with a default "Admin" user account. If this account
    still exists with default credentials (username "Admin", password "zabbix"),
    it presents a critical security vulnerability. This check identifies if the
    default Admin account is present in the user list.
    """

    meta = CheckMeta(
        id="zabbix.default_admin_account",
        name="Default admin account security check",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.HIGH,
        tags={"security", "authentication", "default-credentials"},
        description="Checks if the default Zabbix Admin account exists, which may indicate default credentials.",
        explanation="The built-in Admin account is publicly documented and becomes a trivial entry point when default credentials persist.",
        remediation="Rename or disable the default Admin user and rotate any credentials that shipped with the installation.",
        inputs=(),
        required_facts=("zabbix.users",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        users = ctx.facts.get("zabbix.users", tech="zabbix") or []
        
        if not isinstance(users, list):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Invalid user data format",
                details={"error": "User data is not in expected list format"},
                explanation="User facts must be a list of mappings for the check to inspect accounts.",
                remediation="Verify the Zabbix API token and ensure the users.get call succeeds before rerunning the audit.",
            )

        if not users:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No user data available",
                details={"user_count": 0},
                explanation="Without a user inventory the presence of the default Admin account cannot be verified.",
                remediation="Collect zabbix.users facts by granting audit credentials the 'User Admin' role and rerun the check.",
            )

        # Check for default Admin account
        admin_users = []
        for user in users:
            if isinstance(user, dict):
                username = user.get("username", "").strip()
                # Check for exact match of "Admin" (case sensitive as Zabbix is case sensitive)
                if username == "Admin":
                    admin_users.append({
                        "id": user.get("id", ""),
                        "username": username,
                        "name": user.get("name", ""),
                        "surname": user.get("surname", ""),
                        "type": user.get("type", ""),
                        "roleid": user.get("roleid", ""),
                    })

        if admin_users:
            # Found default Admin account(s) - this is a security risk
            details = {
                "admin_accounts_found": len(admin_users),
                "accounts": admin_users,
                "total_users": len(users),
            }
            
            if len(admin_users) == 1:
                summary = "Default Admin account found (potential security risk)"
            else:
                summary = f"Multiple Admin accounts found ({len(admin_users)} accounts)"
                
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=summary,
                details=details,
                explanation="Keeping the default Admin account exposes the environment to well-known credential stuffing attacks.",
                remediation=(
                    "Change the default Admin account password or disable/rename the account. "
                    "Ensure all administrative accounts use strong, unique passwords."
                ),
            )
        else:
            # No default Admin account found - good security practice
            return CheckResult(
                meta=self.meta,
                status=Status.PASS,
                summary=f"No default Admin account found ({len(users)} users checked)",
                details={"total_users": len(users)},
            )


__all__ = ["DefaultAdminAccountCheck"]