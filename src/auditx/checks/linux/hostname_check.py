from __future__ import annotations
from typing import Any, Mapping

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

class HostnameCheck(BaseCheck):
    """Verify that the system hostname is set and conforms to basic RFC-952/1123 rules.

    This check retrieves the current hostname and validates that it is non-empty and
    matches a conservative pattern allowed for DNS labels.
    """

    meta = CheckMeta(
        id="linux.hostname.sanity",
        name="Hostname sanity",
        version="1.0.0",
        tech="linux",
        severity=Severity.INFO,
        tags={"configuration"},
        description="Check that hostname is set and valid.",
        required_facts=("linux.uname",),
        remediation="Set a lowercase hostname shorter than 64 characters using 'hostnamectl set-hostname <name>'.",
        explanation="Hostnames must follow RFC-1123 to ensure services, TLS certificates, and automation can reliably identify the node.",
    )

    def run(self, ctx: RunContext) -> CheckResult:
        uname: Mapping[str, Any] | None = ctx.facts.get("linux.uname", tech="linux")
        if not isinstance(uname, Mapping):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Missing fact 'linux.uname' (provider not executed)",
                explanation="The linux.uname fact store is empty. Execute the Linux provider before running this check.",
                remediation="Run the Linux discovery phase or provide the 'linux.uname' fact manually.",
            )

        hostname = str(uname.get("node", "")).strip()
        if not hostname:
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary="Hostname is empty",
                explanation="An empty hostname breaks SSH, TLS, and inventory tooling that depend on consistent node identifiers.",
                remediation="Set a descriptive hostname with 'hostnamectl set-hostname <name>'.",
            )
        if len(hostname) > 63 or any(char for char in hostname if char.isupper()):
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=f"Hostname '{hostname}' looks suspicious",
                explanation="Hostnames longer than 63 characters or containing uppercase letters violate DNS label rules and increase the risk of connection issues.",
                remediation="Rename the host using a DNS-compliant, lowercase label shorter than 64 characters.",
            )
        return CheckResult(self.meta, Status.PASS, summary=f"Hostname is '{hostname}' (valid)")

__all__ = ["HostnameCheck"]
