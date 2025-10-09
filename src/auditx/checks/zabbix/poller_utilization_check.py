from __future__ import annotations

from typing import Any, Dict, List

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


POLLER_DISPLAY_NAMES: Dict[str, str] = {
    "odbc_poller": "ODBC poller",
    "agent_poller": "agent poller",
    "browser_poller": "browser poller",
    "http_agent_poller": "http agent poller",
    "http_poller": "http poller",
    "icmp_pinger": "icmp pinger",
    "internal_poller": "internal poller",
    "poller": "poller",
    "proxy_poller": "proxy poller",
    "snmp_poller": "snmp poller",
    "trapper": "trapper",
    "unreachable_poller": "unreachable poller",
}


def _poller_display_name(poller_key: str) -> str:
    """Return the dashboard-style label for a poller process."""

    return POLLER_DISPLAY_NAMES.get(poller_key, poller_key)


class ZabbixPollerUtilizationCheck(BaseCheck):
    """Ensure Zabbix server poller-type processes are within healthy utilization levels."""

    meta = CheckMeta(
        id="zabbix.process.poller_utilization",
        name="Zabbix poller process utilization",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"performance", "monitoring", "process"},
        description=(
            "Verifies that Zabbix server poller-oriented processes are neither overloaded nor severely underused. "
            "High busy percentages can indicate undersized process pools, while consistently idle processes may point "
            "to over-provisioned workers or misconfiguration."
        ),
        explanation="Poller saturation delays checks, while idle pollers waste capacity that could be reassigned.",
        remediation="Tune StartPollers* settings so average busy time stays within the configured band.",
        inputs=(
            {
                "key": "zabbix.pollers.min_busy_percent",
                "required": False,
                "secret": False,
                "description": (
                    "Minimum acceptable average busy percentage for poller processes. Defaults to 40.0%."
                ),
            },
            {
                "key": "zabbix.pollers.max_busy_percent",
                "required": False,
                "secret": False,
                "description": (
                    "Maximum acceptable average busy percentage for poller processes. Defaults to 60.0%."
                ),
            },
        ),
        required_facts=("zabbix.process.pollers",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        poller_fact = ctx.facts.get("zabbix.process.pollers", tech="zabbix")
        if poller_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No poller process facts collected from Zabbix provider",
                explanation="Without poller metrics you can't see utilization hotspots.",
                remediation="Ensure the audit account can query zabbix[process,<type>,avg,busy] metrics and refresh facts.",
            )

        if not isinstance(poller_fact, Dict):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected poller process facts structure from provider",
                explanation="Malformed poller data hides saturation trends.",
                remediation="Upgrade the provider export so poller metrics return a mapping keyed by process type.",
            )

        min_busy = float(ctx.config.get("zabbix.pollers.min_busy_percent", 40.0))
        max_busy = float(ctx.config.get("zabbix.pollers.max_busy_percent", 60.0))

        if min_busy >= max_busy:
            return CheckResult(
                self.meta,
                Status.ERROR,
                summary="Invalid configuration: minimum poller utilization must be less than maximum",
                explanation="Reversed thresholds make the utilization band meaningless.",
                remediation="Set zabbix.pollers.min_busy_percent lower than the max value before re-running the check.",
            )

        problems: List[str] = []
        poller_details: Dict[str, Any] = {}

        for poller_name, poller_info in poller_fact.items():
            if not isinstance(poller_info, Dict):
                continue

            busy_percent = poller_info.get("busy_percent")
            if busy_percent is None:
                continue

            try:
                busy_value = float(busy_percent)
            except (TypeError, ValueError):
                continue

            display_name = _poller_display_name(poller_name)
            poller_details[poller_name] = {
                "display_name": display_name,
                "busy_percent": busy_value,
                "status": "ok",
            }

            if busy_value < min_busy:
                problems.append(f"{display_name}: {busy_value:.1f}% (under-utilized)")
                poller_details[poller_name]["status"] = "under-utilized"
            elif busy_value > max_busy:
                problems.append(f"{display_name}: {busy_value:.1f}% (over-utilized)")
                poller_details[poller_name]["status"] = "over-utilized"

        total_pollers = len(poller_details)
        if total_pollers == 0:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No valid poller utilization data available from Zabbix",
                explanation="Missing poller metrics block sizing decisions.",
                remediation="Collect zabbix[process,...] items on the server or proxies before running this check.",
            )

        if problems:
            status = Status.WARN
            problem_summary = "; ".join(problems)
            summary = (
                f"Zabbix poller utilization issues detected: "
                f"{len(problems)} out of {total_pollers} poller processes outside "
                f"{min_busy:.1f}%-{max_busy:.1f}% busy range. "
                f"Offending pollers: {problem_summary}"
            )
        else:
            status = Status.PASS
            summary = (
                f"All {total_pollers} Zabbix poller processes within healthy busy range "
                f"({min_busy:.1f}%-{max_busy:.1f}%)"
            )

        details = {
            "pollers": poller_details,
            "problems": problems,
            "thresholds": {
                "min_busy_percent": min_busy,
                "max_busy_percent": max_busy,
            },
            "total_pollers": total_pollers,
            "problem_pollers": len(problems),
        }

        remediation: str | None = None
        explanation: str | None = None
        if problems:
            remediation = (
                "Review the configured number of poller-type processes on the Zabbix server. "
                "Over-utilized pollers may require increasing the process pool or distributing load. "
                "Under-utilized pollers can often be reduced to free resources."
            )
            explanation = "Imbalanced poller pools either drop checks or waste server resources."

        return CheckResult(
            meta=self.meta,
            status=status,
            summary=summary,
            details=details,
            remediation=remediation,
            explanation=explanation,
        )


__all__ = ["ZabbixPollerUtilizationCheck", "POLLER_DISPLAY_NAMES"]
