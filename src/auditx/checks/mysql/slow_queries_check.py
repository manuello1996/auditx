from __future__ import annotations
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

class SlowQueriesCheck(BaseCheck):
    """Ensure slow_query_log is enabled and long_query_time <= 1.0 seconds.
    (Skeleton: relies on facts or future DB client integration.)"""

    meta = CheckMeta(
        id="mysql.slowqueries.threshold",
        name="Slow queries threshold",
        version="1.0.0",
        tech="mysql",
        severity=Severity.MEDIUM,
        tags={"performance"},
        description="Checks slow_query_log and long_query_time using collected facts.",
        remediation="Enable slow_query_log=ON and set long_query_time to 1.0 seconds or less, then restart MySQL if required.",
        explanation="Slow query logging is essential to detect expensive statements and adjust indexes or query plans.",
        inputs=(
            {"key": "mysql.user", "required": True, "secret": False, "description": "MySQL username"},
            {"key": "mysql.password", "required": True, "secret": True, "description": "Password"},
            {"key": "mysql.database", "required": True, "secret": False, "description": "Database"},
            {"key": "mysql.host", "required": True, "secret": False, "description": "Host"},
            {"key": "mysql.port", "required": False, "secret": False, "description": "Port (default 3306)"},
        ),
        required_facts=("mysql.variables",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        vars = ctx.facts.get("mysql.variables", tech="mysql") or {}
        slow = vars.get("slow_query_log", "OFF")
        try:
            lqt = float(vars.get("long_query_time", "10"))
        except Exception:
            lqt = 10.0
        if str(slow).upper() != "ON":
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=f"slow_query_log is {slow}",
                explanation="With slow_query_log disabled, slow statements are never captured for analysis.",
                remediation="Set slow_query_log=ON in my.cnf (mysqld section) and reload MySQL to start capturing samples.",
            )
        if lqt > 1.0:
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=f"long_query_time is {lqt}s (> 1.0s)",
                explanation="A long_query_time above 1s delays detection of problematic statements.",
                remediation="Adjust long_query_time to 1.0 or lower and restart or apply SET GLOBAL long_query_time=1.0.",
            )
        return CheckResult(self.meta, Status.PASS, summary=f"slow_query_log ON, long_query_time {lqt}s")
__all__ = ["SlowQueriesCheck"]
