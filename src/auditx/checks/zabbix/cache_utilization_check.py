from __future__ import annotations


from typing import Any, Dict, List

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

"""Check Zabbix cache utilization.

Monitors the key Zabbix caches (configuration, history, history index, trend, value) across
modern ``zabbix[cache,...]`` metrics and legacy ``zabbix[rcache|wcache|vcache,...]`` variants
to ensure they are neither under-utilized nor over-utilized beyond acceptable thresholds.
"""

CACHE_DISPLAY_NAMES: Dict[str, str] = {
    "cache_config": "Configuration cache",
    "cache_hist_index": "History index cache",
    "cache_history": "History write cache",
    "cache_trend": "Trend write cache",
    "cache_value": "Value cache",
}


def _cache_display_name(cache_key: str) -> str:
    """Return the human-readable cache label shown in the Zabbix dashboard."""

    return CACHE_DISPLAY_NAMES.get(cache_key, cache_key)


class ZabbixCacheUtilizationCheck(BaseCheck):
    """Verify that Zabbix cache utilization is within optimal range."""

    meta = CheckMeta(
        id="zabbix.cache.utilization",
        name="Zabbix cache utilization",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"performance", "monitoring", "cache"},
        description=(
            "Verifies that Zabbix caches are utilized within optimal range. "
            "Caches with utilization outside the target range may indicate "
            "configuration issues or performance problems."
        ),
        explanation="Balanced cache utilization keeps pollers responsive and prevents history ingestion backlogs.",
        remediation="Tune CacheSize parameters so utilization remains between the configured minimum and maximum during peak load.",
        inputs=(
            {
                "key": "zabbix.cache.min_utilization_percent",
                "required": False,
                "secret": False,
                "description": (
                    "Minimum acceptable cache utilization percentage. "
                    "Defaults to 40.0%."
                ),
            },
            {
                "key": "zabbix.cache.max_utilization_percent",
                "required": False,
                "secret": False,
                "description": (
                    "Maximum acceptable cache utilization percentage. "
                    "Defaults to 60.0%."
                ),
            },
        ),
        required_facts=("zabbix.cache",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        cache_fact = ctx.facts.get("zabbix.cache", tech="zabbix")
        if cache_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No cache facts collected from Zabbix provider",
                explanation="Without cache metrics the check cannot determine whether sizing issues exist.",
                remediation="Review the Zabbix agent configuration and ensure zabbix[cache,...] metrics are collected.",
            )
        
        if not isinstance(cache_fact, Dict):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected cache facts structure from provider",
                explanation="Cache facts should be a mapping per cache; malformed data hides saturation trends.",
                remediation="Upgrade the provider or API permissions to expose zabbix[cache,...] metrics before rerunning.",
            )

        # Get configuration thresholds
        min_util = float(ctx.config.get("zabbix.cache.min_utilization_percent", 40.0))
        max_util = float(ctx.config.get("zabbix.cache.max_utilization_percent", 60.0))

        if min_util >= max_util:
            return CheckResult(
                self.meta,
                Status.ERROR,
                summary="Invalid configuration: minimum utilization must be less than maximum",
                explanation="Reversed thresholds make the check meaningless and hide genuine cache pressure.",
                remediation="Set zabbix.cache.min_utilization_percent lower than the max value in configuration overrides.",
            )

        # Analyze each cache
        problems: List[str] = []
        cache_details: Dict[str, Any] = {}
        
        for cache_name, cache_info in cache_fact.items():
            if not isinstance(cache_info, Dict):
                continue
                
            used_percent = cache_info.get("used_percent")
            if used_percent is None:
                continue
            display_name = _cache_display_name(cache_name)
            cache_details[cache_name] = {
                "display_name": display_name,
                "used_percent": used_percent,
                "free_percent": cache_info.get("free_percent"),
                "status": "ok",
            }
            
            if used_percent < min_util:
                problems.append(f"{display_name}: {used_percent:.1f}% (under-utilized)")
                cache_details[cache_name]["status"] = "under-utilized"
            elif used_percent > max_util:
                problems.append(f"{display_name}: {used_percent:.1f}% (over-utilized)")
                cache_details[cache_name]["status"] = "over-utilized"

        total_caches = len(cache_details)
        if total_caches == 0:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No valid cache data available from Zabbix",
                explanation="The provider returned cache entries without 'used_percent', so utilization could not be assessed.",
                remediation="Confirm cache metrics collection and rerun the audit once zabbix[cache,...] metrics include utilization.",
            )

        # Determine overall status
        if problems:
            status = Status.FAIL
            problem_summary = "; ".join(problems)
            summary = (
                f"Zabbix cache utilization issues detected: "
                f"{len(problems)} out of {total_caches} caches outside "
                f"{min_util:.1f}%-{max_util:.1f}% range. "
                f"Offending caches: {problem_summary}"
            )
        else:
            status = Status.PASS
            summary = (
                f"All {total_caches} Zabbix caches within optimal utilization range "
                f"({min_util:.1f}%-{max_util:.1f}%)"
            )

        details = {
            "caches": cache_details,
            "problems": problems,
            "thresholds": {
                "min_utilization_percent": min_util,
                "max_utilization_percent": max_util,
            },
            "total_caches": total_caches,
            "problem_caches": len(problems),
        }

        remediation: str | None = None
        explanation: str | None = None
        if problems:
            remediation = (
                "Review cache configuration in Zabbix server settings. "
                "Under-utilized caches may indicate oversized cache configuration. "
                "Over-utilized caches may require increased cache size or optimization of data retention policies."
            )
            explanation = (
                "One or more caches are outside the target utilization band, which can waste memory or stall history ingestion."
            )

        return CheckResult(
            meta=self.meta,
            status=status,
            summary=summary,
            details=details,
            remediation=remediation,
            explanation=explanation,
        )


__all__ = ["ZabbixCacheUtilizationCheck", "CACHE_DISPLAY_NAMES"]