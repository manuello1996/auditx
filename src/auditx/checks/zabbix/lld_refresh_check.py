from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

_DEFAULT_THRESHOLD_SECONDS = 3600.0


class ZabbixLLDRefreshRateCheck(BaseCheck):
    """Ensure low-level discovery rules don't refresh faster than the configured cadence."""

    meta = CheckMeta(
        id="zabbix.lld.refresh_rate",
        name="Zabbix LLD refresh rate",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"performance", "operations"},
        description="Flag discovery rules whose refresh interval is lower than the configured minimum.",
        explanation="Aggressive discovery refresh floods the server and dependent APIs.",
        remediation="Increase LLD intervals or stagger discovery across proxies to protect pollers.",
        inputs=(
            {
                "key": "zabbix.lld_min_refresh_seconds",
                "required": False,
                "secret": False,
                "description": "Minimum allowed refresh frequency for LLD rules (seconds).",
            },
        ),
        required_facts=("zabbix.discovery_rules",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        rules_fact = ctx.facts.get("zabbix.discovery_rules", tech="zabbix")
        if rules_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No discovery rule facts collected from Zabbix provider",
                explanation="Without discovery metadata you can't validate refresh intervals.",
                remediation="Grant the audit account discovery rule access and refresh the facts cache before rerunning.",
            )
        if not isinstance(rules_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected discovery rule facts structure from provider",
                explanation="Malformed discovery data hides excessive refresh rates.",
                remediation="Upgrade the provider export so zabbix.discovery_rules yields a list of maps.",
            )

        threshold = _resolve_threshold_seconds(ctx.config)

        offending: list[Dict[str, Any]] = []
        unresolved: list[Dict[str, Any]] = []
        ignored_zero_delay: list[Dict[str, Any]] = []
        considered_count = 0

        for rule in rules_fact:
            if not isinstance(rule, Mapping):
                continue
            delay_seconds = rule.get("delay_seconds")
            details = {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "hosts": list(rule.get("hosts") or []),
                "delay_seconds": delay_seconds,
                "delay": rule.get("delay"),
            }
            if isinstance(delay_seconds, (int, float)):
                if float(delay_seconds) == 0:
                    ignored_zero_delay.append(details)
                    continue
                considered_count += 1
                if delay_seconds < threshold:
                    offending.append(details)
            else:
                unresolved.append(details)

        if considered_count == 0 and not unresolved:
            summary = "No discovery rules with refresh intervals to evaluate"
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary=summary,
                details={
                    "threshold_seconds": threshold,
                    "offending_rules": offending,
                    "unresolved_rules": unresolved,
                    "ignored_zero_delay_rules": ignored_zero_delay,
                    "sample_size": considered_count,
                    "total_rules": len(rules_fact),
                },
                explanation="If no rules are evaluable, discovery cadence remains unchecked.",
                remediation="Ensure delay_seconds is numeric and discovery rules are linked to hosts before retrying.",
            )

        details_payload = {
            "threshold_seconds": threshold,
            "offending_rules": offending,
            "unresolved_rules": unresolved,
            "ignored_zero_delay_rules": ignored_zero_delay,
            "sample_size": considered_count,
            "total_rules": len(rules_fact),
        }

        if offending:
            fastest = min(offending, key=lambda item: item["delay_seconds"] or 0)
            offending_descriptions = "; ".join(_describe_rule(rule) for rule in offending)
            summary = (
                f"{len(offending)} LLD rule(s) refresh faster than {_format_duration(threshold)} "
                f"(fastest { _format_duration(fastest['delay_seconds']) })"
            )
            if offending_descriptions:
                summary += f": {offending_descriptions}"
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=summary,
                details=details_payload,
                explanation="Fast discovery loops consume API quotas and poller slots needlessly.",
                remediation="Raise the delay for the listed LLD rules or distribute them across proxies.",
            )

        if unresolved:
            unresolved_descriptions = "; ".join(_describe_rule(rule) for rule in unresolved)
            summary = f"{len(unresolved)} LLD rule(s) have non-numeric refresh intervals"
            if unresolved_descriptions:
                summary += f": {unresolved_descriptions}"
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details_payload,
                explanation="Non-numeric delays make discovery cadence unpredictable.",
                remediation="Normalize discovery rule delay syntax to seconds or supported cron expressions.",
            )

        summary = f"All LLD rules refresh slower than or equal to {_format_duration(threshold)}"
        return CheckResult(self.meta, Status.PASS, summary=summary, details=details_payload)


def _describe_rule(rule: Mapping[str, Any]) -> str:
    name = str(rule.get("name", rule.get("id", "unknown")))
    delay = _format_duration(rule.get("delay_seconds"))
    hosts = rule.get("hosts") or []
    if hosts:
        host_part = ", ".join(str(host) for host in hosts)
        return f"{name} (hosts: {host_part}, delay: {delay})"
    return f"{name} (delay: {delay})"


def _resolve_threshold_seconds(config: Mapping[str, Any]) -> float:
    section = config.get("zabbix") if isinstance(config, Mapping) else None
    candidate: Any = None
    if isinstance(section, Mapping):
        candidate = section.get("lld_min_refresh_seconds")
    try:
        if candidate is None:
            raise ValueError
        value = float(candidate)
        if value <= 0:
            raise ValueError
        return value
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD_SECONDS


def _format_duration(value: float | None) -> str:
    if value is None:
        return "unknown"
    seconds = float(value)
    if seconds % 3600 == 0:
        hours = seconds / 3600
        return f"{hours:g}h"
    if seconds % 60 == 0:
        minutes = seconds / 60
        return f"{minutes:g}m"
    return f"{seconds:g}s"


__all__ = ["ZabbixLLDRefreshRateCheck"]
