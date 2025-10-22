from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status

_DEFAULT_THRESHOLD_RATIO = 0.1
_DEFAULT_PROXY_RATIO = 0.1


class ZabbixHostProxyCoverageCheck(BaseCheck):
    """Ensure most monitored hosts are collected via proxies."""

    meta = CheckMeta(
        id="zabbix.hosts.proxy_coverage",
        name="Zabbix host proxy coverage",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"scalability", "best-practice"},
        description=(
            "Alerts when too many monitored hosts are polled directly by the server or by single proxies. "
            "Policy: <= 10% by server (configurable) and <= 10% by proxy (configurable); the rest via proxy-groups."
        ),
        explanation=(
            "Polling large fleets directly from the server increases latency and can overwhelm data collection threads. "
            "Relying heavily on single proxies can also create bottlenecks; proxy-groups distribute load and add resilience."
        ),
        remediation=(
            "Deploy proxies and proxy-groups near monitored networks. Move hosts off direct server polling and "
            "from single proxies to proxy-groups where feasible."
        ),
        inputs=(
            {
                "key": "zabbix.server_monitored_ratio_threshold",
                "required": False,
                "secret": False,
                "description": (
                    "Maximum allowed fraction (0.0-1.0) of monitored hosts collected directly by "
                    "the Zabbix server before raising an alert. Defaults to 0.1 (10%)."
                ),
            },
            {
                "key": "zabbix.proxy_monitored_ratio_threshold",
                "required": False,
                "secret": False,
                "description": (
                    "Maximum allowed fraction (0.0-1.0) of monitored hosts collected via a single proxy (not proxy-group) "
                    "before raising an alert. Defaults to 0.1 (10%)."
                ),
            },
        ),
        required_facts=("zabbix.hosts",),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        hosts_fact = ctx.facts.get("zabbix.hosts", tech="zabbix")
        if hosts_fact is None:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No host facts collected from Zabbix provider",
                explanation="Without host inventory you can't gauge proxy coverage.",
                remediation="Allow the audit account to retrieve host.get data and refresh facts before rerunning.",
            )
        if not isinstance(hosts_fact, Sequence):
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unexpected host facts structure from provider",
                explanation="Malformed host data hides proxy assignment issues.",
                remediation="Upgrade the provider or API version so zabbix.hosts returns a list of host objects.",
            )

        monitored_hosts = [host for host in hosts_fact if _is_monitored_host(host)]
        if not monitored_hosts:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No monitored hosts returned by Zabbix",
                explanation="If no hosts are reported, proxy coverage cannot be evaluated.",
                remediation="Verify the audit credentials can access active hosts or sync the configuration first.",
            )

        classification = _classify_hosts(monitored_hosts)
        unknown = classification[MonitorRole.UNKNOWN]
        if unknown:
            details = {
                "unknown_hosts": unknown,
                "server": classification[MonitorRole.SERVER],
                "proxy": classification[MonitorRole.PROXY],
                "proxy_group": classification[MonitorRole.PROXY_GROUP],
                "total_monitored_hosts": len(monitored_hosts),
            }
            summary = (
                f"{len(unknown)} monitored host(s) have unknown monitoring topology."
                " Configure proxy assignments or upgrade discovery."
            )
            return CheckResult(
                self.meta,
                Status.WARN,
                summary=summary,
                details=details,
                explanation="Unknown topology suggests proxies or server assignments are drifting.",
                remediation="Refresh autoregistration or set explicit proxy assignments for the listed hosts.",
            )

        known_total = classification["known_total"]
        if known_total == 0:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="Unable to determine monitoring topology for any host",
                details={"total_monitored_hosts": len(monitored_hosts)},
                explanation="Without topology info you can't plan proxy scaling.",
                remediation="Expose proxy_ids or monitored_by attributes through the API by upgrading Zabbix before rerunning.",
            )

        server_hosts = classification[MonitorRole.SERVER]
        proxy_hosts = classification[MonitorRole.PROXY]
        proxy_group_hosts = classification[MonitorRole.PROXY_GROUP]

        server_ratio = len(server_hosts) / known_total
        proxy_ratio = len(proxy_hosts) / known_total
        proxy_group_ratio = len(proxy_group_hosts) / known_total

        server_threshold = _resolve_threshold_ratio(ctx.config)
        proxy_threshold = _resolve_proxy_threshold_ratio(ctx.config)
        details = {
            "server_hosts": server_hosts,
            "proxy_hosts": proxy_hosts,
            "proxy_group_hosts": proxy_group_hosts,
            "total_monitored_hosts": known_total,
            "server_monitored_ratio": server_ratio,
            "proxy_monitored_ratio": proxy_ratio,
            "proxy_group_ratio": proxy_group_ratio,
            "allowed_server_ratio": server_threshold,
            "allowed_proxy_ratio": proxy_threshold,
        }

        if server_ratio > server_threshold:
            summary = (
                f"{len(server_hosts)} of {known_total} monitored host(s) are handled directly by the "
                f"server ({_format_ratio(server_ratio)}), exceeding the allowed {_format_ratio(server_threshold)}."
            )
            if server_hosts:
                summary += f" Affected hosts: {_format_host_list(server_hosts)}."
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=summary,
                details=details,
                explanation="Polling many hosts centrally strains the server and increases network latency.",
                remediation="Deploy additional proxies or migrate the listed hosts onto existing proxies.",
            )

        if proxy_ratio > proxy_threshold:
            summary = (
                f"{len(proxy_hosts)} of {known_total} monitored host(s) are handled by single proxies "
                f"({_format_ratio(proxy_ratio)}), exceeding the allowed {_format_ratio(proxy_threshold)}."
            )
            if proxy_hosts:
                summary += f" Affected hosts: {_format_host_list(proxy_hosts)}."
            return CheckResult(
                self.meta,
                Status.FAIL,
                summary=summary,
                details=details,
                explanation="Too many hosts on single proxies can create bottlenecks; prefer proxy-groups for scale/resilience.",
                remediation="Create or expand proxy-groups and migrate hosts from single proxies to proxy-groups.",
            )

        summary = (
            f"Server-monitored {_format_ratio(server_ratio)} and proxy-monitored {_format_ratio(proxy_ratio)} "
            f"are within allowed thresholds (server {_format_ratio(server_threshold)}, proxy {_format_ratio(proxy_threshold)})."
        )
        return CheckResult(self.meta, Status.PASS, summary=summary, details=details)


class MonitorRole:
    SERVER = "server"
    PROXY = "proxy"
    PROXY_GROUP = "proxy_group"
    UNKNOWN = "unknown"


def _is_monitored_host(host: Mapping[str, Any]) -> bool:
    try:
        status = str(host.get("status"))
    except Exception:  # pragma: no cover - defensive
        return False
    return status == "0"


def _classify_hosts(hosts: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    buckets: Dict[str, Any] = {
        MonitorRole.SERVER: [],
        MonitorRole.PROXY: [],
        MonitorRole.PROXY_GROUP: [],
        MonitorRole.UNKNOWN: [],
    }
    known_total = 0

    for host in hosts:
        label = _host_label(host)
        role = _determine_role(host)
        if role == MonitorRole.SERVER:
            buckets[MonitorRole.SERVER].append(label)
            known_total += 1
        elif role == MonitorRole.PROXY:
            buckets[MonitorRole.PROXY].append(label)
            known_total += 1
        elif role == MonitorRole.PROXY_GROUP:
            buckets[MonitorRole.PROXY_GROUP].append(label)
            known_total += 1
        else:
            buckets[MonitorRole.UNKNOWN].append(label)

    buckets["known_total"] = known_total
    return buckets


def _determine_role(host: Mapping[str, Any]) -> str:
    proxy_group_ids = _as_id_list(host.get("proxy_group_ids"))
    if proxy_group_ids:
        return MonitorRole.PROXY_GROUP

    proxy_ids = _as_id_list(host.get("proxy_ids"))
    if proxy_ids:
        return MonitorRole.PROXY

    monitored_by = str(host.get("monitored_by") or "").strip()
    if monitored_by == "2":
        return MonitorRole.PROXY_GROUP
    if monitored_by == "1":
        return MonitorRole.PROXY
    if monitored_by == "0":
        return MonitorRole.SERVER

    return MonitorRole.UNKNOWN


def _resolve_threshold_ratio(config: Mapping[str, Any]) -> float:
    section = config.get("zabbix") if isinstance(config, Mapping) else None
    candidate: Any = None
    if isinstance(section, Mapping):
        candidate = section.get("server_monitored_ratio_threshold")
    try:
        if candidate is None:
            raise ValueError
        value = float(candidate)
        if value < 0:
            raise ValueError
        return value
    except (TypeError, ValueError):
        return _DEFAULT_THRESHOLD_RATIO


def _resolve_proxy_threshold_ratio(config: Mapping[str, Any]) -> float:
    section = config.get("zabbix") if isinstance(config, Mapping) else None
    candidate: Any = None
    if isinstance(section, Mapping):
        candidate = section.get("proxy_monitored_ratio_threshold")
    try:
        if candidate is None:
            raise ValueError
        value = float(candidate)
        if value < 0:
            raise ValueError
        return value
    except (TypeError, ValueError):
        return _DEFAULT_PROXY_RATIO


def _as_id_list(value: Any) -> List[str]:
    result: List[str] = []
    if value is None:
        return result
    if isinstance(value, (list, tuple, set)):
        iterable: Iterable[Any] = value
    else:
        iterable = (value,)
    for entry in iterable:
        text = str(entry).strip()
        if text and text != "0" and text not in result:
            result.append(text)
    return result


def _host_label(host: Mapping[str, Any]) -> str:
    for key in ("name", "host", "display_name"):
        value = host.get(key)
        if value:
            return str(value)
    for key in ("id", "hostid"):
        value = host.get(key)
        if value:
            return f"id={value}"
    return "unknown-host"


def _format_ratio(value: float) -> str:
    return f"{value * 100:.1f}%"


def _format_host_list(hosts: Sequence[str], limit: int = 5) -> str:
    if not hosts:
        return "none"
    if len(hosts) <= limit:
        return ", ".join(hosts)
    remainder = len(hosts) - limit
    return f"{', '.join(hosts[:limit])}, … (+{remainder} more)"


__all__ = ["ZabbixHostProxyCoverageCheck"]
