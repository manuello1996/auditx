from __future__ import annotations
import re
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence

from auditx.core.facts import register_provider

# Required dependency: zabbix-utils
try:
    from zabbix_utils import ZabbixAPI  # type: ignore
except Exception as exc:  # pragma: no cover
    raise RuntimeError("zabbix-utils is required for Zabbix providers. Install auditx[zabbix].") from exc


def _zabbix_base(
    params: dict[str, Any],
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Collect minimal Zabbix facts using token or username/password.

    This function gathers a minimal set of Zabbix facts to enable fast, low-privilege
    discovery of the monitored environment, supporting checks that require only basic
    inventory and configuration data. Collecting minimal facts reduces API load and
    exposure of sensitive information, aligning with the principle of least privilege.
    Both API token and username/password authentication are supported to accommodate
    different Zabbix deployments and user access models, ensuring compatibility with
    environments where only one method may be available or preferred.
    """

    def report(task: str) -> None:
        if progress:
            progress(task)

    params = params or {}
    api_url = params.get("api_url")
    if not api_url:
        return {"zabbix.error": "Missing Zabbix API url (zabbix.api_url)"}

    token = params.get("api_token")
    username = params.get("username")
    password = params.get("password")

    if token:
        auth_kwargs = {"token": token}
        auth_method = "token"
    elif username and password:
        auth_kwargs = {"user": username, "password": password}
        auth_method = "credentials"
    else:
        return {"zabbix.error": "Provide either zabbix.api_token or zabbix.username/zabbix.password"}

    report("Preparing Zabbix client configuration")
    client_kwargs: Dict[str, Any] = {"url": api_url}
    if params.get("timeout") is not None:
        client_kwargs["timeout"] = int(params["timeout"])
    if "validate_certs" in params:
        client_kwargs["validate_certs"] = bool(params["validate_certs"])

    facts: Dict[str, Any] = {}
    client: ZabbixAPI | None = None
    try:
        report("Connecting to Zabbix API")
        client = ZabbixAPI(**client_kwargs, **auth_kwargs)
        facts["zabbix.auth.method"] = auth_method
        try:
            facts["zabbix.api.version"] = str(client.version)
        except Exception as err:  # pragma: no cover
            facts["zabbix.api.version"] = None
            facts["zabbix.warning.version"] = str(err)

        version_value: Optional[str] = None
        version_source: Optional[Dict[str, Any]] = None
        release_value: Optional[str] = None

        try:
            report("Fetching server version items")
            version_items = client.item.get(  # type: ignore[attr-defined]
                output=["itemid", "key_", "lastvalue", "lastclock"],
                filter={"key_": ["zabbix[version]", "zabbix[version,full]"]},
                selectHosts=["hostid", "name", "host"],
            )
        except Exception as err:
            facts.setdefault("zabbix.warning.server_version_item", str(err))
        else:
            for item in version_items or []:
                if not isinstance(item, Mapping):
                    continue
                last_value = _coerce_str(item.get("lastvalue")).strip()
                if not last_value:
                    continue

                version_value = last_value
                version_source = {
                    "item_id": _coerce_str(item.get("itemid")),
                    "key": _coerce_str(item.get("key_")),
                    "host_ids": [
                        _coerce_str(host.get("hostid"))
                        for host in (item.get("hosts") or [])
                        if isinstance(host, Mapping)
                    ],
                    "hosts": [
                        _coerce_str(host.get("name") or host.get("host"))
                        for host in (item.get("hosts") or [])
                        if isinstance(host, Mapping)
                    ],
                    "last_clock": _coerce_int(item.get("lastclock")),
                }
                break

        try:
            report("Querying server information")
            server_response = client.serverinfo.get()  # type: ignore[attr-defined]
        except Exception as err:
            if version_value is None:
                facts.setdefault("zabbix.warning.server_version", str(err))
        else:
            payload: Any = server_response
            if isinstance(server_response, Mapping):
                payload = server_response.get("result", server_response)

            def _extract(entry: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
                raw_version = _coerce_str(entry.get("version")).strip()
                raw_release = _coerce_str(entry.get("release")).strip()
                return (raw_version or None, raw_release or None)

            extracted_version: Optional[str] = None
            extracted_release: Optional[str] = None
            if isinstance(payload, Mapping):
                extracted_version, extracted_release = _extract(payload)
            elif isinstance(payload, Sequence):
                for entry in payload:
                    if not isinstance(entry, Mapping):
                        continue
                    extracted_version, extracted_release = _extract(entry)
                    if extracted_version or extracted_release:
                        break

            if extracted_version and version_value is None:
                version_value = extracted_version
            if extracted_release:
                release_value = extracted_release

            if version_value is None and release_value is None:
                facts.setdefault(
                    "zabbix.warning.server_version",
                    "Unable to determine Zabbix server version from serverinfo.get response.",
                )

        if version_value is not None:
            facts["zabbix.server.version"] = version_value
        if release_value is not None:
            facts["zabbix.server.release"] = release_value
        if version_source is not None:
            facts["zabbix.server.version_source"] = version_source

        host_ids: set[str] = set()
        try:
            report("Listing enabled hosts")
            server_info = client.host.get(  # type: ignore[attr-defined]
                output="extend",
                selectInterfaces="extend",
                selectParentTemplates=["templateid", "name"],  # Add template relationships
                selectGroups=["groupid", "name"],
                filter={"status": 0},
                sortfield=["name"],
            )
            total_hosts = len(server_info) if server_info is not None else None
            facts["zabbix.host.total"] = total_hosts
            if total_hosts is not None:
                facts["zabbix.host.count"] = total_hosts  # backwards compatibility
            normalised_hosts = [_normalise_host_record(h) for h in (server_info or [])]
            facts["zabbix.hosts"] = normalised_hosts
            facts["zabbix.host.enabled"] = sum(1 for h in normalised_hosts if h.get("status") == "0")
            facts["zabbix.host.available"] = sum(1 for h in normalised_hosts if h.get("available") == "1")
            host_ids = {host["id"] for host in normalised_hosts if host.get("id")}
        except Exception as err:
            facts["zabbix.warning.host_summary"] = str(err)

        try:
            item_records: list[Mapping[str, Any]] = []
            if host_ids:
                report("Collecting item metadata for enabled hosts")
                item_records = client.item.get(  # type: ignore[attr-defined]
                    output=[
                        "itemid",
                        "name",
                        "key_",
                        "delay",
                        "status",
                        "state",
                        "lastclock",
                    ],
                    hostids=sorted(host_ids),
                    selectHosts=["hostid", "name", "host"],
                )

            normalised_items = [
                _normalise_item(item, host_ids)
                for item in (item_records or [])
                if isinstance(item, Mapping)
            ]
            filtered_items = [item for item in normalised_items if item["host_ids"]]

            total_items = len(filtered_items)
            enabled_items = sum(1 for item in filtered_items if item["status"] == "0")
            not_supported_items = sum(1 for item in filtered_items if item["state"] != "0")
            disabled_items = total_items - enabled_items

            facts["zabbix.items"] = filtered_items
            facts["zabbix.item.total"] = total_items
            facts["zabbix.item.enabled"] = enabled_items
            facts["zabbix.item.disabled"] = disabled_items
            facts["zabbix.item.not_supported"] = not_supported_items
        except Exception as err:
            facts["zabbix.warning.item_summary"] = str(err)

        try:
            discovery_records: list[Mapping[str, Any]] = []
            if host_ids:
                report("Collecting discovery rules")
                discovery_records = client.discoveryrule.get(  # type: ignore[attr-defined]
                    output=["itemid", "name", "delay"],
                    hostids=sorted(host_ids),
                    selectHosts=["hostid", "name", "host"],
                )

            normalised_rules = [
                _normalise_discovery_rule(rule, host_ids)
                for rule in (discovery_records or [])
                if isinstance(rule, Mapping)
            ]
            filtered_rules = [rule for rule in normalised_rules if rule["host_ids"]]

            facts["zabbix.discovery_rules"] = filtered_rules
            facts["zabbix.discovery_rule.total"] = len(filtered_rules)
        except Exception as err:
            facts["zabbix.warning.discovery_rules"] = str(err)

        try:
            report("Fetching template inventory")
            template_records = client.template.get(  # type: ignore[attr-defined]
                output=[
                    "templateid",
                    "name",
                    "description",
                    "version",
                    "vendor_name",
                    "vendor_version",
                ],
                selectGroups=["groupid", "name"],
                selectMacros=["macro", "type", "value"],
            )

            templates = []
            for template in (template_records or []):
                if not isinstance(template, Mapping):
                    continue
                groups: list[dict[str, str]] = []
                raw_groups = template.get("groups") or []
                if isinstance(raw_groups, Iterable):
                    for group in raw_groups:
                        if not isinstance(group, Mapping):
                            continue
                        groups.append(
                            {
                                "id": _coerce_str(group.get("groupid")),
                                "name": _coerce_str(group.get("name")),
                            }
                        )
                vendor_name = _coerce_str(template.get("vendor_name")) or None
                raw_version = _coerce_str(template.get("version")) or None
                vendor_version = _coerce_str(template.get("vendor_version")) or None
                version = raw_version or vendor_version

                # Macros for template (name-only, no values)
                macros: list[dict[str, str | int | bool]] = []
                raw_macros = template.get("macros") or []
                if isinstance(raw_macros, Iterable):
                    for m in raw_macros:
                        if not isinstance(m, Mapping):
                            continue
                        _val_text = _coerce_str(m.get("value"))
                        _has_value = bool(_val_text)
                        _is_placeholder = False
                        if _has_value:
                            _stripped = _val_text.strip()
                            if _stripped.upper() == "CHANGE_IF_NEEDED" or (_stripped.startswith("<") and _stripped.endswith(">")):
                                _is_placeholder = True
                        macros.append(
                            {
                                "macro": _coerce_str(m.get("macro")),
                                "type": _coerce_int(m.get("type")),
                                "has_value": _has_value,
                                "is_placeholder": _is_placeholder,
                            }
                        )

                templates.append(
                    {
                        "id": _coerce_str(template.get("templateid")),
                        "name": _coerce_str(template.get("name")),
                        "description": _coerce_str(template.get("description")),
                        "version": version,
                        "vendor_name": vendor_name,
                        "vendor_version": vendor_version,
                        "groups": groups,
                        "macros": macros,
                    }
                )

            facts["zabbix.templates"] = templates
            facts["zabbix.template.total"] = len(templates)
        except Exception as err:
            facts["zabbix.warning.template_summary"] = str(err)

        # Host groups inventory for naming/policy checks
        try:
            report("Fetching host groups")
            group_records = client.hostgroup.get(  # type: ignore[attr-defined]
                output=["groupid", "name"],
            )

            hostgroups: list[dict[str, str]] = []
            for record in (group_records or []):
                if not isinstance(record, Mapping):
                    continue
                hostgroups.append(
                    {
                        "id": _coerce_str(record.get("groupid")),
                        "name": _coerce_str(record.get("name")),
                    }
                )

            facts["zabbix.hostgroups"] = hostgroups
            facts["zabbix.hostgroup.total"] = len(hostgroups)
        except Exception as err:
            facts["zabbix.warning.hostgroup_summary"] = str(err)

        # Dashboards
        try:
            report("Fetching dashboards")
            dashboards = client.dashboard.get(output=["dashboardid", "name"])  # type: ignore[attr-defined]
            normalised = []
            for d in (dashboards or []):
                if not isinstance(d, Mapping):
                    continue
                normalised.append({
                    "id": _coerce_str(d.get("dashboardid")),
                    "name": _coerce_str(d.get("name")),
                })
            facts["zabbix.dashboards"] = normalised
            facts["zabbix.dashboard.total"] = len(normalised)
        except Exception as err:
            facts["zabbix.warning.dashboard_summary"] = str(err)

        # Maintenances
        try:
            report("Fetching maintenances")
            maints = client.maintenance.get(output=["maintenanceid", "name"])  # type: ignore[attr-defined]
            normalised = []
            for m in (maints or []):
                if not isinstance(m, Mapping):
                    continue
                normalised.append({
                    "id": _coerce_str(m.get("maintenanceid")),
                    "name": _coerce_str(m.get("name")),
                })
            facts["zabbix.maintenances"] = normalised
            facts["zabbix.maintenance.total"] = len(normalised)
        except Exception as err:
            facts["zabbix.warning.maintenance_summary"] = str(err)

        # Services (IT services)
        try:
            report("Fetching services")
            services = client.service.get(output=["serviceid", "name"])  # type: ignore[attr-defined]
            normalised = []
            for s in (services or []):
                if not isinstance(s, Mapping):
                    continue
                normalised.append({
                    "id": _coerce_str(s.get("serviceid")),
                    "name": _coerce_str(s.get("name")),
                })
            facts["zabbix.services"] = normalised
            facts["zabbix.service.total"] = len(normalised)
        except Exception as err:
            facts["zabbix.warning.service_summary"] = str(err)

        # SLAs (if available)
        try:
            report("Fetching SLAs")
            slas = client.sla.get(output=["slaid", "name"])  # type: ignore[attr-defined]
            normalised = []
            for s in (slas or []):
                if not isinstance(s, Mapping):
                    continue
                normalised.append({
                    "id": _coerce_str(s.get("slaid")),
                    "name": _coerce_str(s.get("name")),
                })
            facts["zabbix.slas"] = normalised
            facts["zabbix.sla.total"] = len(normalised)
        except Exception as err:
            facts["zabbix.warning.sla_summary"] = str(err)

        # Actions (different event sources)
        try:
            report("Fetching actions")
            actions = client.action.get(output=["actionid", "name", "eventsource"])  # type: ignore[attr-defined]
            normalised = []
            for a in (actions or []):
                if not isinstance(a, Mapping):
                    continue
                normalised.append({
                    "id": _coerce_str(a.get("actionid")),
                    "name": _coerce_str(a.get("name")),
                    "eventsource": _coerce_str(a.get("eventsource")),
                })
            facts["zabbix.actions"] = normalised
            facts["zabbix.action.total"] = len(normalised)
        except Exception as err:
            facts["zabbix.warning.action_summary"] = str(err)

        # Global macros
        try:
            report("Fetching global macros")
            global_macros = client.usermacro.get(  # type: ignore[attr-defined]
                output=["globalmacroid", "macro", "type", "value"],
                globalmacro=1,
            )
            macros: list[dict[str, str | int | bool]] = []
            for m in (global_macros or []):
                if not isinstance(m, Mapping):
                    continue
                _val_text = _coerce_str(m.get("value"))
                _has_value = bool(_val_text)
                _is_placeholder = False
                if _has_value:
                    _stripped = _val_text.strip()
                    if _stripped.upper() == "CHANGE_IF_NEEDED" or (_stripped.startswith("<") and _stripped.endswith(">")):
                        _is_placeholder = True
                macros.append(
                    {
                        "id": _coerce_str(m.get("globalmacroid") or m.get("macroid") or m.get("id")),
                        "macro": _coerce_str(m.get("macro")),
                        "type": _coerce_int(m.get("type")),
                        "has_value": _has_value,
                        "is_placeholder": _is_placeholder,
                    }
                )
            facts["zabbix.global_macros"] = macros
            facts["zabbix.global_macro.total"] = len(macros)
        except Exception as err:
            facts["zabbix.warning.global_macro_summary"] = str(err)

        try:
            report("Counting Zabbix users")
            user_count = client.user.get(countOutput=True)  # type: ignore[attr-defined]
            facts["zabbix.user.total"] = int(user_count) if user_count is not None else None
        except Exception as err:
            facts["zabbix.warning.user_summary"] = str(err)

        try:
            # Collect detailed user information for security checks
            report("Collecting user account details")
            user_records = client.user.get(  # type: ignore[attr-defined]
                output=["userid", "username", "name", "surname", "autologin", "autologout", "roleid"],
            )
            
            users = []
            for user in (user_records or []):
                if isinstance(user, Mapping):
                    users.append({
                        "id": _coerce_str(user.get("userid")),
                        "username": _coerce_str(user.get("username")),
                        "name": _coerce_str(user.get("name")),
                        "surname": _coerce_str(user.get("surname")),
                        "autologin": _coerce_str(user.get("autologin")),
                        "autologout": _coerce_str(user.get("autologout")),
                        "roleid": _coerce_str(user.get("roleid")),
                    })
            
            facts["zabbix.users"] = users
        except Exception as err:
            facts["zabbix.warning.user_details"] = str(err)

        default_password_valid: Optional[bool] = None
        default_password_error: Optional[str] = None
        try:
            report("Validating default Admin credentials")
            default_client = ZabbixAPI(url=api_url, user="Admin", password="zabbix")
        except Exception as err:
            message = str(err)
            lowered = message.lower()
            known_invalid = (
                "password is incorrect",
                "login name or password is incorrect",
                "incorrect user or password",
                "invalid username or password",
                "user is blocked",
            )
            if any(token in lowered for token in known_invalid):
                default_password_valid = False
            else:
                default_password_error = message
        else:
            default_password_valid = True
            try:
                default_client.logout()
            except Exception:
                pass

        if default_password_valid is not None:
            facts["zabbix.admin.default_password_valid"] = default_password_valid
        if default_password_error:
            facts["zabbix.warning.admin_default_password"] = default_password_error

        try:
            report("Collecting trigger summary")
            trigger_records = []
            if host_ids:
                trigger_records = client.trigger.get(  # type: ignore[attr-defined]
                    output=[
                        "triggerid",
                        "description",
                        "status",
                        "value",
                        "priority",
                        "state",
                        "lastchange",
                        "templateid",
                    ],
                    hostids=sorted(host_ids),
                    selectHosts=["hostid", "name", "host"],
                    selectFunctions=["itemid"],
                )
            normalised_triggers = []
            for trigger in (trigger_records or []):
                normalised = _normalise_trigger(trigger, host_ids)
                if normalised["host_ids"]:
                    normalised_triggers.append(normalised)
            facts["zabbix.triggers"] = normalised_triggers
            total_triggers = len(normalised_triggers)
            enabled_triggers = [t for t in normalised_triggers if t.get("status") == "0"]
            disabled_triggers = total_triggers - len(enabled_triggers)
            enabled_problem = sum(1 for t in enabled_triggers if t.get("value") == "1")
            enabled_ok = len(enabled_triggers) - enabled_problem
            disabled_problem = sum(1 for t in normalised_triggers if t.get("status") != "0" and t.get("value") == "1")
            disabled_ok = disabled_triggers - disabled_problem
            facts["zabbix.trigger.total"] = total_triggers
            facts["zabbix.trigger.enabled"] = len(enabled_triggers)
            facts["zabbix.trigger.disabled"] = disabled_triggers
            facts["zabbix.trigger.enabled_problem"] = enabled_problem
            facts["zabbix.trigger.enabled_ok"] = enabled_ok
            facts["zabbix.trigger.disabled_problem"] = disabled_problem
            facts["zabbix.trigger.disabled_ok"] = disabled_ok
            facts["zabbix.trigger.problems"] = enabled_problem + disabled_problem
        except Exception as err:
            facts["zabbix.warning.trigger_summary"] = str(err)

        try:
            report("Fetching required performance metric")
            required_perf = client.item.get(  # type: ignore[attr-defined]
                output=["lastvalue"],
                filter={"key_": "zabbix[requiredperformance]"},
                limit=1,
            )
            if required_perf:
                raw_value = required_perf[0].get("lastvalue")
                facts["zabbix.performance.required_values_per_second"] = float(raw_value) if raw_value is not None else None
        except Exception as err:
            facts["zabbix.warning.required_performance"] = str(err)

        try:
            report("Collecting process poller utilisation")
            poller_keys = {
                "agent_poller": "zabbix[process,agent poller,avg,busy]",
                "browser_poller": "zabbix[process,browser poller,avg,busy]",
                "http_agent_poller": "zabbix[process,http agent poller,avg,busy]",
                "http_poller": "zabbix[process,http poller,avg,busy]",
                "icmp_pinger": "zabbix[process,icmp pinger,avg,busy]",
                "internal_poller": "zabbix[process,internal poller,avg,busy]",
                "odbc_poller": "zabbix[process,odbc poller,avg,busy]",
                "poller": "zabbix[process,poller,avg,busy]",
                "proxy_poller": "zabbix[process,proxy poller,avg,busy]",
                "snmp_poller": "zabbix[process,snmp poller,avg,busy]",
                "trapper": "zabbix[process,trapper,avg,busy]",
                "unreachable_poller": "zabbix[process,unreachable poller,avg,busy]",
            }

            poller_lookup = {value: name for name, value in poller_keys.items()}
            poller_filter = sorted(poller_lookup.keys())
            poller_items: Sequence[Mapping[str, Any]] = client.item.get(  # type: ignore[attr-defined]
                output=["lastvalue", "key_"],
                filter={"key_": poller_filter},
                templated=False,
            ) or []

            poller_data: Dict[str, Dict[str, Any]] = {}
            seen_poller_keys: set[str] = set()
            for item in poller_items:
                key = _coerce_str(item.get("key_"))
                if key not in poller_lookup or key in seen_poller_keys:
                    continue

                last_value = item.get("lastvalue")
                if last_value is None:
                    continue

                try:
                    busy_percent = float(last_value)
                except (TypeError, ValueError):
                    continue

                poller_name = poller_lookup[key]
                poller_data[poller_name] = {
                    "busy_percent": busy_percent,
                    "key": key,
                }
                seen_poller_keys.add(key)

            facts["zabbix.process.pollers"] = poller_data
            facts["zabbix.process.poller.total"] = len(poller_data)
        except Exception as err:
            facts["zabbix.warning.process_pollers"] = str(err)

        try:
            report("Collecting cache utilisation metrics")
            cache_keys = {
                "zabbix[cache,config,pused]",
                "zabbix[cache,hist_index,pused]",
                "zabbix[cache,history,pused]",
                "zabbix[cache,trend,pused]",
                "zabbix[cache,value,pused]",
                "zabbix[cache,config,pfree]",
                "zabbix[cache,hist_index,pfree]",
                "zabbix[cache,history,pfree]",
                "zabbix[cache,trend,pfree]",
                "zabbix[cache,value,pfree]",
                "zabbix[rcache,buffer,pused]",
                "zabbix[rcache,buffer,pfree]",
                "zabbix[wcache,history,pused]",
                "zabbix[wcache,history,pfree]",
                "zabbix[wcache,index,pused]",
                "zabbix[wcache,index,pfree]",
                "zabbix[wcache,trend,pused]",
                "zabbix[wcache,trend,pfree]",
                "zabbix[vcache,buffer,pused]",
                "zabbix[vcache,buffer,pfree]",
            }

            cache_filter = sorted(cache_keys)
            cache_items: list[Mapping[str, Any]] = list(
                client.item.get(  # type: ignore[attr-defined]
                    output=["lastvalue", "key_"],
                    filter={"key_": cache_filter},
                )
                or []
            )

            if len(cache_items) < len(cache_keys):
                report("Falling back to cache wildcard search")
                fallback_items = client.item.get(  # type: ignore[attr-defined]
                    output=["lastvalue", "key_"],
                    search={"key_": "zabbix[cache,"},
                    startSearch=True,
                    searchWildcardsEnabled=True,
                )
                if fallback_items:
                    cache_items.extend(fallback_items)

            cache_data: Dict[str, Dict[str, Any]] = {}
            cache_metric_preference: Dict[str, str] = {}
            for item in cache_items:
                key = _coerce_str(item.get("key_"))
                last_value = item.get("lastvalue")
                prepared = _prepare_cache_entry(key, last_value)
                if prepared is None:
                    continue

                cache_name, cache_entry, metric = prepared
                previous_metric = cache_metric_preference.get(cache_name)
                if previous_metric == "pused" and metric != "pused":
                    continue

                cache_metric_preference[cache_name] = metric
                cache_data[cache_name] = cache_entry

            facts["zabbix.cache"] = cache_data
            facts["zabbix.cache.total"] = len(cache_data)
        except Exception as err:
            facts["zabbix.warning.cache"] = str(err)
    except Exception as err:
        return {"zabbix.error": str(err)}
    finally:
        if client is not None:
            try:
                report("Disconnecting from Zabbix API")
                client.logout()
            except Exception:
                pass

    return facts





_INTERFACE_TYPES = {
    "1": "agent",
    "2": "snmp",
    "3": "ipmi",
    "4": "jmx",
}

_CACHE_SUBJECT_ALIASES: Dict[str, str] = {
    "config": "config",
    "configuration": "config",
    "config_cache": "config",
    "hist_index": "hist_index",
    "history_index": "hist_index",
    "historyindex": "hist_index",
    "index": "hist_index",
    "history": "history",
    "history_cache": "history",
    "trend": "trend",
    "trends": "trend",
    "trend_cache": "trend",
    "value": "value",
    "values": "value",
    "value_cache": "value",
    "buffer": "buffer",
}

_CACHE_TYPE_SUBJECT_ALIASES: Dict[tuple[str, str], str] = {
    ("cache", "config"): "config",
    ("cache", "hist_index"): "hist_index",
    ("cache", "history"): "history",
    ("cache", "trend"): "trend",
    ("cache", "value"): "value",
    ("rcache", "buffer"): "config",
    ("wcache", "history"): "history",
    ("wcache", "index"): "hist_index",
    ("wcache", "trend"): "trend",
    ("vcache", "buffer"): "value",
}


def _coerce_int(value: Any) -> Optional[int]:
    """Convert a value to integer, returning None if conversion fails.
    
    Args:
        value: Value to convert to int
        
    Returns:
        Integer value or None if conversion fails
    """
    try:
        if value is None:
            return None
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _coerce_str(value: Any) -> str:
    """Convert a value to string, returning empty string for None.
    
    Args:
        value: Value to convert to string
        
    Returns:
        String representation or empty string
    """
    if value is None:
        return ""
    return str(value)


def _coerce_status(value: Any) -> str:
    """Convert a Zabbix status value to string format.
    
    Normalizes None and "none" to "0" (unknown status).
    
    Args:
        value: Status value to normalize
        
    Returns:
        String status code
    """
    if value is None:
        return "0"
    text = str(value)
    if text.lower() == "none":
        return "0"
    return text


def _first_timestamp(values: Iterable[Any]) -> Optional[int]:
    """Extract the earliest valid timestamp from a sequence.
    
    Filters out None and zero values, returning the minimum.
    
    Args:
        values: Iterable of timestamp values
        
    Returns:
        Earliest valid timestamp or None if no valid values
    """
    parsed = [_coerce_int(v) for v in values]
    filtered = [v for v in parsed if v and v > 0]
    if not filtered:
        return None
    return min(filtered)


def _aggregate_host_available(host: Mapping[str, Any], availability: Mapping[str, str]) -> str:
    """Determine aggregate availability status for a host.
    
    Priority: 1 (available) > 2 (unavailable) > 0 (unknown).
    
    Args:
        host: Host record mapping
        availability: Interface availability status mapping
        
    Returns:
        Aggregate status code string
    """
    codes = [code for code in availability.values() if code]
    fallback = _coerce_status(host.get("available")) if isinstance(host, Mapping) else "0"
    if fallback:
        codes.append(fallback)
    # Priority: available > unavailable > unknown
    if "1" in codes:
        return "1"
    if "2" in codes:
        return "2"
    if "0" in codes:
        return "0"
    return fallback or "0"


def _normalise_host_record(host: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Zabbix host record to a consistent structure.
    
    Extracts and structures interface information, template IDs, and
    availability data.
    
    Args:
        host: Raw host record from Zabbix API
        
    Returns:
        Normalized host dictionary
    """
    availability: Dict[str, str] = {value: "0" for value in _INTERFACE_TYPES.values()}
    interfaces: list[Dict[str, Any]] = []
    interface_errors: Dict[str, Optional[int]] = {value: None for value in _INTERFACE_TYPES.values()}

    raw_interfaces = host.get("interfaces") or []
    if isinstance(raw_interfaces, Iterable):
        for raw in raw_interfaces:
            if not isinstance(raw, Mapping):
                continue
            kind = _INTERFACE_TYPES.get(str(raw.get("type")), f"type_{raw.get('type')}")
            status_code = _coerce_status(raw.get("available"))
            availability[kind] = status_code
            errors_from = _coerce_int(raw.get("errors_from"))
            interface_record = {
                "id": _coerce_str(raw.get("interfaceid")),
                "type": kind,
                "available": status_code,
                "errors_from": errors_from,
                "disable_until": _coerce_int(raw.get("disable_until")),
                "error": _coerce_str(raw.get("error")),
                "ip": _coerce_str(raw.get("ip")),
                "dns": _coerce_str(raw.get("dns")),
                "port": _coerce_str(raw.get("port")),
            }
            interfaces.append(interface_record)
            if kind in interface_errors and errors_from:
                interface_errors[kind] = errors_from

    # Process template information
    template_ids = []
    raw_templates = host.get("parentTemplates") or []
    if isinstance(raw_templates, Iterable):
        for template in raw_templates:
            if isinstance(template, Mapping):
                template_id = _coerce_str(template.get("templateid"))
                if template_id:
                    template_ids.append(template_id)

    # Process group membership
    group_ids: list[str] = []
    group_names: list[str] = []
    raw_groups = host.get("groups") or []
    if isinstance(raw_groups, Iterable):
        for group in raw_groups:
            if not isinstance(group, Mapping):
                continue
            gid = _coerce_str(group.get("groupid"))
            gname = _coerce_str(group.get("name"))
            if gid:
                group_ids.append(gid)
            if gname:
                group_names.append(gname)

    proxy_ids = _collect_ids(
        host,
        (
            "proxyids",
            "proxy_ids",
            "proxyid",
            "proxy_id",
            "proxy_hostid",
            "assigned_proxyid",
            "assigned_proxy_id",
        ),
    )
    proxy_group_ids = _collect_ids(
        host,
        (
            "proxy_groupids",
            "proxy_group_ids",
            "proxy_groupid",
            "proxy_group_id",
        ),
    )
    monitored_by = _coerce_str(host.get("monitored_by"))
    tls_connect = _coerce_int(host.get("tls_connect"))
    tls_accept = _coerce_int(host.get("tls_accept"))
    tls_psk_identity = _coerce_str(host.get("tls_psk_identity"))
    tls_psk_present = bool(_coerce_str(host.get("tls_psk")))
    tls_issuer = _coerce_str(host.get("tls_issuer"))
    tls_subject = _coerce_str(host.get("tls_subject"))

    return {
        "id": _coerce_str(host.get("hostid")),
        "name": _coerce_str(host.get("name") or host.get("host")),
        "status": _coerce_str(host.get("status")),
        "available": _aggregate_host_available(host, availability),
        "availability": availability,
        "errors_from": _coerce_int(host.get("errors_from")) or interface_errors["agent"],
        "snmp_errors_from": _coerce_int(host.get("snmp_errors_from")) or interface_errors["snmp"],
        "ipmi_errors_from": _coerce_int(host.get("ipmi_errors_from")) or interface_errors["ipmi"],
        "jmx_errors_from": _coerce_int(host.get("jmx_errors_from")) or interface_errors["jmx"],
        "interfaces": interfaces,
        "template_ids": template_ids,
        "group_ids": group_ids,
        "groups": group_names,
        "proxy_ids": proxy_ids,
        "proxy_group_ids": proxy_group_ids,
        "monitored_by": monitored_by,
        "tls_connect": tls_connect,
        "tls_accept": tls_accept,
        "tls_psk_identity": tls_psk_identity or None,
        "tls_psk_present": tls_psk_present,
        "tls_issuer": tls_issuer or None,
        "tls_subject": tls_subject or None,
        "unavailable_since": _first_timestamp(
            (
                host.get("errors_from"),
                host.get("snmp_errors_from"),
                host.get("ipmi_errors_from"),
                host.get("jmx_errors_from"),
                *interface_errors.values(),
            )
        ),
    }


def _parse_delay_seconds(raw: Any) -> Optional[int]:
    """Parse a Zabbix delay string to seconds.
    
    Supports plain integers and time unit suffixes (s, m, h, d, w).
    Returns None for flexible intervals (starting with {).
    
    Args:
        raw: Delay value (string or number)
        
    Returns:
        Delay in seconds or None if invalid/flexible
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    # Skip flexible/scheduling intervals
    if text.startswith("{") and text.endswith("}"):
        return None
    if text.isdigit():
        return int(text)
    match = re.fullmatch(r"(\d+)([smhdwSMHDW])", text)
    if match:
        value = int(match.group(1))
        unit = match.group(2).lower()
        multipliers = {
            "s": 1,
            "m": 60,
            "h": 3600,
            "d": 86400,
            "w": 604800,
        }
        return value * multipliers[unit]
    # Unsupported schedule expression (e.g. flexible): return None
    return None


def _normalise_discovery_rule(rule: Dict[str, Any], allowed_host_ids: Iterable[str] | None = None) -> Dict[str, Any]:
    """Normalize a Zabbix discovery rule to a consistent structure.
    
    Filters hosts by allowed_host_ids if provided.
    
    Args:
        rule: Raw discovery rule from Zabbix API
        allowed_host_ids: Optional set of allowed host IDs for filtering
        
    Returns:
        Normalized discovery rule dictionary
    """
    allowed = {str(host_id) for host_id in allowed_host_ids or []}
    hosts_raw = rule.get("hosts") or []
    hosts: list[str] = []
    host_ids: list[str] = []
    if isinstance(hosts_raw, Iterable):
        for host in hosts_raw:
            if not isinstance(host, Mapping):
                continue
            host_id = _coerce_str(host.get("hostid"))
            if allowed and host_id not in allowed:
                continue
            hosts.append(_coerce_str(host.get("name") or host.get("host")))
            host_ids.append(host_id)
    elif rule.get("hostid") is not None:
        host_id = _coerce_str(rule.get("hostid"))
        if not allowed or host_id in allowed:
            host_ids.append(host_id)

    delay_raw = rule.get("delay")
    delay_seconds = _parse_delay_seconds(delay_raw)

    return {
        "id": _coerce_str(rule.get("itemid")),
        "name": _coerce_str(rule.get("name")),
        "delay": _coerce_str(delay_raw),
        "delay_seconds": delay_seconds,
        "hosts": hosts,
        "host_ids": host_ids,
    }


def _normalise_item(item: Dict[str, Any], allowed_host_ids: Iterable[str] | None = None) -> Dict[str, Any]:
    """Normalize a Zabbix item to a consistent structure.
    
    Filters hosts by allowed_host_ids if provided.
    
    Args:
        item: Raw item from Zabbix API
        allowed_host_ids: Optional set of allowed host IDs for filtering
        
    Returns:
        Normalized item dictionary
    """
    allowed = {str(host_id) for host_id in allowed_host_ids or []}
    hosts_raw = item.get("hosts") or []
    hosts: list[str] = []
    host_ids: list[str] = []
    if isinstance(hosts_raw, Iterable):
        for host in hosts_raw:
            if not isinstance(host, Mapping):
                continue
            host_id = _coerce_str(host.get("hostid"))
            if allowed and host_id not in allowed:
                continue
            hosts.append(_coerce_str(host.get("name") or host.get("host")))
            host_ids.append(host_id)
    elif item.get("hostid") is not None:
        host_id = _coerce_str(item.get("hostid"))
        if not allowed or host_id in allowed:
            host_ids.append(host_id)

    delay_raw = item.get("delay")
    delay_seconds = _parse_delay_seconds(delay_raw)

    return {
        "id": _coerce_str(item.get("itemid")),
        "name": _coerce_str(item.get("name")),
        "key": _coerce_str(item.get("key_")),
        "delay": _coerce_str(delay_raw),
        "delay_seconds": delay_seconds,
        "hosts": hosts,
        "host_ids": host_ids,
        "status": _coerce_status(item.get("status")),
        "state": _coerce_str(item.get("state")),
        "last_clock": _coerce_int(item.get("lastclock")),
    }


def _prepare_cache_entry(
    key: str,
    raw_value: Any,
) -> Optional[tuple[str, Dict[str, Any], str]]:
    """Normalise a cache metric into a canonical cache entry.

    Returns a tuple of (cache_name, entry, metric) when successful.
    """

    if not key or not key.startswith("zabbix[") or not key.endswith("]"):
        return None

    inner = key[7:-1]
    parts = [part.strip().lower() for part in inner.split(",") if part.strip()]
    if len(parts) < 3:
        return None

    metric = parts[-1]
    if metric not in {"pused", "pfree"}:
        return None

    cache_type = parts[0]
    subject_raw = parts[1]
    subject = _CACHE_TYPE_SUBJECT_ALIASES.get((cache_type, subject_raw))
    if subject is None:
        subject = _CACHE_SUBJECT_ALIASES.get(subject_raw, subject_raw.replace(" ", "_"))
    if not subject:
        return None

    try:
        numeric_value = float(raw_value)
    except (TypeError, ValueError):
        return None

    if metric == "pused":
        used_percent = numeric_value
        free_percent = 100.0 - numeric_value if 0.0 <= numeric_value <= 100.0 else None
    else:
        free_percent = numeric_value
        used_percent = 100.0 - numeric_value if 0.0 <= numeric_value <= 100.0 else None

    cache_name = f"cache_{subject}"
    entry = {
        "used_percent": used_percent,
        "free_percent": free_percent,
        "key": key,
    }
    return cache_name, entry, metric


def _collect_ids(host: Mapping[str, Any], keys: Sequence[str]) -> list[str]:
    """Collect and deduplicate IDs from a host record.
    
    Looks for values under any of the specified keys and collects
    them into a deduplicated list. Handles both scalar and list values.
    
    Args:
        host: Host record mapping
        keys: Sequence of potential key names to look for
        
    Returns:
        List of unique non-zero ID strings
    """
    collected: list[str] = []
    for key in keys:
        if key not in host:
            continue
        value = host.get(key)
        if isinstance(value, (list, tuple, set)):
            for entry in value:
                text = _coerce_str(entry)
                if text and text != "0" and text not in collected:
                    collected.append(text)
        else:
            text = _coerce_str(value)
            if text and text != "0" and text not in collected:
                collected.append(text)
    return collected


def _normalise_trigger(trigger: Dict[str, Any], allowed_host_ids: Iterable[str] | None = None) -> Dict[str, Any]:
    """Normalize a Zabbix trigger to a consistent structure.
    
    Filters hosts by allowed_host_ids if provided.
    
    Args:
        trigger: Raw trigger from Zabbix API
        allowed_host_ids: Optional set of allowed host IDs for filtering
        
    Returns:
        Normalized trigger dictionary
    """
    allowed = {str(host_id) for host_id in allowed_host_ids or []}
    hosts_raw = trigger.get("hosts") or []
    hosts: list[str] = []
    host_ids: list[str] = []
    if isinstance(hosts_raw, Iterable):
        for host in hosts_raw:
            if not isinstance(host, Mapping):
                continue
            host_id = _coerce_str(host.get("hostid"))
            if allowed and host_id not in allowed:
                continue
            hosts.append(_coerce_str(host.get("name") or host.get("host")))
            host_ids.append(host_id)

    return {
        "id": _coerce_str(trigger.get("triggerid")),
        "name": _coerce_str(trigger.get("description") or trigger.get("name")),
        "status": _coerce_status(trigger.get("status")),
        "value": _coerce_str(trigger.get("value")),
        "state": _coerce_str(trigger.get("state")),
        "priority": _coerce_int(trigger.get("priority")),
        "lastchange": _coerce_int(trigger.get("lastchange")),
        "hosts": hosts,
        "host_ids": host_ids,
        "item_ids": [
            _coerce_str(function.get("itemid"))
            for function in (trigger.get("functions") or [])
            if isinstance(function, Mapping) and _coerce_str(function.get("itemid"))
        ],
    }

register_provider("zabbix", _zabbix_base)
