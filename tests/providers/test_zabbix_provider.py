from __future__ import annotations

from typing import Any, Dict

from auditx.providers import zabbix_base


class DummyClient:
    def __init__(
        self,
        *,
        url: str,
        token: str | None = None,
        user: str | None = None,
        password: str | None = None,
        **_: Any,
    ) -> None:
        self.url = url
        self.token = token
        self._auth_user = user
        self._auth_password = password
        self.version = "6.0"
        self.logged_out = False

        self.host_calls: list[Dict[str, Any]] = []
        self.trigger_calls: list[Dict[str, Any]] = []
        self.item_calls: list[Dict[str, Any]] = []
        self.discovery_calls: list[Dict[str, Any]] = []
        self.template_calls: list[Dict[str, Any]] = []
        self.user_calls: list[Dict[str, Any]] = []
        self.serverinfo_calls: list[Dict[str, Any]] = []

        class _HostAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> list[Dict[str, Any]]:
                self._parent.host_calls.append(kwargs)
                return [
                    {
                        "hostid": "1",
                        "host": "agent-1",
                        "name": "agent-1",
                        "status": "0",
                        "available": "1",
                        "errors_from": 0,
                        "snmp_available": "1",
                        "snmp_errors_from": 0,
                        "ipmi_available": "0",
                        "ipmi_errors_from": 0,
                        "jmx_available": "0",
                        "jmx_errors_from": 0,
                        "monitored_by": "0",
                        "tls_connect": "2",
                        "tls_accept": "6",
                        "tls_psk_identity": "psk-agent-1",
                        "tls_psk": "abcdef",
                        "tls_issuer": "CN=Zabbix",
                        "tls_subject": "CN=agent-1",
                        "interfaces": [
                            {
                                "interfaceid": "10",
                                "type": "1",
                                "available": "1",
                                "errors_from": 0,
                                "disable_until": 0,
                                "ip": "10.0.0.10",
                                "dns": "",
                                "port": "10050",
                                "error": "",
                            }
                        ],
                    },
                    {
                        "hostid": "2",
                        "host": "agent-2",
                        "name": "agent-2",
                        "status": "0",
                        "available": "0",
                        "errors_from": 100,
                        "snmp_available": "0",
                        "snmp_errors_from": 50,
                        "ipmi_available": "0",
                        "ipmi_errors_from": 0,
                        "jmx_available": "0",
                        "jmx_errors_from": 0,
                        "proxyid": "2001",
                        "monitored_by": "1",
                        "tls_connect": "1",
                        "tls_accept": "1",
                        "tls_psk_identity": "",
                        "tls_psk": "",
                        "tls_issuer": "",
                        "tls_subject": "",
                        "interfaces": [
                            {
                                "interfaceid": "11",
                                "type": "1",
                                "available": "2",
                                "errors_from": 100,
                                "disable_until": 200,
                                "ip": "10.0.0.1",
                                "dns": "",
                                "port": "10050",
                                "error": "unreachable",
                            },
                            {
                                "interfaceid": "12",
                                "type": "2",
                                "available": "2",
                                "errors_from": 50,
                                "disable_until": 200,
                                "ip": "10.0.0.1",
                                "dns": "",
                                "port": "161",
                                "error": "snmp unreachable",
                            },
                        ],
                    },
                ]

        class _TriggerAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> list[Dict[str, Any]]:
                self._parent.trigger_calls.append(kwargs)
                return [
                    {
                        "triggerid": "10",
                        "description": "High CPU",
                        "status": "0",
                        "value": "1",
                        "state": "1",
                        "priority": "3",
                        "lastchange": "900000",
                        "templateid": "",
                        "hosts": [{"hostid": "1", "name": "agent-1"}],
                        "functions": [{"itemid": "201"}],
                    },
                    {
                        "triggerid": "11",
                        "description": "Disk usage",
                        "status": "0",
                        "value": "0",
                        "state": "0",
                        "priority": "2",
                        "lastchange": "950000",
                        "templateid": "",
                        "hosts": [{"hostid": "1", "name": "agent-1"}],
                        "functions": [{"itemid": "201"}],
                    },
                    {
                        "triggerid": "12",
                        "description": "HTTPS check",
                        "status": "1",
                        "value": "1",
                        "state": "1",
                        "priority": "4",
                        "lastchange": "960000",
                        "templateid": "",
                        "hosts": [{"hostid": "2", "name": "agent-2"}],
                        "functions": [{"itemid": "202"}],
                    },
                    {
                        "triggerid": "13",
                        "description": "Template check",
                        "status": "0",
                        "value": "0",
                        "state": "0",
                        "priority": "1",
                        "lastchange": "970000",
                        "templateid": "90001",
                        "hosts": [],
                        "functions": [{"itemid": "203"}],
                    },
                ]

        class _ItemAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> list[Dict[str, Any]]:
                self._parent.item_calls.append(kwargs)
                filt = kwargs.get("filter") or {}
                if isinstance(filt, dict):
                    key = filt.get("key_")
                    version_responses = {
                        "zabbix[version]": {
                            "itemid": "204",
                            "name": "Zabbix version",
                            "key_": "zabbix[version]",
                            "delay": "1m",
                            "lastclock": "997500",
                            "lastvalue": "6.0.12",
                            "status": "0",
                            "state": "0",
                            "hosts": [
                                {
                                    "hostid": "10084",
                                    "name": "Zabbix server",
                                    "host": "Zabbix server",
                                }
                            ],
                        },
                        "zabbix[version,full]": {
                            "itemid": "205",
                            "name": "Zabbix version (full)",
                            "key_": "zabbix[version,full]",
                            "delay": "1m",
                            "lastclock": "997501",
                            "lastvalue": "Zabbix 6.0.12",
                            "status": "0",
                            "state": "0",
                            "hosts": [
                                {
                                    "hostid": "10084",
                                    "name": "Zabbix server",
                                    "host": "Zabbix server",
                                }
                            ],
                        },
                    }
                    cache_responses = {
                        "zabbix[cache,config,pused]": "15.3656",
                        "zabbix[cache,hist_index,pused]": "1.9077",
                        "zabbix[cache,history,pused]": "0.0",
                        "zabbix[cache,trend,pused]": "16.5379",
                        "zabbix[cache,value,pused]": "22.0547",
                    }
                    poller_responses = {
                        "zabbix[process,agent poller,avg,busy]": "0.2373",
                        "zabbix[process,browser poller,avg,busy]": "0.0",
                        "zabbix[process,http agent poller,avg,busy]": "0.0",
                        "zabbix[process,http poller,avg,busy]": "0.01695",
                        "zabbix[process,icmp pinger,avg,busy]": "3.3887",
                        "zabbix[process,internal poller,avg,busy]": "0.03385",
                        "zabbix[process,odbc poller,avg,busy]": "0.0",
                        "zabbix[process,poller,avg,busy]": "0.0",
                        "zabbix[process,proxy poller,avg,busy]": "0.0",
                        "zabbix[process,snmp poller,avg,busy]": "0.0",
                        "zabbix[process,trapper,avg,busy]": "0.00339",
                        "zabbix[process,unreachable poller,avg,busy]": "0.0",
                    }
                    if isinstance(key, list):
                        results = []
                        for requested_key in key:
                            if requested_key in version_responses:
                                results.append(version_responses[requested_key])
                                continue
                            if requested_key in cache_responses:
                                results.append({"lastvalue": cache_responses[requested_key], "key_": requested_key})
                                continue
                            if requested_key in poller_responses:
                                results.append({"lastvalue": poller_responses[requested_key], "key_": requested_key})
                                continue
                        if results:
                            return results
                    elif key in cache_responses:
                        return [{"lastvalue": cache_responses[key], "key_": key}]
                    elif key in poller_responses:
                        return [{"lastvalue": poller_responses[key], "key_": key}]
                    elif key in version_responses:
                        return [version_responses[key]]
                    if key == "zabbix[requiredperformance]":
                        return [{"lastvalue": "123.45"}]
                return [
                    {
                        "itemid": "201",
                        "name": "CPU usage",
                        "key_": "system.cpu",
                        "delay": "15s",
                        "lastclock": "999000",
                        "lastvalue": "12.5",
                        "status": "0",
                        "state": "0",
                        "hosts": [
                            {"hostid": "1", "name": "agent-1"},
                        ],
                    },
                    {
                        "itemid": "202",
                        "name": "HTTP check",
                        "key_": "web.http",
                        "delay": "0",
                        "lastclock": "998000",
                        "lastvalue": "0",
                        "status": "0",
                        "state": "1",
                        "hosts": [
                            {"hostid": "2", "name": "agent-2"},
                        ],
                    },
                    {
                        "itemid": "203",
                        "name": "Template metric",
                        "key_": "template.metric",
                        "delay": "1m",
                        "lastclock": "997000",
                        "lastvalue": "0",
                        "status": "1",
                        "state": "0",
                        "hosts": [
                            {"hostid": "10001", "name": "Template OS Linux"},
                        ],
                    },
                    {
                        "itemid": "204",
                        "name": "Zabbix version",
                        "key_": "zabbix[version]",
                        "delay": "1m",
                        "lastclock": "997500",
                        "lastvalue": "6.0.12",
                        "status": "0",
                        "state": "0",
                        "hosts": [
                            {"hostid": "10084", "name": "Zabbix server"},
                        ],
                    },
                ]

        class _DiscoveryRuleAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> list[Dict[str, Any]]:
                self._parent.discovery_calls.append(kwargs)
                return [
                    {
                        "itemid": "301",
                        "name": "Filesystems",
                        "delay": "30m",
                        "hosts": [
                            {"hostid": "1", "name": "agent-1"},
                        ],
                    },
                    {
                        "itemid": "302",
                        "name": "Ports",
                        "delay": "120",
                        "hosts": [
                            {"hostid": "2", "name": "agent-2"},
                        ],
                    },
                    {
                        "itemid": "303",
                        "name": "Flexible schedule",
                        "delay": "1-7,00:00-24:00",
                        "hosts": [
                            {"hostid": "1", "name": "agent-1"},
                        ],
                    },
                    {
                        "itemid": "304",
                        "name": "Template check",
                        "delay": "60",
                        "hosts": [
                            {"hostid": "10001", "name": "Template OS Linux"},
                        ],
                    },
                ]

        class _TemplateAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> str:
                self._parent.template_calls.append(kwargs)
                if kwargs.get("output"):
                    return [
                        {
                            "templateid": "10001",
                            "name": "Template OS Linux",
                            "description": "Linux base template",
                            "vendor_name": "Zabbix",
                            "vendor_version": "6.4-2",
                            "groups": [
                                {"groupid": "1", "name": "Linux servers"},
                            ],
                        },
                        {
                            "templateid": "10002",
                            "name": "Template App HTTPS",
                            "description": "HTTPS monitoring",
                            "vendor_name": "Zabbix",
                            "vendor_version": "6.2-0",
                            "groups": [
                                {"groupid": "2", "name": "Applications"},
                            ],
                        },
                    ]
                return "7"

        class _UserAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> str | list[Dict[str, Any]]:
                self._parent.user_calls.append(kwargs)
                if kwargs.get("countOutput") is True:
                    return "12"
                # Return detailed user information for security checks
                return [
                    {
                        "userid": "1",
                        "username": "Admin",
                        "name": "Zabbix",
                        "surname": "Administrator",
                        "autologin": "0",
                        "autologout": "0",
                        "roleid": "3",
                        "type": "3",
                    },
                    {
                        "userid": "2",
                        "username": "guest",
                        "name": "guest",
                        "surname": "",
                        "autologin": "0",
                        "autologout": "15m",
                        "roleid": "4",
                        "type": "1",
                    },
                    {
                        "userid": "3",
                        "username": "operator",
                        "name": "System",
                        "surname": "Operator",
                        "autologin": "0",
                        "autologout": "15m",
                        "roleid": "2",
                        "type": "1",
                    },
                ]

        self.host = _HostAPI(self)
        self.trigger = _TriggerAPI(self)
        self.item = _ItemAPI(self)
        self.discoveryrule = _DiscoveryRuleAPI(self)
        self.template = _TemplateAPI(self)
        self.user = _UserAPI(self)

        class _ServerInfoAPI:
            def __init__(self, parent: DummyClient) -> None:
                self._parent = parent

            def get(self, **kwargs: Any) -> Dict[str, Any]:
                self._parent.serverinfo_calls.append(kwargs)
                return {"version": "6.0.12", "release": "6.0.12"}

        self.serverinfo = _ServerInfoAPI(self)

    def logout(self) -> None:
        self.logged_out = True


def test_zabbix_provider_uses_token(monkeypatch):
    captured: Dict[str, Any] = {}
    created_clients: list[DummyClient] = []

    def factory(**kwargs: Any) -> DummyClient:
        if kwargs.get("user") == "Admin" and kwargs.get("password") == "zabbix":
            raise RuntimeError("Login name or password is incorrect.")
        client = DummyClient(**kwargs)
        created_clients.append(client)
        captured.update(
            {
                "token": client.token,
                "user": getattr(client, "_auth_user", None),
                "password": getattr(client, "_auth_password", None),
            }
        )
        return client

    monkeypatch.setattr(zabbix_base, "ZabbixAPI", factory)

    facts = zabbix_base._zabbix_base({"api_url": "https://api", "api_token": "tok"})
    assert facts["zabbix.auth.method"] == "token"
    assert facts["zabbix.host.count"] == 2
    assert facts["zabbix.host.total"] == 2
    assert facts["zabbix.host.enabled"] == 2
    assert facts["zabbix.host.available"] == 1
    hosts = facts["zabbix.hosts"]
    assert len(hosts) == 2
    assert hosts[0]["name"] == "agent-1"
    assert hosts[0]["unavailable_since"] is None
    assert hosts[0]["proxy_ids"] == []
    assert hosts[0]["proxy_group_ids"] == []
    assert hosts[0]["monitored_by"] == "0"
    assert hosts[1]["unavailable_since"] == 50
    assert hosts[1]["availability"]["snmp"] == "2"
    assert hosts[0]["availability"]["agent"] == "1"
    assert hosts[1]["availability"]["agent"] == "2"
    assert hosts[1]["interfaces"][0]["type"] == "agent"
    assert hosts[1]["interfaces"][0]["available"] == "2"
    assert hosts[1]["snmp_errors_from"] == 50
    assert hosts[1]["proxy_ids"] == ["2001"]
    assert hosts[1]["proxy_group_ids"] == []
    assert hosts[1]["monitored_by"] == "1"
    assert hosts[0]["tls_connect"] == 2
    assert hosts[0]["tls_accept"] == 6
    assert hosts[0]["tls_psk_identity"] == "psk-agent-1"
    assert hosts[0]["tls_psk_present"] is True
    assert hosts[0]["tls_subject"] == "CN=agent-1"
    assert hosts[1]["tls_connect"] == 1
    assert hosts[1]["tls_psk_present"] is False
    assert facts["zabbix.template.total"] == 2
    templates = facts["zabbix.templates"]
    assert len(templates) == 2
    assert templates[0]["version"] == "6.4-2"
    assert templates[0]["vendor_version"] == "6.4-2"
    assert templates[0]["vendor_name"] == "Zabbix"
    assert templates[0]["groups"][0]["name"] == "Linux servers"
    assert templates[1]["version"] == "6.2-0"
    assert templates[1]["vendor_version"] == "6.2-0"
    assert templates[1]["vendor_name"] == "Zabbix"
    assert facts["zabbix.user.total"] == 12
    assert facts["zabbix.admin.default_password_valid"] is False
    assert facts["zabbix.trigger.problems"] == 2
    assert facts["zabbix.trigger.total"] == 3
    assert facts["zabbix.trigger.enabled"] == 2
    assert facts["zabbix.trigger.disabled"] == 1
    assert facts["zabbix.trigger.enabled_problem"] == 1
    assert facts["zabbix.trigger.enabled_ok"] == 1
    assert facts["zabbix.trigger.disabled_problem"] == 1
    assert facts["zabbix.trigger.disabled_ok"] == 0
    items = facts["zabbix.items"]
    assert facts["zabbix.item.total"] == 2
    assert facts["zabbix.item.enabled"] == 2
    assert facts["zabbix.item.disabled"] == 0
    assert facts["zabbix.item.not_supported"] == 1
    assert facts["zabbix.performance.required_values_per_second"] == 123.45
    triggers = facts["zabbix.triggers"]
    assert len(triggers) == 3
    assert triggers[0]["name"] == "High CPU"
    assert triggers[0]["hosts"] == ["agent-1"]
    assert triggers[0]["state"] == "1"
    assert triggers[0]["item_ids"] == ["201"]
    rules = facts["zabbix.discovery_rules"]
    assert len(rules) == 3
    assert rules[0]["delay_seconds"] == 1800
    assert rules[1]["delay_seconds"] == 120
    assert rules[2]["delay_seconds"] is None
    assert rules[0]["hosts"] == ["agent-1"]
    assert all("Template" not in ",".join(rule["hosts"]) for rule in rules)
    assert len(items) == 2
    assert {item["id"] for item in items} == {"201", "202"}
    cpu_item = next(item for item in items if item["id"] == "201")
    assert cpu_item["delay_seconds"] == 15
    assert cpu_item["hosts"] == ["agent-1"]
    assert cpu_item["last_clock"] == 999000
    dependent_item = next(item for item in items if item["id"] == "202")
    assert dependent_item["delay_seconds"] == 0
    assert dependent_item["hosts"] == ["agent-2"]
    assert dependent_item["last_clock"] == 998000
    assert all("Template" not in ",".join(item["hosts"]) for item in items)
    assert facts["zabbix.api.version"] == "6.0"
    assert facts["zabbix.server.version"] == "6.0.12"
    version_source = facts["zabbix.server.version_source"]
    assert version_source["key"] == "zabbix[version]"
    assert version_source["hosts"] == ["Zabbix server"]
    assert captured == {"token": "tok", "user": None, "password": None}
    assert created_clients
    assert created_clients[0].serverinfo_calls == [{}]
    discovery_call = created_clients[0].discovery_calls[0]
    assert discovery_call["hostids"] == ["1", "2"]
    item_calls = created_clients[0].item_calls
    assert len(item_calls) >= 5
    version_call = item_calls[0]
    items_call = item_calls[1]
    performance_call = item_calls[2]
    poller_call = item_calls[3]
    cache_call = item_calls[4]
    assert version_call["filter"] == {"key_": ["zabbix[version]", "zabbix[version,full]"]}
    assert "limit" not in version_call
    assert version_call["selectHosts"] == ["hostid", "name", "host"]
    assert version_call["output"] == ["itemid", "key_", "lastvalue", "lastclock"]
    assert items_call["hostids"] == ["1", "2"]
    trigger_call = created_clients[0].trigger_calls[0]
    assert trigger_call["hostids"] == ["1", "2"]
    assert trigger_call["selectHosts"] == ["hostid", "name", "host"]
    assert len(created_clients[0].item_calls) in {5, 6}
    expected_cache_keys = {
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
    assert set(cache_call["filter"]["key_"]) == expected_cache_keys
    if len(item_calls) > 5:
        fallback_call = item_calls[5]
        assert fallback_call.get("search") == {"key_": "zabbix[cache,"}
        assert fallback_call.get("startSearch") is True
    assert performance_call["filter"] == {"key_": "zabbix[requiredperformance]"}
    assert poller_call["filter"] == {
        "key_": [
            "zabbix[process,agent poller,avg,busy]",
            "zabbix[process,browser poller,avg,busy]",
            "zabbix[process,http agent poller,avg,busy]",
            "zabbix[process,http poller,avg,busy]",
            "zabbix[process,icmp pinger,avg,busy]",
            "zabbix[process,internal poller,avg,busy]",
            "zabbix[process,odbc poller,avg,busy]",
            "zabbix[process,poller,avg,busy]",
            "zabbix[process,proxy poller,avg,busy]",
            "zabbix[process,snmp poller,avg,busy]",
            "zabbix[process,trapper,avg,busy]",
            "zabbix[process,unreachable poller,avg,busy]",
        ]
    }
    assert created_clients[0].template_calls[0] == {
        "output": [
            "templateid",
            "name",
            "description",
            "version",
            "vendor_name",
            "vendor_version",
        ],
        "selectGroups": ["groupid", "name"],
    }
    assert created_clients[0].user_calls[0] == {"countOutput": True}
    assert created_clients[0].user_calls[1] == {
        "output": [
            "userid",
            "username",
            "name",
            "surname",
            "autologin",
            "autologout",
            "roleid",
        ]
    }
    assert facts["zabbix.cache.total"] == 5
    caches = facts["zabbix.cache"]
    assert caches["cache_config"]["used_percent"] == 15.3656
    assert caches["cache_hist_index"]["used_percent"] == 1.9077
    assert caches["cache_value"]["used_percent"] == 22.0547
    pollers = facts["zabbix.process.pollers"]
    assert facts["zabbix.process.poller.total"] == 12
    assert pollers["agent_poller"]["busy_percent"] == 0.2373
    assert pollers["icmp_pinger"]["busy_percent"] == 3.3887
    assert pollers["trapper"]["busy_percent"] == 0.00339


def test_zabbix_provider_requires_credentials(monkeypatch):
    monkeypatch.setattr(zabbix_base, "ZabbixAPI", DummyClient)
    facts = zabbix_base._zabbix_base({"api_url": "https://api"})
    assert "zabbix.error" in facts
    assert "api_token" in facts["zabbix.error"]


def test_zabbix_provider_detects_default_admin_password(monkeypatch):
    created_clients: list[DummyClient] = []

    class DefaultLoginClient:
        def __init__(self) -> None:
            self.logout_called = False

        def logout(self) -> None:
            self.logout_called = True

    def factory(**kwargs: Any) -> Any:
        if kwargs.get("token") == "tok":
            client = DummyClient(**kwargs)
            created_clients.append(client)
            return client
        if kwargs.get("user") == "Admin" and kwargs.get("password") == "zabbix":
            return DefaultLoginClient()
        raise AssertionError(f"Unexpected credentials: {kwargs}")

    monkeypatch.setattr(zabbix_base, "ZabbixAPI", factory)

    facts = zabbix_base._zabbix_base({"api_url": "https://api", "api_token": "tok"})
    assert facts["zabbix.admin.default_password_valid"] is True
    assert "zabbix.warning.admin_default_password" not in facts
    assert created_clients


def test_zabbix_provider_uses_username_password(monkeypatch):
    captured: Dict[str, Any] = {}

    def factory(**kwargs: Any) -> DummyClient:
        if kwargs.get("user") == "Admin" and kwargs.get("password") == "zabbix":
            raise RuntimeError("Login name or password is incorrect.")
        client = DummyClient(**kwargs)
        captured.update(
            {
                "token": client.token,
                "user": getattr(client, "_auth_user", None),
                "password": getattr(client, "_auth_password", None),
            }
        )
        return client

    monkeypatch.setattr(zabbix_base, "ZabbixAPI", factory)

    facts = zabbix_base._zabbix_base({
        "api_url": "https://api",
        "username": "alice",
        "password": "secret",
    })
    assert facts["zabbix.auth.method"] == "credentials"
    assert captured == {"token": None, "user": "alice", "password": "secret"}
    assert len(facts["zabbix.hosts"]) == 2
    assert facts["zabbix.host.total"] == 2
    assert len(facts["zabbix.discovery_rules"]) == 3
    assert all("Template" not in ",".join(rule["hosts"]) for rule in facts["zabbix.discovery_rules"])
    assert len(facts["zabbix.items"]) == 2
    assert all("Template" not in ",".join(item["hosts"]) for item in facts["zabbix.items"])
    assert len(facts["zabbix.triggers"]) == 3
    assert facts["zabbix.template.total"] == 2
    assert facts["zabbix.user.total"] == 12
    assert facts["zabbix.admin.default_password_valid"] is False
    assert facts["zabbix.item.not_supported"] == 1
    assert facts["zabbix.performance.required_values_per_second"] == 123.45
    assert facts["zabbix.server.version"] == "6.0.12"
    version_source = facts["zabbix.server.version_source"]
    assert version_source["key"] == "zabbix[version]"
    assert version_source["hosts"] == ["Zabbix server"]
