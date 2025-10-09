from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Sequence

import pytest

from auditx.checks.zabbix.default_admin_account_check import DefaultAdminAccountCheck
from auditx.core.models import RunContext, Status


@dataclass
class DummyFacts:
    values: Dict[str, Any]

    def get(self, key: str, *, tech: str | None = None) -> Any:
        return self.values.get(key)


def make_ctx(users: Sequence[Dict[str, Any]] | None, config: Dict[str, Any] | None = None) -> RunContext:
    facts_data = {}
    if users is not None:
        facts_data["zabbix.users"] = list(users)
    return RunContext(tech_filter={"zabbix"}, config=config or {}, env={}, facts=DummyFacts(facts_data))


def build_user(
    *,
    userid: str = "1",
    username: str,
    name: str = "",
    surname: str = "",
    user_type: str = "1",
    roleid: str = "1",
) -> Dict[str, Any]:
    return {
        "id": userid,
        "username": username,
        "name": name,
        "surname": surname,
        "type": user_type,
        "roleid": roleid,
    }


def test_skip_when_no_facts() -> None:
    ctx = make_ctx(None)
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No user data available" in result.summary


def test_skip_when_empty_user_list() -> None:
    ctx = make_ctx([])
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No user data available" in result.summary


def test_error_when_invalid_user_data() -> None:
    # Create context with invalid data directly in facts  
    facts_data = {"zabbix.users": "invalid_data"}
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=DummyFacts(facts_data))
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.ERROR
    assert "Invalid user data format" in result.summary


def test_pass_when_no_admin_account() -> None:
    users = [
        build_user(userid="1", username="operator"),
        build_user(userid="2", username="monitoring"),
        build_user(userid="3", username="guest"),
    ]
    ctx = make_ctx(users)
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.PASS
    assert "No default Admin account found" in result.summary
    assert "3 users checked" in result.summary
    assert result.details["total_users"] == 3


def test_fail_when_admin_account_found() -> None:
    users = [
        build_user(userid="1", username="Admin", name="Zabbix", surname="Administrator", user_type="3", roleid="3"),
        build_user(userid="2", username="operator"),
        build_user(userid="3", username="guest"),
    ]
    ctx = make_ctx(users)
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "Default Admin account found" in result.summary
    assert "(potential security risk)" in result.summary
    assert result.details["admin_accounts_found"] == 1
    assert result.details["total_users"] == 3
    assert len(result.details["accounts"]) == 1
    assert result.details["accounts"][0]["username"] == "Admin"
    assert "Change the default Admin account password" in result.remediation


def test_fail_when_multiple_admin_accounts() -> None:
    users = [
        build_user(userid="1", username="Admin", name="Zabbix", surname="Administrator"),
        build_user(userid="2", username="Admin", name="Another", surname="Admin"),
        build_user(userid="3", username="guest"),
    ]
    ctx = make_ctx(users)
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "Multiple Admin accounts found" in result.summary
    assert "2 accounts" in result.summary
    assert result.details["admin_accounts_found"] == 2
    assert result.details["total_users"] == 3
    assert len(result.details["accounts"]) == 2


def test_case_sensitive_admin_check() -> None:
    """Test that the check is case-sensitive and only matches exact 'Admin'."""
    users = [
        build_user(userid="1", username="admin"),  # lowercase - should not match
        build_user(userid="2", username="ADMIN"),  # uppercase - should not match  
        build_user(userid="3", username="Administrator"),  # different name - should not match
        build_user(userid="4", username="Admin"),  # exact match - should match
    ]
    ctx = make_ctx(users)
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "Default Admin account found" in result.summary
    assert result.details["admin_accounts_found"] == 1
    assert result.details["accounts"][0]["username"] == "Admin"


def test_ignores_non_dict_user_entries() -> None:
    """Test that invalid user entries are ignored gracefully."""
    users = [
        "invalid_string_user",  # Should be ignored
        build_user(userid="1", username="operator"),
        None,  # Should be ignored  
        build_user(userid="2", username="Admin"),
        {"invalid": "user"},  # Missing username - should be ignored
    ]
    ctx = make_ctx(users)
    result = DefaultAdminAccountCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "Default Admin account found" in result.summary
    assert result.details["admin_accounts_found"] == 1
    assert result.details["total_users"] == 5  # All entries counted, even invalid ones