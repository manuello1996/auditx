from __future__ import annotations

import pytest
from auditx.checks.zabbix.cache_utilization_check import CACHE_DISPLAY_NAMES, ZabbixCacheUtilizationCheck
from auditx.core.facts import FactStore
from auditx.core.models import RunContext, Status


def make_ctx(cache_data: dict | None = None, config: dict | None = None) -> RunContext:
    """Helper to create a RunContext for testing."""
    facts = FactStore()
    if cache_data is not None:
        facts.set_namespace("zabbix", {"zabbix.cache": cache_data})
    return RunContext(
        tech_filter={"zabbix"},
        config=config or {},
        env={},
        facts=facts,
    )


def test_cache_utilization_check_skip_no_facts():
    """Test that check skips when no cache facts are available."""
    ctx = make_ctx(cache_data=None)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No cache facts collected" in result.summary


def test_cache_utilization_check_skip_invalid_facts():
    """Test that check skips when cache facts have invalid structure."""
    ctx = make_ctx(cache_data="invalid")
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "Unexpected cache facts structure" in result.summary


def test_cache_utilization_check_skip_no_valid_cache_data():
    """Test that check skips when no valid cache data is present."""
    cache_data = {
        "invalid_cache": "not a dict",
        "incomplete_cache": {"missing_used_percent": 30.0},
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.SKIP
    assert "No valid cache data available" in result.summary


def test_cache_utilization_check_pass_all_optimal():
    """Test that check passes when all caches are within optimal range."""
    cache_data = {
        "cache_history": {
            "used_percent": 45.0,
            "free_percent": 55.0,
            "key": "zabbix[cache,history,pused]",
        },
        "cache_trend": {
            "used_percent": 50.0,
            "free_percent": 50.0,
            "key": "zabbix[cache,trend,pused]",
        },
        "cache_value": {
            "used_percent": 55.0,
            "free_percent": 45.0,
            "key": "zabbix[cache,value,pused]",
        },
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.PASS
    assert "All 3 Zabbix caches within optimal utilization range" in result.summary
    assert result.details["total_caches"] == 3
    assert result.details["problem_caches"] == 0
    assert len(result.details["problems"]) == 0


def test_cache_utilization_check_fail_under_utilized():
    """Test that check fails when caches are under-utilized."""
    cache_data = {
        "cache_history": {
            "used_percent": 25.0,  # Under 40% threshold
            "free_percent": 75.0,
            "key": "zabbix[cache,history,pused]",
        },
        "cache_trend": {
            "used_percent": 45.0,  # Within range
            "free_percent": 55.0,
            "key": "zabbix[cache,trend,pused]",
        },
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "cache utilization issues detected" in result.summary
    assert "1 out of 2 caches outside" in result.summary
    assert "Offending caches:" in result.summary
    expected_label = CACHE_DISPLAY_NAMES["cache_history"]
    assert f"{expected_label}: 25.0% (under-utilized)" in result.summary
    assert result.details["problem_caches"] == 1
    assert f"{expected_label}: 25.0% (under-utilized)" in result.details["problems"]
    assert result.details["caches"]["cache_history"]["status"] == "under-utilized"
    assert result.details["caches"]["cache_history"]["display_name"] == expected_label
    assert result.details["caches"]["cache_trend"]["status"] == "ok"
    assert result.remediation is not None
    assert "Under-utilized caches" in result.remediation


def test_cache_utilization_check_fail_over_utilized():
    """Test that check fails when caches are over-utilized."""
    cache_data = {
        "cache_value": {
            "used_percent": 75.0,  # Over 60% threshold
            "free_percent": 25.0,
            "key": "zabbix[cache,value,pused]",
        },
        "cache_history": {
            "used_percent": 50.0,  # Within range
            "free_percent": 50.0,
            "key": "zabbix[cache,history,pused]",
        },
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "cache utilization issues detected" in result.summary
    assert "1 out of 2 caches outside" in result.summary
    assert "Offending caches:" in result.summary
    value_label = CACHE_DISPLAY_NAMES["cache_value"]
    assert f"{value_label}: 75.0% (over-utilized)" in result.summary
    assert result.details["problem_caches"] == 1
    assert f"{value_label}: 75.0% (over-utilized)" in result.details["problems"]
    assert result.details["caches"]["cache_value"]["status"] == "over-utilized"
    assert result.details["caches"]["cache_value"]["display_name"] == value_label
    assert result.details["caches"]["cache_history"]["status"] == "ok"
    assert result.remediation is not None
    assert "Over-utilized caches" in result.remediation


def test_cache_utilization_check_fail_multiple_problems():
    """Test that check fails when multiple caches have problems."""
    cache_data = {
        "cache_history": {
            "used_percent": 30.0,  # Under-utilized
            "free_percent": 70.0,
            "key": "zabbix[cache,history,pused]",
        },
        "cache_value": {
            "used_percent": 80.0,  # Over-utilized
            "free_percent": 20.0,
            "key": "zabbix[cache,value,pused]",
        },
        "cache_trend": {
            "used_percent": 50.0,  # OK
            "free_percent": 50.0,
            "key": "zabbix[cache,trend,pused]",
        },
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert "2 out of 3 caches outside" in result.summary
    assert "Offending caches:" in result.summary
    history_label = CACHE_DISPLAY_NAMES["cache_history"]
    value_label = CACHE_DISPLAY_NAMES["cache_value"]
    assert f"{history_label}: 30.0% (under-utilized)" in result.summary
    assert f"{value_label}: 80.0% (over-utilized)" in result.summary
    assert result.details["problem_caches"] == 2
    assert f"{history_label}: 30.0% (under-utilized)" in result.details["problems"]
    assert f"{value_label}: 80.0% (over-utilized)" in result.details["problems"]


def test_cache_utilization_check_custom_thresholds():
    """Test that check uses custom thresholds from configuration."""
    cache_data = {
        "cache_history": {
            "used_percent": 35.0,
            "free_percent": 65.0,
            "key": "zabbix[cache,history,pused]",
        },
    }
    config = {
        "zabbix.cache.min_utilization_percent": 30.0,
        "zabbix.cache.max_utilization_percent": 70.0,
    }
    ctx = make_ctx(cache_data=cache_data, config=config)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.PASS
    assert "30.0%-70.0%" in result.summary
    assert result.details["thresholds"]["min_utilization_percent"] == 30.0
    assert result.details["thresholds"]["max_utilization_percent"] == 70.0


def test_cache_utilization_check_custom_thresholds_fail():
    """Test that check fails with custom thresholds."""
    cache_data = {
        "cache_history": {
            "used_percent": 35.0,
            "free_percent": 65.0,
            "key": "zabbix[cache,history,pused]",
        },
    }
    config = {
        "zabbix.cache.min_utilization_percent": 40.0,
        "zabbix.cache.max_utilization_percent": 50.0,
    }
    ctx = make_ctx(cache_data=cache_data, config=config)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert f"{CACHE_DISPLAY_NAMES['cache_history']}: 35.0% (under-utilized)" in result.details["problems"]
    assert f"{CACHE_DISPLAY_NAMES['cache_history']}: 35.0% (under-utilized)" in result.summary


def test_cache_utilization_check_invalid_configuration():
    """Test that check errors when configuration is invalid."""
    cache_data = {
        "cache_history": {
            "used_percent": 50.0,
            "free_percent": 50.0,
            "key": "zabbix[cache,history,pused]",
        },
    }
    config = {
        "zabbix.cache.min_utilization_percent": 70.0,  # Higher than max
        "zabbix.cache.max_utilization_percent": 60.0,
    }
    ctx = make_ctx(cache_data=cache_data, config=config)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.ERROR
    assert "Invalid configuration: minimum utilization must be less than maximum" in result.summary


def test_cache_utilization_check_boundary_values():
    """Test that check handles boundary values correctly."""
    cache_data = {
        "cache_at_min": {
            "used_percent": 40.0,  # Exactly at min threshold
            "free_percent": 60.0,
            "key": "zabbix[cache,test_min,pused]",
        },
        "cache_at_max": {
            "used_percent": 60.0,  # Exactly at max threshold
            "free_percent": 40.0,
            "key": "zabbix[cache,test_max,pused]",
        },
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.PASS
    assert result.details["problem_caches"] == 0


def test_cache_utilization_check_edge_case_just_outside():
    """Test that check correctly identifies values just outside thresholds."""
    cache_data = {
        "cache_just_under": {
            "used_percent": 39.9,  # Just under 40%
            "free_percent": 60.1,
            "key": "zabbix[cache,test1,pused]",
        },
        "cache_just_over": {
            "used_percent": 60.1,  # Just over 60%
            "free_percent": 39.9,
            "key": "zabbix[cache,test2,pused]",
        },
    }
    ctx = make_ctx(cache_data=cache_data)
    result = ZabbixCacheUtilizationCheck().run(ctx)
    assert result.status is Status.FAIL
    assert result.details["problem_caches"] == 2
    assert "cache_just_under: 39.9% (under-utilized)" in result.details["problems"]
    assert "cache_just_over: 60.1% (over-utilized)" in result.details["problems"]