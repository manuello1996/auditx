from __future__ import annotations

from auditx.core.models import CheckMeta, CheckResult, Severity, Status
from auditx.core.reporting import to_html


def _make_result(status: Status, severity: Severity, summary: str) -> CheckResult:
    meta = CheckMeta(
        id="test.check",
        name="Test Check",
        version="1.0.0",
        tech="zabbix",
        severity=severity,
        tags=set(),
        description="",
        explanation="Reason",
        remediation="Fix",
    )
    return CheckResult(
        meta=meta,
        status=status,
        summary=summary,
        details={"foo": "bar"},
        duration_ms=1234,
    )


def test_to_html_contains_table_and_rows() -> None:
    html = to_html([_make_result(Status.WARN, Severity.MEDIUM, "Something happened")])
    assert "<!DOCTYPE html>" in html
    assert "<table" in html
    assert "status-WARN" in html
    assert "Something happened" in html
    assert "1234 ms" not in html
    assert "foo" not in html  # details removed from table


def test_to_html_empty_results_renders_placeholder() -> None:
    html = to_html([])
    assert "No check results available" in html


def test_to_html_with_metadata_renders_section() -> None:
    html = to_html([], metadata=[("Command", "auditx run"), ("Duration", "1.23 s")])
    assert "Run information" in html
    assert "Command" in html
    assert "1.23 s" in html
    assert "<details>" in html
