from __future__ import annotations

from auditx.cli import _summarize_fact_value


def test_summarize_list_of_objects_with_names() -> None:
    data = [
        {"name": "host-1", "id": 1},
        {"name": "host-2", "id": 2},
        {"name": "host-3", "id": 3},
        {"name": "host-4", "id": 4},
    ]
    summary = _summarize_fact_value(data)
    assert isinstance(summary, str)
    assert summary.startswith("4 object(s)")
    assert "host-1" in summary
    assert "host-2" in summary
    assert summary.endswith("…)")


def test_summarize_empty_list() -> None:
    summary = _summarize_fact_value([])
    assert summary == "0 object(s)"


def test_summarize_list_without_mappings_returns_original() -> None:
    data = [1, 2, 3]
    summary = _summarize_fact_value(data)
    assert summary == data
