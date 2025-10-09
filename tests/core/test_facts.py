from __future__ import annotations

from typing import Any

from auditx.core.facts import FactStore, collect_facts, register_provider

_PROGRESS_TECH = "__test_progress__"
_LEGACY_TECH = "__test_legacy__"


def _progress_provider(params: dict[str, Any], progress=None):  # type: ignore[override]
    if progress:
        progress("step one")
        progress("step two")
    return {"example.value": 42}


def _legacy_provider(params: dict[str, Any]):
    return {"legacy.value": True}


register_provider(_PROGRESS_TECH, _progress_provider)
register_provider(_LEGACY_TECH, _legacy_provider)


def test_collect_facts_reports_progress_steps() -> None:
    store = FactStore()
    seen: list[str] = []

    collect_facts(_PROGRESS_TECH, {}, store, reporter=seen.append)

    assert store.data[_PROGRESS_TECH]["example.value"] == 42
    assert seen == ["step one", "step two"]


def test_collect_facts_handles_legacy_providers() -> None:
    store = FactStore()

    collect_facts(_LEGACY_TECH, {}, store, reporter=lambda *_args: None)

    assert store.data[_LEGACY_TECH]["legacy.value"] is True
