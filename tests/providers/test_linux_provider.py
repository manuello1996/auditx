from __future__ import annotations

from auditx.providers.linux_base import _linux_base


def test_linux_provider_collects_expected_facts() -> None:
    """The Linux provider should expose baseline host facts."""

    facts = _linux_base({})

    assert "linux.uname" in facts
    assert isinstance(facts["linux.uname"], dict)
    system_name = facts["linux.uname"].get("system")
    assert system_name is not None
    assert system_name.lower() == "linux"

    assert "linux.cpu.count" in facts
    cpu_count = facts["linux.cpu.count"]
    assert cpu_count is None or cpu_count > 0

    load = facts.get("linux.load_average")
    if load is not None:
        assert set(load) == {"1m", "5m", "15m"}

    disk = facts.get("linux.disk.root")
    if disk is not None:
        assert disk["total_bytes"] >= disk["used_bytes"] >= 0
        assert disk["free_bytes"] >= 0

    memory = facts.get("linux.memory")
    if memory is not None:
        assert memory["total_kib"] > 0
        available = memory.get("available_kib")
        if available is not None:
            assert available <= memory["total_kib"]

    os_release = facts.get("linux.os_release")
    if os_release is not None:
        assert isinstance(os_release, dict)
        assert os_release.get("NAME") is not None
