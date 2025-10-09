from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any, Callable

from auditx.core.facts import register_provider

_MEMINFO_PATH = Path("/proc/meminfo")


def _load_os_release() -> dict[str, str] | None:
    """Return parsed `/etc/os-release` data when available."""

    try:
        release = platform.freedesktop_os_release()
    except (AttributeError, OSError, ValueError):
        return None
    return dict(release)


def _load_average() -> dict[str, float] | None:
    """Return the 1m/5m/15m system load averages when supported."""

    try:
        one_minute, five_minutes, fifteen_minutes = os.getloadavg()
    except (AttributeError, OSError):
        return None
    return {
        "1m": one_minute,
        "5m": five_minutes,
        "15m": fifteen_minutes,
    }


def _root_disk_usage(root: Path) -> dict[str, int] | None:
    """Return disk usage details for the provided root path."""

    try:
        usage = shutil.disk_usage(root)
    except OSError:
        return None
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
    }


def _meminfo_snapshot(path: Path = _MEMINFO_PATH) -> dict[str, int] | None:
    """Return selected memory metrics sourced from `/proc/meminfo`."""

    if not path.exists():
        return None

    aliases = {
        "MemTotal": "total_kib",
        "MemAvailable": "available_kib",
        "MemFree": "free_kib",
        "Buffers": "buffers_kib",
        "Cached": "cached_kib",
    }
    data: dict[str, int] = {}

    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                key, _, raw_value = line.partition(":")
                if key not in aliases:
                    continue
                value = raw_value.strip().split()
                if not value:
                    continue
                try:
                    data[aliases[key]] = int(value[0])
                except ValueError:
                    continue
    except OSError:
        return None

    if not data:
        return None
    return data


def _linux_base(
    params: dict[str, Any],
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Collect baseline Linux system facts for checks and reports."""

    if progress:
        progress("Gathering basic system metrics")
    facts: dict[str, Any] = {
        "linux.uname": platform.uname()._asdict(),
        "linux.cpu.count": os.cpu_count(),
    }

    load_average = _load_average()
    if load_average is not None:
        if progress:
            progress("Captured load average")
        facts["linux.load_average"] = load_average

    disk_usage = _root_disk_usage(Path("/"))
    if disk_usage is not None:
        if progress:
            progress("Collected root filesystem usage")
        facts["linux.disk.root"] = disk_usage

    meminfo = _meminfo_snapshot()
    if meminfo is not None:
        if progress:
            progress("Read memory statistics")
        facts["linux.memory"] = meminfo

    os_release = _load_os_release()
    if os_release is not None:
        if progress:
            progress("Parsed /etc/os-release")
        facts["linux.os_release"] = os_release

    return facts


register_provider("linux", _linux_base)
