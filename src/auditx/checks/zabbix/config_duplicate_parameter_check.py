from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Set

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


@dataclass(frozen=True)
class ParameterOccurrence:
    """Represent a single configuration parameter definition.

    Attributes store the raw key/value pair alongside the file location so we can
    surface actionable remediation guidance to the user whenever a parameter is
    defined multiple times.
    """

    key: str
    normalized_key: str
    value: str
    path: Path
    line: int

    def as_detail(self) -> Dict[str, Any]:
        """Return a JSON-serialisable payload for reporting."""

        return {
            "key": self.key,
            "value": self.value,
            "file": str(self.path),
            "line": self.line,
        }


@dataclass
class ScanResult:
    occurrences: Dict[str, List[ParameterOccurrence]]
    files_scanned: List[Path]
    missing_includes: List[str]


class ZabbixConfigDuplicateParameterCheck(BaseCheck):
    """Detect duplicate parameter definitions across Zabbix configuration includes."""

    meta = CheckMeta(
        id="zabbix.config.duplicate_parameters",
        name="Duplicate Zabbix configuration parameters",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"configuration", "consistency"},
        description="Ensure each Zabbix configuration parameter is defined at most once across all included files.",
        explanation="Duplicate definitions make it unclear which parameter value Zabbix will honour, leading to drift and outages.",
        remediation="Keep each parameter in a single file or remove duplicates so operators know which value applies.",
        requires_privileges=True,
        inputs=(
            {
                "key": "zabbix.config_file",
                "required": True,
                "secret": False,
                "description": "Absolute path to the main Zabbix configuration file (e.g. /etc/zabbix/zabbix_agentd.conf)",
            },
            {
                "key": "zabbix.config_duplicate_ignore_keys",
                "required": False,
                "secret": False,
                "description": "Comma separated list of keys allowed to appear multiple times (case-insensitive)",
            },
        ),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        config_section = _section(ctx.config, "zabbix")
        config_path_value = config_section.get("config_file")
        if not config_path_value:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="Missing zabbix.config_file input; unable to inspect configuration",
                explanation="Without the main configuration path the check cannot inspect for conflicting overrides.",
                remediation="Provide --set zabbix.config_file=/path/to/zabbix_agentd.conf or update auditx.yaml before rerunning.",
            )

        config_path = Path(str(config_path_value)).expanduser()
        if not config_path.is_absolute():
            config_path = (Path.cwd() / config_path).resolve()

        if not config_path.exists():
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary=f"Configuration file {config_path} not found",
                explanation="If the root configuration file is missing, the agent may be misconfigured or not installed correctly.",
                remediation="Verify the path on the target host and mount or copy the configuration before re-running.",
            )

        allowed_duplicates = _normalise_key_set(config_section.get("config_duplicate_ignore_keys"))

        scan = _scan_configuration(config_path)
        duplicates = {
            key: occs
            for key, occs in scan.occurrences.items()
            if len(occs) > 1 and key not in allowed_duplicates
        }

        details: Dict[str, Any] = {
            "files_scanned": [str(path) for path in scan.files_scanned],
            "duplicates": {
                occs[0].key: [occ.as_detail() for occ in occs]
                for occs in duplicates.values()
            },
        }
        if scan.missing_includes:
            details["missing_includes"] = sorted(scan.missing_includes)

        if duplicates:
            duplicate_keys = ", ".join(sorted({occs[0].key for occs in duplicates.values()}))
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=f"Found duplicate parameter definitions for: {duplicate_keys}",
                details=details,
                explanation="Duplicate parameters cause Zabbix to pick the last value silently, hiding configuration drift.",
                remediation="Ensure each parameter is defined only once across main and included configuration files.",
            )

        if scan.missing_includes:
            return CheckResult(
                meta=self.meta,
                status=Status.WARN,
                summary="Some Include directives referenced files that were not found",
                details=details,
                remediation="Verify Include/IncludeDir paths and ensure referenced files exist.",
                explanation="Missing includes mean parts of the intended configuration never load.",
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="No duplicate parameter definitions detected across configuration includes",
            details=details,
        )


def _section(config: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = config.get(key)
    if isinstance(value, dict):
        return value
    return {}


def _normalise_key_set(raw: Any) -> Set[str]:
    if raw is None:
        return set()
    values: Iterable[str]
    if isinstance(raw, str):
        values = (segment.strip() for segment in raw.split(","))
    elif isinstance(raw, (list, tuple, set)):
        values = (str(item).strip() for item in raw)
    else:
        return set()
    return {value.lower() for value in values if value}


def _scan_configuration(root: Path) -> ScanResult:
    occurrences: Dict[str, List[ParameterOccurrence]] = {}
    visited: Set[Path] = set()
    missing_includes: List[str] = []
    files_scanned: List[Path] = []

    def _visit(target: Path) -> None:
        real_path = target.resolve()
        if real_path in visited:
            return
        if not real_path.exists():
            missing_includes.append(str(target))
            return
        visited.add(real_path)
        files_scanned.append(real_path)

        try:
            lines = real_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            missing_includes.append(str(real_path))
            return

        for index, raw_line in enumerate(lines, start=1):
            line = _strip_comments(raw_line)
            if not line:
                continue
            if "=" not in line:
                continue
            raw_key, raw_value = line.split("=", 1)
            key = raw_key.strip()
            value = raw_value.strip()
            if not key:
                continue
            normalized_key = key.lower()
            if normalized_key in {"include", "includedir"}:
                for include_path in _resolve_include_paths(real_path, normalized_key, value):
                    _visit(include_path)
                continue
            occurrence = ParameterOccurrence(
                key=key,
                normalized_key=normalized_key,
                value=value,
                path=real_path,
                line=index,
            )
            occurrences.setdefault(normalized_key, []).append(occurrence)

    _visit(root)
    files_scanned.sort()
    missing_includes = sorted(set(missing_includes))
    return ScanResult(occurrences=occurrences, files_scanned=files_scanned, missing_includes=missing_includes)


def _strip_comments(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    hash_index = line.find("#")
    if hash_index != -1:
        line = line[:hash_index].strip()
    return line


def _resolve_include_paths(origin: Path, directive: str, value: str) -> Sequence[Path]:
    normalized_value = value.strip().strip('"')
    if not normalized_value:
        return []
    expanded = os.path.expandvars(os.path.expanduser(normalized_value))
    if not os.path.isabs(expanded):
        expanded = str((origin.parent / expanded).resolve())

    if directive == "includedir":
        directory = Path(expanded)
        if not directory.is_dir():
            return [directory]
        candidates = [path for path in sorted(directory.iterdir()) if path.is_file()]
        return candidates

    patterns = glob.glob(expanded)
    if patterns:
        return [Path(match) for match in sorted(set(patterns))]
    return [Path(expanded)]


__all__ = ["ZabbixConfigDuplicateParameterCheck"]
