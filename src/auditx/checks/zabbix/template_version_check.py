from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence, Set, Tuple

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


@dataclass(frozen=True)
class TemplateRecord:
    """Small helper representing a template and its version metadata."""

    id: str
    name: str
    version: str | None
    vendor_version: str | None
    vendor_name: str | None
    source: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "TemplateRecord":
        identifier = str(payload.get("id") or payload.get("templateid") or "")
        name = str(payload.get("name") or identifier)
        vendor_name_raw = payload.get("vendor_name")
        vendor_version_raw = payload.get("vendor_version")
        version_raw = payload.get("version")

        vendor_name = str(vendor_name_raw).strip() if vendor_name_raw not in (None, "") else None
        vendor_version = str(vendor_version_raw).strip() if vendor_version_raw not in (None, "") else None

        version_candidates = [version_raw, vendor_version]
        version: str | None = None
        for candidate in version_candidates:
            if candidate is None:
                continue
            text = str(candidate).strip()
            if text:
                version = text
                break

        return cls(
            id=identifier,
            name=name,
            version=version,
            vendor_version=vendor_version,
            vendor_name=vendor_name,
            source=payload,
        )


class ZabbixTemplateVersionCheck(BaseCheck):
    """Ensure template version metadata is aligned with the running Zabbix release."""

    meta = CheckMeta(
        id="zabbix.templates.version",
        name="Template version compliance",
        version="1.2.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"configuration", "maintenance"},
        description="Flag templates declaring a version older than the detected Zabbix server version.",
        explanation="Outdated templates miss fixes and macros shipped with the running Zabbix version.",
        remediation="Re-import the listed templates from a release matching the server or document intentional exceptions.",
        required_facts=("zabbix.templates", "zabbix.api.version"),
        inputs=(
            {
                "key": "zabbix.template_version_ignore",
                "required": False,
                "secret": False,
                "description": "Comma-separated list (or array) of template names to ignore.",
            },
        ),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        templates_fact = ctx.facts.get("zabbix.templates", tech="zabbix")
        if not templates_fact:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No template facts available; ensure the Zabbix provider collected templates.",
                explanation="Missing template data prevents alignment with the server version.",
                remediation="Grant template.get API access and refresh the discovery facts before rerunning.",
            )

        if not isinstance(templates_fact, Sequence):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Unexpected format for zabbix.templates fact (expected sequence).",
                details={"type": type(templates_fact).__name__},
                explanation="Malformed template metadata hides outdated releases.",
                remediation="Ensure zabbix.templates returns a list of template objects from the provider.",
            )

        server_version_raw = ctx.facts.get("zabbix.api.version", tech="zabbix")
        if not isinstance(server_version_raw, str) or not server_version_raw.strip():
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="Zabbix server version is unavailable; cannot compare template versions.",
                explanation="Without the server version there's nothing to compare against.",
                remediation="Collect zabbix.api.version by authenticating with sufficient privileges.",
            )

        server_version = _parse_server_version(server_version_raw)
        if server_version is None:
            return CheckResult(
                meta=self.meta,
                status=Status.WARN,
                summary=f"Unable to parse Zabbix server version '{server_version_raw}'.",
                details={"server_version_raw": server_version_raw},
                remediation="Verify the Zabbix API version string or update the parser to handle custom formats.",
                explanation="Non-standard version strings block compliance checks.",
            )

        config_section = _section(ctx.config, "zabbix")
        ignored_templates = _normalise_name_set(config_section.get("template_version_ignore"))

        outdated: list[dict[str, Any]] = []
        ignored_no_version: list[dict[str, Any]] = []
        unparsable: list[dict[str, Any]] = []
        evaluated = 0

        for entry in templates_fact:
            if not isinstance(entry, Mapping):
                continue
            record = TemplateRecord.from_mapping(entry)
            name_key = record.name.strip().lower()
            if name_key and name_key in ignored_templates:
                continue
            if record.version is None:
                ignored_no_version.append(
                    _template_detail(record, reason="Version metadata missing; template ignored")
                )
                continue
            parsed = _parse_template_version(record.version)
            if parsed is None:
                unparsable.append(
                    _template_detail(record, reason=f"Unrecognised version string '{record.version}'")
                )
                continue
            evaluated += 1
            template_major_minor = (parsed[0], parsed[1])
            if template_major_minor < server_version:
                outdated.append(
                    _template_detail(
                        record,
                        reason=(
                            "Template declares version "
                            f"{record.version} older than server {server_version_raw}"
                        ),
                    )
                )

        details: Dict[str, Any] = {
            "server_version": server_version_raw,
            "server_version_major_minor": {
                "major": server_version[0],
                "minor": server_version[1],
            },
            "evaluated_templates": evaluated,
            "ignored_templates": sorted(ignored_templates),
            "outdated_templates": outdated,
        }
        if ignored_no_version:
            details["ignored_templates_no_version"] = ignored_no_version
        if unparsable:
            details["unparsable_templates"] = unparsable

        if outdated:
            count = len(outdated)
            formatted_names = []
            for entry in outdated:
                name = entry.get("name") or entry.get("id") or "unknown"
                version_text = entry.get("version") or "unknown version"
                formatted_names.append(f"{name} ({version_text})")

            details["outdated_template_names"] = formatted_names
            name_suffix = ""
            if formatted_names:
                name_suffix = ": " + ", ".join(formatted_names)
            return CheckResult(
                meta=self.meta,
                status=Status.FAIL,
                summary=(
                    f"{count} template(s) declare a version older than Zabbix server "
                    f"{server_version_raw}{name_suffix}."
                ),
                details=details,
                remediation=(
                    "Re-import or upgrade the listed templates from a release matching the running Zabbix version."
                ),
                explanation="Old templates may miss discovery rules, macros, and fixes required by the current server.",
            )

        if unparsable:
            return CheckResult(
                meta=self.meta,
                status=Status.WARN,
                summary="Some templates contain non-standard version strings; verify they match the running server release.",
                details=details,
                remediation="Normalise template version metadata or adjust the ignore list if custom semantics are expected.",
                explanation="Unparseable versions stop automated drift detection.",
            )

        if evaluated == 0:
            summary = "No templates evaluated after applying ignore filters."
            if ignored_no_version:
                summary = (
                    "No templates evaluated; "
                    f"{len(ignored_no_version)} template(s) missing version metadata."
                )
            elif ignored_templates:
                summary = (
                    "No templates evaluated; all templates matched the ignore list."
                )
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary=summary,
                details=details,
                explanation="Nothing was evaluated, so divergence could remain unnoticed.",
                remediation="Adjust the ignore list or add version metadata to templates so they can be checked.",
            )

        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary=(
                f"All evaluated templates declare versions aligned with Zabbix server {server_version_raw}."
            ),
            details=details,
        )


def _section(config: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = config.get(key)
    if isinstance(value, dict):
        return value
    return {}


def _normalise_name_set(raw: Any) -> Set[str]:
    if raw is None:
        return set()
    entries: Iterable[str]
    if isinstance(raw, str):
        entries = (segment.strip() for segment in raw.split(","))
    elif isinstance(raw, (list, tuple, set)):
        entries = (str(item).strip() for item in raw)
    else:
        return set()
    return {entry.lower() for entry in entries if entry}


def _parse_template_version(value: str) -> Tuple[int, int, int] | None:
    text = value.strip()
    if not text:
        return None

    hyphen_match = re.search(r"(\d+)\.(\d+)-(\d+)", text)
    if hyphen_match:
        major, minor, revision = hyphen_match.groups()
        return int(major), int(minor), int(revision)

    dot_match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if dot_match:
        major, minor, patch = dot_match.groups()
        return int(major), int(minor), int(patch or 0)

    return None


def _parse_server_version(value: str) -> Tuple[int, int] | None:
    text = value.strip()
    if not text:
        return None

    match = re.search(r"(\d+)\.(\d+)", text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _template_detail(record: TemplateRecord, *, reason: str) -> Dict[str, Any]:
    detail = {
        "id": record.id,
        "name": record.name,
        "version": record.version,
        "reason": reason,
    }
    if record.vendor_version and record.vendor_version != record.version:
        detail["vendor_version"] = record.vendor_version
    if record.vendor_name:
        detail["vendor_name"] = record.vendor_name
    groups = record.source.get("groups")
    if isinstance(groups, Sequence):
        detail["groups"] = [group for group in groups if isinstance(group, Mapping)]
    return detail


__all__ = ["ZabbixTemplateVersionCheck"]
