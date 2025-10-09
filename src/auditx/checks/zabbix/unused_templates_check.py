from __future__ import annotations
"""Unused templates: Detect Zabbix templates that are not linked to any hosts.

Identifies templates that create unnecessary database entries and may indicate
configuration drift or cleanup opportunities. Unused templates consume resources
and can cause confusion in monitoring setup.

This check compares all available templates against host-template mappings to
find templates that are not actively used by any monitored hosts.
"""
from typing import Any, Dict, List, Set
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


class UnusedTemplatesCheck(BaseCheck):
    """Detect Zabbix templates that are not linked to any hosts.
    
    Unused templates can indicate configuration drift and consume database resources
    without providing monitoring value. This check identifies templates that are
    not assigned to any hosts for potential cleanup.
    """

    meta = CheckMeta(
        id="zabbix.unused_templates",
        name="Unused templates",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"configuration", "cleanup", "efficiency"},
        description="Detect templates that are not linked to any hosts and may be unnecessary.",
        explanation="Unused templates clutter configuration and risk deploying stale logic.",
        remediation="Review the listed templates and archive or delete those that are no longer applied.",
        inputs=(),
        required_facts=("zabbix.templates", "zabbix.hosts"),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        templates = ctx.facts.get("zabbix.templates", tech="zabbix") or []
        hosts = ctx.facts.get("zabbix.hosts", tech="zabbix") or []
        
        if not isinstance(templates, list):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Invalid template data format",
                details={"error": "Template data is not in expected list format"},
                explanation="Malformed template data prevents identifying drift.",
                remediation="Ensure the audit account can call template.get and returns a list response.",
            )
            
        if not isinstance(hosts, list):
            return CheckResult(
                meta=self.meta,
                status=Status.ERROR,
                summary="Invalid host data format",
                details={"error": "Host data is not in expected list format"},
                explanation="Without host mappings you can't see template usage.",
                remediation="Grant host.get access or expand the provider to include template_ids for each host.",
            )

        if not templates:
            return CheckResult(
                meta=self.meta,
                status=Status.SKIP,
                summary="No templates found",
                details={"template_count": 0, "host_count": len(hosts)},
                explanation="If no templates exist, configuration drift can't be assessed.",
                remediation="Verify template discovery is enabled and the audit account has template.get permissions.",
            )

        # Collect all template IDs used by hosts
        used_template_ids: Set[str] = set()
        for host in hosts:
            if isinstance(host, dict):
                template_ids = host.get("template_ids") or []
                if isinstance(template_ids, list):
                    used_template_ids.update(template_ids)

        # Find unused templates
        unused_templates: List[Dict[str, Any]] = []
        for template in templates:
            if isinstance(template, dict):
                template_id = template.get("id")
                if template_id and template_id not in used_template_ids:
                    unused_templates.append({
                        "id": template_id,
                        "name": template.get("name", ""),
                        "description": template.get("description", ""),
                    })

        details = {
            "total_templates": len(templates),
            "total_hosts": len(hosts),
            "used_templates": len(used_template_ids),
            "unused_templates": len(unused_templates),
            "unused_template_list": unused_templates,
        }

        if unused_templates:
            template_names = [t.get("name", f"ID:{t.get('id')}") for t in unused_templates[:5]]
            name_list = ", ".join(template_names)
            if len(unused_templates) > 5:
                name_list += f" (and {len(unused_templates) - 5} more)"
                
            summary = f"{len(unused_templates)} unused template(s) found: {name_list}"
            return CheckResult(
                meta=self.meta,
                status=Status.WARN,
                summary=summary,
                details=details,
                remediation=(
                    "Review unused templates and consider removing them if they are no longer needed. "
                    "Unused templates consume database resources and can cause configuration confusion. "
                    "Before removal, verify that templates are not used by host prototypes or other automation."
                ),
                explanation="Dormant templates create confusion and slow tuning efforts.",
            )

        summary = f"All {len(templates)} template(s) are in use"
        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary=summary,
            details=details,
        )

__all__ = ["UnusedTemplatesCheck"]
