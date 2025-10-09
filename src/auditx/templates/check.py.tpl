from __future__ import annotations
"""${check_name}: ${short_description}

Write in ENGLISH. Include purpose, approach and examples.
"""
from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, Severity, Status

class ${class_name}(BaseCheck):
    """${long_description}"""

    meta = CheckMeta(
        id="${tech}.${slug}",
        name="${human_name}",
        version="0.1.0",
        tech="${tech}",
        severity=Severity.${severity},
        tags={${tags}},
        description="${short_description}",
        inputs=${inputs},
        required_facts=${required_facts},
    )

    def run(self, ctx):
        # TODO: implement the actual logic
        # Example: read a fact
        # value = ctx.facts.get("${tech}.example", tech="${tech}")
        return CheckResult(
            meta=self.meta,
            status=Status.PASS,
            summary="${human_name}: placeholder PASS",
            details={},
            remediation="Describe how to fix the issue if it fails.",
        )

__all__ = ["${class_name}"]
