from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence, Iterable

from auditx.core.base import BaseCheck
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status


ALLOWED_SECRET_TYPES = {1, 2, "1", "2"}  # 1=Secret text, 2=Vault (Zabbix >= 6.4)


class ZabbixMacroSecretTypeCheck(BaseCheck):
    """Ensure macros with 'password', 'pass' or 'pwd' in the name are secret or vault macros."""

    meta = CheckMeta(
        id="zabbix.macros.secret_type",
        name="Macro secret type compliance",
        version="1.0.0",
        tech="zabbix",
        severity=Severity.MEDIUM,
        tags={"security", "governance"},
        description=(
            "Check global and template macros: any macro whose name contains 'password', 'pass' or 'pwd' must be of type 'Secret text' or 'Vault'."
        ),
        explanation=(
            "Sensitive credentials in plain macros expose secrets; Zabbix supports secret text and vault-backed macros to protect values."
        ),
        remediation=(
            "Convert listed macros to 'Secret text' or migrate them to a secret vault."
        ),
        required_facts=("zabbix.templates", "zabbix.global_macros"),
    )

    def run(self, ctx: RunContext) -> CheckResult:
        templates = ctx.facts.get("zabbix.templates", tech="zabbix")
        global_macros = ctx.facts.get("zabbix.global_macros", tech="zabbix")

        if not templates and not global_macros:
            return CheckResult(
                self.meta,
                Status.SKIP,
                summary="No template or global macro inventory available",
            )

        details: Dict[str, Any] = {
            "non_secret_global_macros": [],
            "non_secret_template_macros": [],
        }

        # Evaluate global macros
        if isinstance(global_macros, Sequence):
            for m in global_macros:
                if not isinstance(m, Mapping):
                    continue
                name = str(m.get("macro") or "").strip()
                if not _is_sensitive_name(name):
                    continue
                mtype = m.get("type")
                has_value = bool(m.get("has_value"))
                is_placeholder = bool(m.get("is_placeholder"))
                if not has_value or is_placeholder:
                    continue
                if mtype not in ALLOWED_SECRET_TYPES:
                    details["non_secret_global_macros"].append({
                        "macro": name,
                        "type": mtype,
                        "id": m.get("id"),
                    })

        # Evaluate template macros (macros provided under each template)
        codes = _team_codes(ctx.config)
        if isinstance(templates, Sequence):
            for t in templates:
                if not isinstance(t, Mapping):
                    continue
                tname = str(t.get("name") or "").strip()
                # Only check templates that are under Templates/<TEAM> groups
                if codes:
                    groups = t.get("groups")
                    group_names: list[str] = []
                    if isinstance(groups, Sequence):
                        for g in groups:
                            if isinstance(g, Mapping):
                                n = str(g.get("name") or "").strip()
                                if n:
                                    group_names.append(n)
                    in_scope = False
                    lower_names = [n.lower() for n in group_names]
                    for code in codes:
                        prefix = f"templates/{code.lower()}"
                        if any(n.startswith(prefix) for n in lower_names):
                            in_scope = True
                            break
                    if not in_scope:
                        continue
                macros = t.get("macros")
                if not isinstance(macros, Sequence):
                    continue
                for m in macros:
                    if not isinstance(m, Mapping):
                        continue
                    name = str(m.get("macro") or "").strip()
                    if not _is_sensitive_name(name):
                        continue
                    mtype = m.get("type")
                    has_value = bool(m.get("has_value"))
                    is_placeholder = bool(m.get("is_placeholder"))
                    if not has_value or is_placeholder:
                        continue
                    if mtype not in ALLOWED_SECRET_TYPES:
                        details["non_secret_template_macros"].append({
                            "template": tname,
                            "macro": name,
                            "type": mtype,
                        })

        non_secret_globals = details["non_secret_global_macros"]
        non_secret_templates = details["non_secret_template_macros"]
        total_offenders = len(non_secret_globals) + len(non_secret_templates)
        if total_offenders:
            # Build explicit macro list: "{MACRO} (Global)" or "{MACRO} ({TEMPLATE})"
            formatted: list[str] = []
            for g in non_secret_globals:
                macro_name = str(g.get("macro") or "").strip()
                if macro_name:
                    formatted.append(f"{macro_name} (Global)")
            for t in non_secret_templates:
                macro_name = str(t.get("macro") or "").strip()
                tmpl_name = str(t.get("template") or "").strip()
                label = f"{macro_name} ({tmpl_name})" if tmpl_name else macro_name
                if macro_name:
                    formatted.append(label)
            suffix = f": {'; '.join(formatted)}" if formatted else ""
            summary = f"{total_offenders} sensitive macro(s) are not secret{suffix}"
            return CheckResult(self.meta, Status.FAIL, summary=summary, details=details)

        # If nothing was evaluated, report skip
        evaluated_any = False
        if isinstance(global_macros, Sequence):
            evaluated_any = evaluated_any or any(_is_sensitive_name(str((m or {}).get("macro") or "")) for m in global_macros if isinstance(m, Mapping))
        if isinstance(templates, Sequence):
            for t in templates:
                if not isinstance(t, Mapping):
                    continue
                # Respect scope here as well when deciding if anything was evaluated
                if codes:
                    groups = t.get("groups")
                    group_names: list[str] = []
                    if isinstance(groups, Sequence):
                        for g in groups:
                            if isinstance(g, Mapping):
                                n = str(g.get("name") or "").strip()
                                if n:
                                    group_names.append(n)
                    lower_names = [n.lower() for n in group_names]
                    in_scope = any(any(n.startswith(f"templates/{code.lower()}" ) for n in lower_names) for code in codes)
                    if not in_scope:
                        continue
                macros = t.get("macros")
                if isinstance(macros, Sequence) and any(_is_sensitive_name(str((m or {}).get("macro") or "")) for m in macros if isinstance(m, Mapping)):
                    evaluated_any = True
                    break
        if not evaluated_any:
            return CheckResult(self.meta, Status.SKIP, summary="No non secret macros matched 'password', 'pass' or 'pwd'")

        return CheckResult(self.meta, Status.PASS, summary="All sensitive macros are secret or vault")


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return "password" in lowered or "pwd" in lowered or "pass" in lowered


def _team_codes(config: Mapping[str, Any]) -> set[str]:
    if not isinstance(config, Mapping):
        return set()
    section = config.get("zabbix")
    raw = section.get("team_codes") if isinstance(section, Mapping) else None
    if raw is None:
        return set()
    entries: Iterable[str]
    if isinstance(raw, str):
        entries = (seg.strip() for seg in raw.split(","))
    elif isinstance(raw, (list, tuple, set)):
        entries = (str(x).strip() for x in raw)
    else:
        return set()
    return {e.upper() for e in entries if e}


__all__ = ["ZabbixMacroSecretTypeCheck"]
