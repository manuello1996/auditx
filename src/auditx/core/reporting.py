from __future__ import annotations

import json
from html import escape
from typing import Iterable, List
from typing import Mapping, Sequence

from .models import CheckResult, Severity, Status

def to_json(results: Iterable[CheckResult]) -> str:
    """Convert check results to JSON format.
    
    Args:
        results: Iterable of check results
        
    Returns:
        Pretty-printed JSON string
    """
    return json.dumps([
        {
            "id": r.meta.id,
            "name": r.meta.name,
            "version": r.meta.version,
            "tech": r.meta.tech,
            "severity": r.meta.severity,
            "status": r.status,
            "summary": r.summary,
            "details": r.details,
            "remediation": r.remediation,
            "explanation": r.explanation,
            "duration_ms": r.duration_ms,
        } for r in results
    ], indent=2, default=str)

def to_markdown(results: Iterable[CheckResult]) -> str:
    """Convert check results to Markdown format.
    
    Creates a structured Markdown document with sections for each check,
    including metadata, summary, and detailed results.
    
    Args:
        results: Iterable of check results
        
    Returns:
        Markdown-formatted string
    """
    lines = ["# Audit Report"]
    for r in results:
        lines += [
            f"\n## {r.meta.id} — {r.status}",
            f"**Name:** {r.meta.name}",
            f"**Tech:** {r.meta.tech} | **Severity:** {r.meta.severity}",
            f"**Summary:** {r.summary}",
            f"**Explanation:** {r.explanation or '-'}",
            f"**Duration:** {r.duration_ms} ms",
            f"**Remediation:** {r.remediation or '-'}",
            "\n````json", json.dumps(r.details, indent=2, default=str), "````",
        ]
    return "\n".join(lines)


def _normalise_status(value: object) -> str:
    """Normalize a status value to string format.
    
    Args:
        value: Status enum or string
        
    Returns:
        String representation of the status
    """
    if isinstance(value, Status):
        return value.value
    return str(value)


def _normalise_severity(value: object) -> str:
    """Normalize a severity value to string format.
    
    Args:
        value: Severity enum or string
        
    Returns:
        String representation of the severity
    """
    if isinstance(value, Severity):
        return value.value
    return str(value)


def to_html(
    results: Iterable[CheckResult],
    *,
    metadata: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
) -> str:
    entries: List[dict[str, str]] = []
    for r in results:
        entries.append(
            {
                "id": escape(str(r.meta.id)),
                "name": escape(str(r.meta.name)),
                "tech": escape(str(r.meta.tech)),
                "severity": escape(_normalise_severity(r.meta.severity)),
                "status": escape(_normalise_status(r.status)),
                "summary": escape(str(r.summary)),
                "explanation": escape(str(r.explanation or "-")),
                "remediation": escape(str(r.remediation or "-")),
            }
        )

    meta_entries: List[tuple[str, str]] = []
    if metadata:
        if isinstance(metadata, Mapping):
            meta_entries = [(str(key), str(value)) for key, value in metadata.items()]
        else:
            meta_entries = [(str(key), str(value)) for key, value in metadata]

    html: List[str] = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "    <meta charset=\"utf-8\" />",
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />",
        "    <title>AuditX Report</title>",
        "    <style>",
        "        body { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 2rem; color: #1f2933; background: #f9fafb; }",
        "        h1 { margin-bottom: 1.5rem; }",
    "        .meta { margin-bottom: 2rem; background: #ffffff; padding: 1rem 1.5rem; border-left: 4px solid #2563eb; box-shadow: 0 1px 2px rgba(0,0,0,0.08); }",
    "        .meta details { margin: 0; }",
    "        .meta summary { margin: 0; font-size: 1.05rem; font-weight: 600; color: #1f2937; cursor: pointer; }",
    "        .meta summary:focus { outline: none; }",
    "        .meta dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.5rem 1rem; margin: 0; padding-top: 0.75rem; }",
        "        .meta dt { font-weight: 600; color: #1f2937; }",
        "        .meta dd { margin: 0; color: #4b5563; }",
        "        table { border-collapse: collapse; width: 100%; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }",
        "        th, td { border: 1px solid #e5e7eb; padding: 0.75rem; text-align: left; vertical-align: top; }",
        "        th { background: #111827; color: #ffffff; }",
        "        tr:nth-child(even) { background: #f3f4f6; }",
        "        .status-PASS { color: #047857; font-weight: 600; }",
        "        .status-WARN { color: #b45309; font-weight: 600; }",
        "        .status-FAIL { color: #b91c1c; font-weight: 600; }",
        "        .status-SKIP { color: #4b5563; font-weight: 600; }",
        "        .status-ERROR { color: #7c3aed; font-weight: 600; }",
        "    </style>",
        "</head>",
        "<body>",
        "    <h1>AuditX Report</h1>",
    ]

    if meta_entries:
        html += [
            "    <section class=\"meta\">",
            "        <details>",
            "            <summary>Run information</summary>",
            "            <dl>",
        ]
        for label, value in meta_entries:
            html += [
                f"                <dt>{escape(label)}</dt>",
                f"                <dd>{escape(value)}</dd>",
            ]
        html += [
            "            </dl>",
            "        </details>",
            "    </section>",
        ]

    html += [
        "    <table>",
        "        <thead>",
        "            <tr>",
        "                <th>Status</th>",
        "                <th>ID</th>",
        "                <th>Name</th>",
        "                <th>Tech</th>",
        "                <th>Severity</th>",
        "                <th>Summary</th>",
        "                <th>Explanation</th>",
        "                <th>Remediation</th>",
        "            </tr>",
        "        </thead>",
        "        <tbody>",
    ]

    if entries:
        for entry in entries:
            status_class = f"status-{entry['status']}" if entry["status"] else ""
            html += [
                "            <tr>",
                f"                <td class=\"{status_class}\">{entry['status']}</td>",
                f"                <td>{entry['id']}</td>",
                f"                <td>{entry['name']}</td>",
                f"                <td>{entry['tech']}</td>",
                f"                <td>{entry['severity']}</td>",
                f"                <td>{entry['summary']}</td>",
                f"                <td>{entry['explanation']}</td>",
                f"                <td>{entry['remediation']}</td>",
                "            </tr>",
            ]
    else:
        html += [
            "            <tr>",
            "                <td colspan=\"8\" style=\"text-align:center;\">No check results available.</td>",
            "            </tr>",
        ]

    html += [
        "        </tbody>",
        "    </table>",
        "</body>",
        "</html>",
    ]

    return "\n".join(html)


def docs_to_html(entries: Sequence[Mapping[str, object]]) -> str:
    """Render check documentation entries as an HTML document.

    Args:
        entries: Sequence of mappings describing each check's metadata and guidance.

    Returns:
        Styled HTML document containing a card for each check.
    """
    def _format_inputs(items: object) -> str:
        if not items:
            return "<li><span class=\"muted\">None</span></li>"

        if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
            return "<li><span class=\"muted\">None</span></li>"

        rendered: List[str] = []
        for raw in items:
            if not isinstance(raw, Mapping):
                continue
            key = escape(str(raw.get("key", "")))
            description = escape(str(raw.get("description", "")))
            required = bool(raw.get("required", False))
            secret = bool(raw.get("secret", False))

            key_html = key or "&lt;unknown&gt;"
            description_html = description or "<span class=\"muted\">No description provided.</span>"
            flags: List[str] = []
            if required:
                flags.append("required")
            if secret:
                flags.append("secret")
            flags_html = " <span class=\"flags\">({})</span>".format(", ".join(flags)) if flags else ""
            rendered.append(
                "<li><code>{key}</code>{flags} — {description}</li>".format(
                    key=key_html,
                    flags=flags_html,
                    description=description_html,
                )
            )
        return "\n".join(rendered) if rendered else "<li><span class=\"muted\">None</span></li>"

    html: List[str] = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "    <meta charset=\"utf-8\" />",
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />",
        "    <title>AuditX Checks Documentation</title>",
        "    <style>",
        "        body { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 2rem; color: #1f2933; background: #f9fafb; }",
        "        h1 { margin-bottom: 2rem; font-size: 2rem; }",
        "        .grid { display: grid; gap: 1.5rem; }",
        "        .card { background: #ffffff; border-radius: 0.75rem; box-shadow: 0 12px 24px -12px rgba(15, 23, 42, 0.4); padding: 1.75rem; border: 1px solid #e2e8f0; }",
        "        .card h2 { margin-top: 0; margin-bottom: 0.5rem; font-size: 1.5rem; color: #111827; }",
        "        .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin-bottom: 1.25rem; }",
        "        .meta div { background: #f8fafc; border-radius: 0.5rem; padding: 0.75rem; border: 1px solid #e2e8f0; }",
        "        .meta span.label { display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.35rem; font-weight: 600; }",
        "        .meta span.value { font-size: 0.95rem; color: #0f172a; }",
        "        .section-title { font-size: 1rem; font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; color: #0f172a; }",
        "        ul.inputs { list-style: disc inside; padding: 0; margin: 0; }",
        "        ul.inputs li { margin-bottom: 0.4rem; }",
        "        code { background: #0f172a0d; padding: 0.15rem 0.25rem; border-radius: 0.25rem; font-size: 0.85rem; }",
        "        .muted { color: #94a3b8; font-style: italic; }",
        "        .flags { font-size: 0.75rem; color: #dc2626; margin-left: 0.25rem; }",
        "    </style>",
        "</head>",
        "<body>",
        "    <h1>AuditX Checks Documentation</h1>",
        "    <section class=\"grid\">",
    ]

    for entry in entries:
        check_id = escape(str(entry.get("id", "")))
        name = escape(str(entry.get("name", "")))
        severity = escape(str(entry.get("severity", "")))
        tech = escape(str(entry.get("tech", "")))
        version = escape(str(entry.get("version", "")))
        explanation = escape(str(entry.get("explanation", "-")))
        remediation = escape(str(entry.get("remediation", "-")))
        description = escape(str(entry.get("description", "-")))
        tags_obj = entry.get("tags", [])
        tags = ", ".join(sorted(str(tag) for tag in tags_obj)) if tags_obj else "-"
        tags = escape(tags)
        requires_privileges = "Yes" if entry.get("requires_privileges") else "No"

        html += [
            "        <article class=\"card\">",
            f"            <h2>{check_id} — {name}</h2>",
            "            <div class=\"meta\">",
            "                <div><span class=\"label\">Tech</span><span class=\"value\">{}</span></div>".format(tech),
            "                <div><span class=\"label\">Severity</span><span class=\"value\">{}</span></div>".format(severity),
            "                <div><span class=\"label\">Version</span><span class=\"value\">{}</span></div>".format(version),
            "                <div><span class=\"label\">Requires Privileges</span><span class=\"value\">{}</span></div>".format(requires_privileges),
            "                <div><span class=\"label\">Tags</span><span class=\"value\">{}</span></div>".format(tags or "-"),
            "            </div>",
            "            <div>",
            "                <div class=\"section-title\">Description</div>",
            f"                <p>{description}</p>",
            "                <div class=\"section-title\">Explanation</div>",
            f"                <p>{explanation}</p>",
            "                <div class=\"section-title\">Remediation</div>",
            f"                <p>{remediation}</p>",
            "                <div class=\"section-title\">Inputs</div>",
            "                <ul class=\"inputs\">",
            f"                    {_format_inputs(entry.get('inputs'))}",
            "                </ul>",
            "            </div>",
            "        </article>",
        ]

    html += [
        "    </section>",
        "</body>",
        "</html>",
    ]

    return "\n".join(html)
