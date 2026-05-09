"""Report generator — Markdown + JSON."""
from __future__ import annotations
import json
import os
from datetime import datetime
from core.context import ScanContext

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ICON  = {"critical": "[!]", "high": "[H]", "medium": "[M]", "low": "[L]", "info": "[i]"}


def generate_report(ctx: ScanContext) -> str:
    """Write Markdown + JSON reports to ~/netcrawler_reports/. Returns the Markdown path."""
    timestamp = ctx.started_at.strftime("%Y%m%d_%H%M%S")
    safe_host  = ctx.target_host.replace(".", "_").replace("/", "_")
    report_dir = f"/mnt/c/Users/taari/Desktop/netcrawler/netcrawler_reports/{safe_host}_{timestamp}"
    os.makedirs(report_dir, exist_ok=True)

    md_path   = os.path.join(report_dir, "report.md")
    json_path = os.path.join(report_dir, "report.json")

    sorted_findings = sorted(
        ctx.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )

    # ── Markdown ──────────────────────────────────────────────────────────────
    lines = [
        f"# NetCrawler Report — {ctx.target_host}",
        f"**Scanned:** {ctx.started_at:%Y-%m-%d %H:%M:%S}  ",
        f"**Completed:** {datetime.now():%Y-%m-%d %H:%M:%S}  ",
        f"**Model:** {ctx.model}  ",
        "",
        "---",
        "",
        "## Target",
        f"- Host: `{ctx.target_host}`",
        f"- Web: {ctx.is_web} ({ctx.target_url})" if ctx.is_web else f"- Web: no",
        f"- Stages completed: {', '.join(ctx.completed_stages) or 'none'}",
        "",
        "## Discovery summary",
        f"- Subdomains: {len(ctx.subdomains)}",
        f"- Emails: {len(ctx.emails)}",
        f"- Open ports: {sorted(set(ctx.ports))}",
        f"- Services: {', '.join(f'{s.port}/{s.name}' for s in ctx.services) or 'none'}",
        f"- Tech stack: {', '.join(ctx.tech_stack) or 'none'}",
        f"- WAF: {ctx.waf_detected or 'not detected'}",
        f"- Directories found: {len(ctx.directories)}",
        "",
        "## Findings",
        f"Total: {len(sorted_findings)}  ",
        f"Critical: {sum(1 for f in sorted_findings if f.severity == 'critical')}  ",
        f"High: {sum(1 for f in sorted_findings if f.severity == 'high')}  ",
        f"Medium: {sum(1 for f in sorted_findings if f.severity == 'medium')}  ",
        "",
    ]

    for i, f in enumerate(sorted_findings, 1):
        icon = SEVERITY_ICON.get(f.severity, "[?]")
        lines += [
            f"### {i}. {icon} {f.title}",
            f"**Severity:** {f.severity.upper()}  ",
            f"**Source:** {f.source}  ",
        ]
        if f.host:
            lines.append(f"**Host:** {f.host}  ")
        if f.port:
            lines.append(f"**Port:** {f.port}  ")
        if f.url:
            lines.append(f"**URL:** {f.url}  ")
        if f.tags:
            lines.append(f"**Tags:** {', '.join(f.tags)}  ")
        lines += ["", f.description, ""]
        if f.raw:
            lines += ["```", f.raw[:400], "```", ""]

    # Agent thoughts section
    if ctx.agent_thoughts:
        lines += ["## Agent reasoning log", ""]
        for i, thought in enumerate(ctx.agent_thoughts, 1):
            lines.append(f"{i}. {thought}")
        lines.append("")

    if ctx.subdomains:
        lines += ["## Subdomains", "```"]
        lines += ctx.subdomains[:50]
        lines += ["```", ""]

    if ctx.emails:
        lines += ["## Emails", "```"]
        lines += ctx.emails
        lines += ["```", ""]

    with open(md_path, "w") as f:
        f.write("\n".join(lines))

    # ── JSON ──────────────────────────────────────────────────────────────────
    report_data = {
        "target":     ctx.target_host,
        "scanned_at": ctx.started_at.isoformat(),
        "model":      ctx.model,
        "summary": {
            "subdomains": ctx.subdomains,
            "emails":     ctx.emails,
            "ports":      sorted(set(ctx.ports)),
            "services":   [{"port": s.port, "name": s.name, "product": s.product, "version": s.version} for s in ctx.services],
            "tech_stack": ctx.tech_stack,
            "waf":        ctx.waf_detected,
            "directories": ctx.directories,
        },
        "findings": [
            {
                "severity":    f.severity,
                "title":       f.title,
                "description": f.description,
                "source":      f.source,
                "host":        f.host,
                "port":        f.port,
                "url":         f.url,
                "tags":        f.tags,
            }
            for f in sorted_findings
        ],
        "agent_thoughts": ctx.agent_thoughts,
    }

    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)

    return md_path
