"""HTML report generator."""
from __future__ import annotations
from datetime import datetime
from core.context import ScanContext

SEVERITY_COLOR = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#44aaff",
    "info":     "#888888",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_html_report(ctx: ScanContext, output_path: str):
    sorted_findings = sorted(
        ctx.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )

    counts = {s: sum(1 for f in sorted_findings if f.severity == s)
              for s in ["critical", "high", "medium", "low", "info"]}

    findings_html = ""
    for i, f in enumerate(sorted_findings, 1):
        color = SEVERITY_COLOR.get(f.severity, "#888")
        tags_html = " ".join(f'<span class="tag">{t}</span>' for t in f.tags)
        raw_html = f'<pre class="raw">{f.raw[:400]}</pre>' if f.raw else ""
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{f.severity.upper()}</span>
                <span class="finding-title">{i}. {f.title}</span>
            </div>
            <div class="finding-meta">
                <span>Source: {f.source}</span>
                {"<span>Host: " + f.host + "</span>" if f.host else ""}
                {"<span>Port: " + str(f.port) + "</span>" if f.port else ""}
                {"<span>URL: <a href='" + f.url + "' target='_blank'>" + f.url[:60] + "</a></span>" if f.url else ""}
            </div>
            <p class="finding-desc">{f.description}</p>
            {tags_html}
            {raw_html}
        </div>"""

    thoughts_html = "".join(
        f'<div class="thought"><span class="thought-num">{i}</span>{t}</div>'
        for i, t in enumerate(ctx.agent_thoughts, 1)
    )

    subdomains_html = "".join(f"<li>{s}</li>" for s in ctx.subdomains[:50])
    services_html = "".join(
        f"<tr><td>{s.port}</td><td>{s.protocol}</td><td>{s.name}</td>"
        f"<td>{s.product}</td><td>{s.version}</td></tr>"
        for s in ctx.services
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetCrawler Report — {ctx.target_host}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #161b22, #0d1117); border-bottom: 1px solid #30363d; padding: 2rem; }}
  .header h1 {{ font-size: 2rem; color: #58a6ff; font-family: monospace; }}
  .header .meta {{ color: #8b949e; margin-top: 0.5rem; font-size: 0.9rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin: 2rem 0; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: bold; font-family: monospace; }}
  .stat-card .label {{ color: #8b949e; font-size: 0.8rem; margin-top: 0.3rem; }}
  .section {{ margin: 2rem 0; }}
  .section h2 {{ color: #58a6ff; font-size: 1.2rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; margin-bottom: 1rem; }}
  .finding {{ background: #161b22; border-radius: 8px; padding: 1.2rem; margin: 1rem 0; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.8rem; }}
  .severity-badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #000; }}
  .finding-title {{ font-weight: 600; font-size: 1rem; }}
  .finding-meta {{ display: flex; gap: 1rem; color: #8b949e; font-size: 0.85rem; margin-bottom: 0.6rem; flex-wrap: wrap; }}
  .finding-meta a {{ color: #58a6ff; }}
  .finding-desc {{ color: #c9d1d9; margin: 0.5rem 0; }}
  .tag {{ background: #21262d; color: #8b949e; padding: 0.1rem 0.5rem; border-radius: 12px; font-size: 0.75rem; margin-right: 0.3rem; }}
  .raw {{ background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 0.8rem; font-size: 0.8rem; color: #8b949e; margin-top: 0.8rem; overflow-x: auto; white-space: pre-wrap; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; color: #8b949e; padding: 0.8rem; text-align: left; font-size: 0.85rem; }}
  td {{ padding: 0.7rem 0.8rem; border-top: 1px solid #30363d; font-size: 0.9rem; font-family: monospace; }}
  .thought {{ background: #161b22; border-left: 3px solid #58a6ff; padding: 0.6rem 1rem; margin: 0.4rem 0; border-radius: 0 4px 4px 0; font-size: 0.9rem; }}
  .thought-num {{ color: #58a6ff; font-weight: bold; margin-right: 0.8rem; }}
  ul {{ list-style: none; columns: 2; gap: 1rem; }}
  ul li {{ font-family: monospace; font-size: 0.85rem; color: #8b949e; padding: 0.2rem 0; }}
  ul li::before {{ content: "→ "; color: #58a6ff; }}
  .banner {{ font-family: monospace; font-size: 0.65rem; color: #21262d; white-space: pre; line-height: 1.2; }}
</style>
</head>
<body>
<div class="header">
  <pre class="banner"> ███╗   ██╗███████╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝╚══════╝╚══════╝╚═╝  ╚═╝</pre>
  <h1>Scan Report — {ctx.target_host}</h1>
  <div class="meta">
    Scanned: {ctx.started_at:%Y-%m-%d %H:%M:%S} &nbsp;|&nbsp;
    Completed: {datetime.now():%Y-%m-%d %H:%M:%S} &nbsp;|&nbsp;
    Model: {ctx.model} &nbsp;|&nbsp;
    Stages: {', '.join(ctx.completed_stages) or 'none'}
  </div>
</div>

<div class="container">
  <div class="stats-grid">
    <div class="stat-card"><div class="num" style="color:#ff4444">{counts['critical']}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="num" style="color:#ff8800">{counts['high']}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="num" style="color:#ffcc00">{counts['medium']}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="num" style="color:#44aaff">{counts['low']}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="num" style="color:#58a6ff">{len(ctx.subdomains)}</div><div class="label">Subdomains</div></div>
    <div class="stat-card"><div class="num" style="color:#58a6ff">{len(set(ctx.ports))}</div><div class="label">Open Ports</div></div>
    <div class="stat-card"><div class="num" style="color:#58a6ff">{len(ctx.directories)}</div><div class="label">Directories</div></div>
  </div>

  <div class="section">
    <h2>Findings ({len(sorted_findings)})</h2>
    {findings_html if findings_html else '<p style="color:#8b949e">No findings recorded.</p>'}
  </div>

  {"<div class='section'><h2>Services Detected</h2><table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>" + services_html + "</tbody></table></div>" if ctx.services else ""}

  {"<div class='section'><h2>Subdomains (" + str(len(ctx.subdomains)) + ")</h2><ul>" + subdomains_html + "</ul></div>" if ctx.subdomains else ""}

  {"<div class='section'><h2>Tech Stack</h2><p style='font-family:monospace;color:#8b949e'>" + ", ".join(ctx.tech_stack) + "</p></div>" if ctx.tech_stack else ""}

  {"<div class='section'><h2>WAF</h2><p style='font-family:monospace;color:#8b949e'>" + ctx.waf_detected + "</p></div>" if ctx.waf_detected else ""}

  {"<div class='section'><h2>Agent Reasoning Log</h2>" + thoughts_html + "</div>" if ctx.agent_thoughts else ""}
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)