"""Web fingerprinting — WhatWeb + wafw00f."""
from __future__ import annotations
import subprocess
import shutil
import re
from typing import Callable
from core.context import ScanContext


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def _parse_tech(raw: str, ctx: ScanContext):
    """Extract meaningful tech from WhatWeb output, skip CDN noise."""
    skip = {
        "http", "https", "ok", "redirect", "redirectlocation", "country",
        "200", "301", "302", "303", "304", "404", "ip", "email",
        "httpserver", "via-proxy", "x-powered-by",
    }
    tech_pattern = re.findall(r'([A-Za-z][A-Za-z0-9\-\.\_]+)\[([^\]]*)\]', raw)
    for name, version in tech_pattern:
        if name.lower() in skip:
            continue
        if len(name) < 3:
            continue
        # Skip pure numeric or single-word CDN noise
        if re.match(r'^\d+$', name):
            continue
        tech_str = f"{name}[{version}]" if version and version != name else name
        if tech_str not in ctx.tech_stack:
            ctx.tech_stack.append(tech_str)


def run_web_fingerprint(ctx: ScanContext, status: Callable[[str], None]) -> str:
    if not ctx.is_web:
        return "[skipped — not a web target]"

    url     = ctx.target_url
    host    = ctx.target_host
    output_parts = []

    # Build list of URLs to scan — include www and any interesting subdomains
    urls_to_scan = [url]
    www_url = url.replace("://", "://www.") if "://www." not in url else None
    if www_url:
        urls_to_scan.append(www_url)

    # Add up to 3 interesting subdomains
    interesting_keywords = ["admin", "api", "dev", "staging", "portal", "app", "mail"]
    for sub in ctx.subdomains[:30]:
        for kw in interesting_keywords:
            if kw in sub.lower() and f"https://{sub}" not in urls_to_scan:
                urls_to_scan.append(f"https://{sub}")
                break
    urls_to_scan = urls_to_scan[:6]  # Cap at 6

    # --- WhatWeb ---
    if shutil.which("whatweb"):
        status(f"Running WhatWeb on {len(urls_to_scan)} URL(s)...")
        raw = _run(
            [
                "whatweb", "--color=never", "--log-brief=/dev/stdout",
                "--follow-redirect=always", "-a", "3",
            ] + urls_to_scan,
            timeout=90,
        )
        output_parts.append(f"=== WHATWEB ===\n{raw}")
        _parse_tech(raw, ctx)

        if ctx.tech_stack:
            ctx.add_finding(
                severity="info",
                title="Technology stack identified",
                description=f"Detected: {', '.join(ctx.tech_stack[:15])}",
                source="web_fingerprint",
                host=host,
                url=url,
                tags=["fingerprint", "tech"],
                raw=raw[:600],
            )

        # Flag interesting tech
        dangerous = ["WordPress", "Drupal", "Joomla", "Laravel", "Django",
                     "phpMyAdmin", "Jenkins", "Tomcat", "Struts", "jQuery[1.", "jQuery[2."]
        for tech in ctx.tech_stack:
            for d in dangerous:
                if d.lower() in tech.lower():
                    ctx.add_finding(
                        severity="medium",
                        title=f"Notable technology detected: {tech}",
                        description=f"{tech} detected — check for known CVEs and default configs.",
                        source="web_fingerprint",
                        host=host,
                        url=url,
                        tags=["fingerprint", "tech", "cve-check"],
                        raw=tech,
                    )
    else:
        output_parts.append("=== WHATWEB ===\n[not installed — sudo apt install whatweb]")

    # --- wafw00f ---
    if shutil.which("wafw00f"):
        status(f"Running wafw00f on {url}...")
        raw = _run(["wafw00f", "-a", url], timeout=30)
        output_parts.append(f"=== WAFW00F ===\n{raw}")

        for line in raw.splitlines():
            line_l = line.lower()
            if "is behind" in line_l or "detected" in line_l:
                ctx.waf_detected = line.strip()
                ctx.add_finding(
                    severity="medium",
                    title="WAF detected",
                    description=line.strip(),
                    source="web_fingerprint",
                    host=host,
                    url=url,
                    tags=["waf", "fingerprint"],
                    raw=raw[:300],
                )
                break
            elif "no waf" in line_l or "not detected" in line_l:
                ctx.waf_detected = "none"
                break
    else:
        output_parts.append("=== WAFW00F ===\n[not installed — pip install wafw00f]")

    return "\n\n".join(output_parts)

