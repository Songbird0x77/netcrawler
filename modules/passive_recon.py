"""Passive recon — Subfinder + theHarvester."""
from __future__ import annotations
import subprocess
import shutil
import re
from typing import Callable
from core.context import ScanContext


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def _is_valid_subdomain(line: str, base_host: str) -> bool:
    line = line.strip().lower()
    if not line:
        return False
    if not line.endswith(base_host):
        return False
    if not re.match(r'^[a-z0-9][a-z0-9\.\-]*\.[a-z]{2,}$', line):
        return False
    if any(c in line for c in ' /\\[](){}*@#!'):
        return False
    return True


def _is_valid_email(line: str) -> bool:
    line = line.strip()
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', line):
        return False
    false_positives = [
        "cmartorella@edge-security.com",
        "noreply@",
        "example@",
    ]
    if any(fp in line.lower() for fp in false_positives):
        return False
    return True


def run_passive_recon(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output_parts = []

    if shutil.which("subfinder"):
        status(f"Running Subfinder on {host}...")
        raw = _run(["subfinder", "-d", host, "-silent", "-timeout", "30"], timeout=90)
        output_parts.append(f"=== SUBFINDER ===\n{raw}")
        for line in raw.splitlines():
            line = line.strip().lower()
            if _is_valid_subdomain(line, host) and line not in ctx.subdomains:
                ctx.subdomains.append(line)
    else:
        output_parts.append("=== SUBFINDER ===\n[not installed]")

    if shutil.which("theHarvester"):
        status(f"Running theHarvester on {host}...")
        raw = _run(
            ["theHarvester", "-d", host, "-b", "crtsh,dnsdumpster,threatminer", "-l", "100"],
            timeout=45,
        )
        output_parts.append(f"=== THEHARVESTER ===\n{raw}")
        for line in raw.splitlines():
            line = line.strip()
            if "@" in line and _is_valid_email(line):
                if line not in ctx.emails:
                    ctx.emails.append(line)
            elif _is_valid_subdomain(line.lower(), host):
                if line.lower() not in ctx.subdomains:
                    ctx.subdomains.append(line.lower())
    else:
        output_parts.append("=== THEHARVESTER ===\n[not installed]")

    ctx.subdomains = sorted(set(ctx.subdomains))
    ctx.emails     = sorted(set(ctx.emails))

    if ctx.subdomains:
        ctx.add_finding(
            severity="info",
            title=f"Subdomains discovered ({len(ctx.subdomains)})",
            description=f"Found {len(ctx.subdomains)} subdomains via passive recon.",
            source="passive_recon",
            host=host,
            tags=["recon", "subdomains"],
            raw="\n".join(ctx.subdomains[:20]),
        )

    if ctx.emails:
        ctx.add_finding(
            severity="info",
            title=f"Email addresses discovered ({len(ctx.emails)})",
            description=f"Found {len(ctx.emails)} emails: " + ", ".join(ctx.emails[:5]),
            source="passive_recon",
            host=host,
            tags=["recon", "osint", "email"],
            raw="\n".join(ctx.emails),
        )

    interesting_keywords = [
        "admin", "api", "dev", "staging", "stage", "portal", "app",
        "dashboard", "internal", "vpn", "remote", "test", "uat",
        "jenkins", "jira", "confluence", "gitlab", "git", "ci",
        "mail", "webmail", "ftp", "cpanel", "plesk", "docker",
        "registry", "citrix", "desktop", "identity", "wso2",
    ]
    high_value = [s for s in ctx.subdomains if any(kw in s for kw in interesting_keywords)]

    if high_value:
        ctx.add_finding(
            severity="info",
            title=f"High-value subdomains for investigation ({len(high_value)})",
            description="Subdomains suggesting sensitive services: " + ", ".join(high_value[:10]),
            source="passive_recon",
            host=host,
            tags=["recon", "subdomains", "followup"],
            raw="\n".join(high_value),
        )

    return "\n\n".join(output_parts)
