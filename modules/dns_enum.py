"""DNS enumeration — zone transfer, SPF/DMARC/DKIM, DNS records."""
from __future__ import annotations
import subprocess
import shutil
import re
from typing import Callable
from core.context import ScanContext


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def run_dns_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host   = ctx.target_host
    output = []

    if not shutil.which("dig") and not shutil.which("nslookup"):
        return "[dig/nslookup not installed — sudo apt install dnsutils]"

    # --- Basic DNS records ---
    status(f"Enumerating DNS records for {host}...")
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        raw = _run(["dig", "+short", record_type, host], timeout=10)
        if raw and "[" not in raw:
            output.append(f"{record_type}: {raw}")

    # --- Zone transfer attempt ---
    status("Attempting DNS zone transfer...")
    ns_raw = _run(["dig", "+short", "NS", host], timeout=10)
    nameservers = [ns.strip().rstrip(".") for ns in ns_raw.splitlines() if ns.strip()]

    for ns in nameservers[:3]:
        zt = _run(["dig", f"@{ns}", "AXFR", host], timeout=15)
        if zt and "Transfer failed" not in zt and "connection refused" not in zt.lower():
            if len(zt.splitlines()) > 5:
                output.append(f"\n[!!!] ZONE TRANSFER SUCCESSFUL from {ns}:\n{zt[:1000]}")
                ctx.add_finding(
                    severity="critical",
                    title=f"DNS Zone Transfer Allowed ({ns})",
                    description=(
                        f"Nameserver {ns} allowed a full zone transfer for {host}. "
                        "This exposes all DNS records to attackers."
                    ),
                    source="dns_enum",
                    host=host,
                    tags=["dns", "zone-transfer", "critical"],
                    raw=zt[:500],
                )

    # --- SPF check ---
    status("Checking SPF/DMARC/DKIM...")
    txt_raw = _run(["dig", "+short", "TXT", host], timeout=10)
    output.append(f"\nTXT records:\n{txt_raw}")

    if "v=spf1" not in txt_raw.lower():
        ctx.add_finding(
            severity="medium",
            title="No SPF record found",
            description=f"{host} has no SPF record — email spoofing may be possible.",
            source="dns_enum",
            host=host,
            tags=["dns", "spf", "email-spoofing"],
            raw=txt_raw[:200],
        )
    else:
        # Check for +all (allow all) which is a misconfiguration
        if "+all" in txt_raw:
            ctx.add_finding(
                severity="high",
                title="SPF record uses +all (allows all senders)",
                description=f"SPF record for {host} uses '+all' which allows anyone to send email as this domain.",
                source="dns_enum",
                host=host,
                tags=["dns", "spf", "misconfiguration"],
                raw=txt_raw[:200],
            )

    # --- DMARC check ---
    dmarc_raw = _run(["dig", "+short", "TXT", f"_dmarc.{host}"], timeout=10)
    if not dmarc_raw or "v=DMARC1" not in dmarc_raw.upper():
        ctx.add_finding(
            severity="medium",
            title="No DMARC record found",
            description=f"No DMARC record for {host} — email spoofing protection is missing.",
            source="dns_enum",
            host=host,
            tags=["dns", "dmarc", "email-spoofing"],
            raw=dmarc_raw[:200] if dmarc_raw else "no record",
        )
    else:
        output.append(f"\nDMARC: {dmarc_raw}")
        # Check for p=none (monitoring only, no enforcement)
        if "p=none" in dmarc_raw.lower():
            ctx.add_finding(
                severity="low",
                title="DMARC policy is p=none (not enforced)",
                description=f"DMARC record exists but policy is 'none' — emails are not rejected/quarantined.",
                source="dns_enum",
                host=host,
                tags=["dns", "dmarc", "weak-policy"],
                raw=dmarc_raw[:200],
            )

    # --- Subdomain takeover hints ---
    status("Checking for potential subdomain takeover...")
    takeover_signatures = [
        ("github", "There isn't a GitHub Pages site here"),
        ("heroku", "No such app"),
        ("amazonaws", "NoSuchBucket"),
        ("azure", "404 Web Site not found"),
        ("shopify", "Sorry, this shop is currently unavailable"),
        ("fastly", "Fastly error: unknown domain"),
    ]
    for sub in ctx.subdomains[:20]:
        cname = _run(["dig", "+short", "CNAME", sub], timeout=5)
        if cname:
            for provider, _ in takeover_signatures:
                if provider in cname.lower():
                    ctx.add_finding(
                        severity="high",
                        title=f"Potential subdomain takeover: {sub}",
                        description=(
                            f"{sub} has a CNAME pointing to {cname.strip()} ({provider}). "
                            "If the resource no longer exists, this subdomain may be claimable."
                        ),
                        source="dns_enum",
                        host=sub,
                        tags=["dns", "subdomain-takeover", provider],
                        raw=f"CNAME: {cname}",
                    )

    return "\n".join(output)
