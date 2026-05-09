"""Port scanning — Nmap service/version + script scan."""
from __future__ import annotations
import subprocess
import shutil
import re
from typing import Callable
from core.context import ScanContext, Service


def _run(cmd: list[str], timeout: int = 300) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout — scan took too long]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def run_port_scan(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host

    if not shutil.which("nmap"):
        return "[nmap not installed]"

    status(f"Running Nmap on {host} (top 1000 ports, -sV -sC)...")

    raw = _run([
        "nmap", "-sV", "-sC",
        "--open",
        "-T4",
        "--top-ports", "1000",
        "-oN", "-",
        host,
    ], timeout=300)

    # Parse open ports + services from nmap output
    port_re = re.compile(
        r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
    )
    for match in port_re.finditer(raw):
        port = int(match.group(1))
        proto = match.group(2)
        svc_name = match.group(3)
        extra = match.group(4).strip()

        if port not in ctx.ports:
            ctx.ports.append(port)

        # Parse product/version from extra
        product, version = "", ""
        version_match = re.search(r"(\S[\w\.\-]+)\s+([\d\.]+)", extra)
        if version_match:
            product = version_match.group(1)
            version = version_match.group(2)

        svc = Service(
            port=port,
            protocol=proto,
            name=svc_name,
            product=product,
            version=version,
            extra=extra,
        )
        # Avoid duplicates
        if not any(s.port == port for s in ctx.services):
            ctx.services.append(svc)

    # Generate findings for interesting services
    interesting = {
        21: ("ftp", "high"),
        22: ("ssh", "info"),
        23: ("telnet", "high"),
        25: ("smtp", "medium"),
        80: ("http", "info"),
        443: ("https", "info"),
        445: ("smb", "high"),
        3306: ("mysql", "high"),
        3389: ("rdp", "high"),
        5432: ("postgres", "high"),
        6379: ("redis", "high"),
        27017: ("mongodb", "high"),
    }

    for svc in ctx.services:
        if svc.port in interesting:
            _, severity = interesting[svc.port]
            ctx.add_finding(
                severity=severity,
                title=f"Open port: {svc.port}/{svc.name}",
                description=(
                    f"Port {svc.port} ({svc.name}) is open. "
                    f"{svc.product} {svc.version}".strip()
                ),
                source="port_scan",
                host=host,
                port=svc.port,
                tags=["port", svc.name],
                raw=raw[:200],
            )

    return raw
