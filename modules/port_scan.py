"""Port scanning — RustScan (fast discovery) + Nmap (service detection)."""
from __future__ import annotations
import subprocess
import shutil
import re
from typing import Callable
from core.context import ScanContext, Service


def _run(cmd: list[str], timeout: int = 300) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def _parse_nmap(raw: str, ctx: ScanContext, host: str):
    port_re = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)")
    for match in port_re.finditer(raw):
        port     = int(match.group(1))
        proto    = match.group(2)
        svc_name = match.group(3)
        extra    = match.group(4).strip()

        if port not in ctx.ports:
            ctx.ports.append(port)

        product, version = "", ""
        vm = re.search(r"(\S[\w\.\-]+)\s+([\d\.]+)", extra)
        if vm:
            product = vm.group(1)
            version = vm.group(2)

        if not any(s.port == port for s in ctx.services):
            ctx.services.append(Service(
                port=port, protocol=proto, name=svc_name,
                product=product, version=version, extra=extra,
            ))

    interesting = {
        21:    ("ftp",       "high"),
        22:    ("ssh",       "info"),
        23:    ("telnet",    "high"),
        25:    ("smtp",      "medium"),
        80:    ("http",      "info"),
        443:   ("https",     "info"),
        445:   ("smb",       "high"),
        3306:  ("mysql",     "high"),
        3389:  ("rdp",       "high"),
        5432:  ("postgres",  "high"),
        6379:  ("redis",     "high"),
        8080:  ("http-alt",  "info"),
        8443:  ("https-alt", "info"),
        27017: ("mongodb",   "high"),
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
                raw=raw[:300],
            )


def run_port_scan(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host   = ctx.target_host
    output = []

    if shutil.which("rustscan"):
        # Phase 1 — RustScan fast discovery
        status(f"Running RustScan on {host} (fast port discovery)...")
        rs_raw = _run([
            "rustscan",
            "-a", host,
            "--range", "1-1000",
            "--timeout", "2000",
            "--tries", "1",
            "-g",
        ], timeout=60)

        output.append(f"=== RUSTSCAN ===\n{rs_raw}")

        # Parse greppable output: "host -> [80, 443]"
        open_ports = []
        if "->" in rs_raw:
            ports_section = rs_raw.split("->")[-1]
            open_ports = re.findall(r'\b(\d+)\b', ports_section)
        elif re.search(r'\b\d+\b', rs_raw):
            open_ports = [p for p in re.findall(r'\b(\d+)\b', rs_raw)
                         if 1 <= int(p) <= 65535]

        if open_ports:
            port_list = ",".join(open_ports)
            status(f"RustScan found {len(open_ports)} open port(s) — running Nmap service detection on {port_list}...")

            # Populate ports from RustScan immediately — don't wait for Nmap
            for p in open_ports:
                port_int = int(p)
                if port_int not in ctx.ports:
                    ctx.ports.append(port_int)
                # Add basic service entry so ssl_audit and other modules fire
                if not any(s.port == port_int for s in ctx.services):
                    svc_name = "http" if port_int in (80, 8080) else \
                               "https" if port_int in (443, 8443) else "unknown"
                    ctx.services.append(Service(
                        port=port_int, protocol="tcp",
                        name=svc_name, product="", version="", extra="",
                    ))
                    ctx.add_finding(
                        severity="info",
                        title=f"Open port: {port_int}/{svc_name}",
                        description=f"Port {port_int} is open (discovered by RustScan).",
                        source="port_scan",
                        host=host,
                        port=port_int,
                        tags=["port", svc_name],
                        raw=rs_raw[:200],
                    )

            # Phase 2 — Nmap service detection on open ports only
            nmap_raw = _run([
                "nmap", "-sV", "-sC", "--open", "-T4",
                "-p", port_list,
                "-oN", "-",
                host,
            ], timeout=90)

            output.append(f"=== NMAP SERVICE DETECTION ===\n{nmap_raw}")

            if "[timeout]" not in nmap_raw:
                _parse_nmap(nmap_raw, ctx, host)

            status(f"Port scan complete — {len(ctx.ports)} port(s) identified")
        else:
            status("RustScan found no open ports — falling back to Nmap...")
            _run_nmap(ctx, host, status, output)

    elif shutil.which("nmap"):
        _run_nmap(ctx, host, status, output)
    else:
        output.append("[neither rustscan nor nmap installed]")

    return "\n\n".join(output)


def _run_nmap(ctx: ScanContext, host: str, status: Callable, output: list):
    if not shutil.which("nmap"):
        output.append("[nmap not installed]")
        return

    status(f"Nmap phase 1: fast port discovery on {host}...")
    discovery_raw = _run([
        "nmap", "-T4", "--open",
        "-p", "1-1000",
        "--min-rate", "1000",
        "-oN", "-",
        host,
    ], timeout=90)

    open_ports = re.findall(r"(\d+)/tcp\s+open", discovery_raw)

    if open_ports:
        port_list = ",".join(open_ports)

        # Populate ports immediately
        for p in open_ports:
            if int(p) not in ctx.ports:
                ctx.ports.append(int(p))

        status(f"Found {len(open_ports)} open port(s) — running service detection on {port_list}...")

        service_raw = _run([
            "nmap", "-sV", "-sC", "--open", "-T4",
            "-p", port_list,
            "-oN", "-",
            host,
        ], timeout=90)

        output.append(f"=== NMAP (2-phase) ===\n{service_raw}")
        if "[timeout]" not in service_raw:
            _parse_nmap(service_raw, ctx, host)
        status(f"Nmap complete — {len(ctx.ports)} port(s) identified")
    else:
        status("No open ports found in top 1000")
        output.append(f"=== NMAP ===\n{discovery_raw}")
