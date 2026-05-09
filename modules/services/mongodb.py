"""MongoDB enumeration — unauthenticated access check."""
from __future__ import annotations
import socket
import struct
import subprocess
import shutil
from typing import Callable
from core.context import ScanContext


def run_mongodb_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output = []

    if 27017 not in ctx.ports:
        return "[skipped — port 27017 not open]"

    status(f"Checking MongoDB on {host}:27017...")

    # Nmap MongoDB scripts first
    if shutil.which("nmap"):
        result = subprocess.run(
            ["nmap", "-p", "27017", "--script", "mongodb-info,mongodb-databases", host],
            capture_output=True, text=True, timeout=30
        )
        raw = result.stdout
        output.append(f"=== NMAP MONGODB ===\n{raw}")

        raw_lower = raw.lower()
        if "databases" in raw_lower or "totalsize" in raw_lower:
            ctx.add_finding(
                severity="critical",
                title="MongoDB Unauthenticated Access",
                description=(
                    f"MongoDB on {host}:27017 is accessible without credentials. "
                    "Database listing and data exfiltration is possible."
                ),
                source="mongodb_enum",
                host=host,
                port=27017,
                tags=["mongodb", "no-auth", "critical"],
                raw=raw[:500],
            )
        elif "unauthorized" in raw_lower or "authentication" in raw_lower:
            output.append("[+] MongoDB requires authentication (good)")
            ctx.add_finding(
                severity="info",
                title="MongoDB requires authentication",
                description=f"MongoDB on {host}:27017 is protected.",
                source="mongodb_enum",
                host=host,
                port=27017,
                tags=["mongodb", "info"],
                raw=raw[:200],
            )
    else:
        # Fallback: raw TCP probe
        try:
            with socket.create_connection((host, 27017), timeout=5) as sock:
                output.append("[*] MongoDB port is open")
                output.append("[*] Install nmap for detailed enumeration")
                ctx.add_finding(
                    severity="medium",
                    title="MongoDB port open — manual check needed",
                    description=(
                        f"MongoDB port 27017 is open on {host}. "
                        "Install nmap to enumerate access controls."
                    ),
                    source="mongodb_enum",
                    host=host,
                    port=27017,
                    tags=["mongodb", "open-port"],
                    raw="port open",
                )
        except Exception as e:
            output.append(f"Connection failed: {e}")

    return "\n".join(output)
