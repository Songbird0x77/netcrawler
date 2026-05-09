"""SSH enumeration — version banner + CVE hints."""
from __future__ import annotations
import socket
from typing import Callable
from core.context import ScanContext

# Known vulnerable SSH versions and associated CVEs
SSH_CVE_MAP = {
    "openssh_8.0": ["CVE-2023-38408", "CVE-2021-41617"],
    "openssh_7.": ["CVE-2018-15473", "CVE-2016-10009", "CVE-2016-10010"],
    "openssh_6.": ["CVE-2016-0777", "CVE-2016-0778", "CVE-2014-1692"],
    "openssh_5.": ["CVE-2010-4755", "CVE-2008-4109"],
    "dropbear":   ["CVE-2016-7406", "CVE-2012-0920"],
}


def run_ssh_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output = []

    if 22 not in ctx.ports:
        return "[skipped — port 22 not open]"

    status(f"Grabbing SSH banner from {host}:22...")

    try:
        with socket.create_connection((host, 22), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            output.append(f"Banner: {banner}")

            banner_lower = banner.lower()

            # Check for CVEs
            matched_cves = []
            for version_key, cves in SSH_CVE_MAP.items():
                if version_key in banner_lower:
                    matched_cves.extend(cves)

            if matched_cves:
                output.append(f"\n[!] Potentially vulnerable SSH version detected")
                output.append(f"    Possible CVEs: {', '.join(matched_cves)}")

                ctx.add_finding(
                    severity="high",
                    title=f"Outdated SSH version — possible CVEs",
                    description=(
                        f"SSH banner: {banner}\n"
                        f"Possible CVEs: {', '.join(matched_cves)}\n"
                        "Recommend upgrading OpenSSH to latest stable version."
                    ),
                    source="ssh_enum",
                    host=host,
                    port=22,
                    tags=["ssh", "cve", "outdated"],
                    raw="\n".join(output),
                )
            else:
                output.append("[+] No known CVEs matched for this SSH version")
                ctx.add_finding(
                    severity="info",
                    title="SSH service detected",
                    description=f"SSH running: {banner}",
                    source="ssh_enum",
                    host=host,
                    port=22,
                    tags=["ssh", "info"],
                    raw=banner,
                )

            # Flag weak auth methods (needs paramiko for full check, note for now)
            output.append("\n[*] Recommend checking: ssh-audit " + host)

    except Exception as e:
        output.append(f"SSH banner grab failed: {e}")

    return "\n".join(output)
