"""SMB enumeration — null sessions, shares, OS info via smbclient/nmap."""
from __future__ import annotations
import subprocess
import shutil
from typing import Callable
from core.context import ScanContext


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def run_smb_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output = []

    smb_ports = [p for p in ctx.ports if p in (139, 445)]
    if not smb_ports:
        return "[skipped — SMB ports 139/445 not open]"

    status(f"Enumerating SMB on {host}...")

    # Nmap SMB scripts
    if shutil.which("nmap"):
        status("Running Nmap SMB scripts...")
        raw = _run([
            "nmap", "-p", "445,139",
            "--script", "smb-security-mode,smb-os-discovery,smb-enum-shares,smb2-security-mode",
            "-T4", host,
        ], timeout=60)
        output.append(f"=== NMAP SMB SCRIPTS ===\n{raw}")

        # Check for critical issues
        raw_lower = raw.lower()
        if "message signing disabled" in raw_lower or "signing: disabled" in raw_lower:
            ctx.add_finding(
                severity="high",
                title="SMB Signing Disabled",
                description=(
                    f"SMB signing is disabled on {host}. "
                    "This allows NTLM relay attacks (e.g. Responder + ntlmrelayx)."
                ),
                source="smb_enum",
                host=host,
                port=445,
                tags=["smb", "signing", "relay", "ntlm"],
                raw=raw[:500],
            )

        if "smb1" in raw_lower or "smbv1" in raw_lower:
            ctx.add_finding(
                severity="critical",
                title="SMBv1 Enabled (EternalBlue risk)",
                description=(
                    f"SMBv1 detected on {host}. "
                    "Vulnerable to MS17-010 (EternalBlue/WannaCry). "
                    "Disable SMBv1 immediately."
                ),
                source="smb_enum",
                host=host,
                port=445,
                tags=["smb", "eternalblue", "ms17-010", "critical"],
                raw=raw[:500],
            )

    # smbclient null session
    if shutil.which("smbclient"):
        status("Attempting SMB null session...")
        raw = _run([
            "smbclient", "-L", f"//{host}/",
            "-N", "--option=client min protocol=NT1",
        ], timeout=15)
        output.append(f"\n=== SMBCLIENT NULL SESSION ===\n{raw}")

        if "sharename" in raw.lower() or "disk" in raw.lower():
            ctx.add_finding(
                severity="high",
                title="SMB Null Session Allowed",
                description=(
                    f"SMB null session (no credentials) succeeded on {host}. "
                    "Share listing is possible without authentication."
                ),
                source="smb_enum",
                host=host,
                port=445,
                tags=["smb", "null-session", "misconfiguration"],
                raw=raw[:500],
            )
    else:
        output.append("\n[smbclient not installed — install with: sudo apt install samba-client]")

    return "\n".join(output)