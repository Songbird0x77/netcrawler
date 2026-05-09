"""FTP service enumeration — anonymous login + banner grab."""
from __future__ import annotations
import ftplib
import socket
from typing import Callable
from core.context import ScanContext


def run_ftp_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output = []

    if 21 not in ctx.ports:
        return "[skipped — port 21 not open]"

    status(f"Checking FTP anonymous login on {host}:21...")

    # Banner grab
    try:
        with socket.create_connection((host, 21), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            output.append(f"Banner: {banner}")
    except Exception as e:
        output.append(f"Banner grab failed: {e}")

    # Anonymous login attempt
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=5)
        ftp.login("anonymous", "anonymous@anonymous.com")

        output.append("[!] ANONYMOUS LOGIN SUCCESSFUL")

        # List root directory
        try:
            files = []
            ftp.retrlines("LIST", files.append)
            output.append("Root directory listing:")
            for f in files[:20]:
                output.append(f"  {f}")
        except Exception:
            output.append("Directory listing failed (permissions)")

        ftp.quit()

        ctx.add_finding(
            severity="high",
            title="FTP Anonymous Login Enabled",
            description=(
                f"FTP on {host}:21 allows anonymous login. "
                "Attackers can read/write files without credentials."
            ),
            source="ftp_enum",
            host=host,
            port=21,
            tags=["ftp", "anonymous", "misconfiguration"],
            raw="\n".join(output),
        )

    except ftplib.error_perm:
        output.append("[+] Anonymous login denied (good)")
    except Exception as e:
        output.append(f"FTP connection failed: {e}")

    return "\n".join(output)
