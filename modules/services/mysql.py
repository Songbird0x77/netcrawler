"""MySQL enumeration — default/weak credential check."""
from __future__ import annotations
import socket
import subprocess
import shutil
from typing import Callable
from core.context import ScanContext

# Common default MySQL credentials to try
DEFAULT_CREDS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "mysql"),
    ("admin", "admin"),
    ("mysql", "mysql"),
    ("root", "123456"),
]


def _try_mysql(host: str, user: str, password: str, timeout: int = 5) -> bool:
    """Try MySQL login using the mysql CLI client."""
    if not shutil.which("mysql"):
        return False
    try:
        cmd = ["mysql", "-h", host, "-u", user, "--connect-timeout", str(timeout)]
        if password:
            cmd += [f"--password={password}"]
        else:
            cmd += ["--password="]
        cmd += ["-e", "SELECT 1;"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return "1" in result.stdout and result.returncode == 0
    except Exception:
        return False


def run_mysql_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output = []

    if 3306 not in ctx.ports:
        return "[skipped — port 3306 not open]"

    status(f"Checking MySQL on {host}:3306...")

    # Port reachability check first
    try:
        with socket.create_connection((host, 3306), timeout=5) as sock:
            banner = sock.recv(1024)
            output.append(f"MySQL port open, received {len(banner)} bytes handshake")
    except Exception as e:
        return f"MySQL port not reachable: {e}"

    # Nmap MySQL scripts
    if shutil.which("nmap"):
        status("Running Nmap MySQL scripts...")
        import subprocess as sp
        raw = sp.run(
            ["nmap", "-p", "3306", "--script", "mysql-info,mysql-empty-password,mysql-databases", host],
            capture_output=True, text=True, timeout=30
        ).stdout
        output.append(f"\n=== NMAP MYSQL ===\n{raw}")

        if "empty password" in raw.lower() or "anonymous" in raw.lower():
            ctx.add_finding(
                severity="critical",
                title="MySQL Empty Password (root)",
                description=f"MySQL root account has no password on {host}:3306.",
                source="mysql_enum",
                host=host,
                port=3306,
                tags=["mysql", "default-creds", "critical"],
                raw=raw[:400],
            )

    # Try default creds with mysql client
    if shutil.which("mysql"):
        status("Trying MySQL default credentials...")
        for user, password in DEFAULT_CREDS:
            display_pass = password if password else "(empty)"
            status(f"  Trying {user}:{display_pass}...")
            if _try_mysql(host, user, password):
                output.append(f"[!!!] VALID CREDENTIALS: {user}:{display_pass}")
                ctx.add_finding(
                    severity="critical",
                    title=f"MySQL Default Credentials Valid: {user}:{display_pass}",
                    description=(
                        f"MySQL on {host}:3306 accepted default credentials "
                        f"{user}:{display_pass}. Full database access possible."
                    ),
                    source="mysql_enum",
                    host=host,
                    port=3306,
                    tags=["mysql", "default-creds", "auth-bypass"],
                    raw=f"user={user} password={display_pass}",
                )
                break
            else:
                output.append(f"  [-] {user}:{display_pass} — failed")
    else:
        output.append("\n[mysql client not installed — install: sudo apt install mysql-client]")

    return "\n".join(output)
