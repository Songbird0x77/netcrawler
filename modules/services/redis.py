"""Redis enumeration — unauthenticated access check."""
from __future__ import annotations
import socket
from typing import Callable
from core.context import ScanContext


def _redis_cmd(sock: socket.socket, cmd: str) -> str:
    sock.sendall(f"{cmd}\r\n".encode())
    return sock.recv(4096).decode(errors="ignore").strip()


def run_redis_enum(ctx: ScanContext, status: Callable[[str], None]) -> str:
    host = ctx.target_host
    output = []

    if 6379 not in ctx.ports:
        return "[skipped — port 6379 not open]"

    status(f"Checking Redis on {host}:6379...")

    try:
        with socket.create_connection((host, 6379), timeout=5) as sock:
            sock.settimeout(5)

            # Try PING without auth
            ping_resp = _redis_cmd(sock, "PING")
            output.append(f"PING response: {ping_resp}")

            if "+PONG" in ping_resp:
                output.append("[!!!] REDIS ACCESSIBLE WITHOUT AUTHENTICATION")

                # Get server info
                info = _redis_cmd(sock, "INFO server")
                output.append(f"\nINFO server:\n{info[:500]}")

                # Try to get config
                config = _redis_cmd(sock, "CONFIG GET dir")
                output.append(f"\nCONFIG GET dir: {config}")

                ctx.add_finding(
                    severity="critical",
                    title="Redis Unauthenticated Access",
                    description=(
                        f"Redis on {host}:6379 is accessible without authentication. "
                        "Attackers can read/write all data, and potentially achieve "
                        "RCE via config set to write SSH keys or cron jobs."
                    ),
                    source="redis_enum",
                    host=host,
                    port=6379,
                    tags=["redis", "no-auth", "rce-potential", "critical"],
                    raw="\n".join(output[:10]),
                )

            elif "NOAUTH" in ping_resp or "WRONGPASS" in ping_resp:
                output.append("[+] Redis requires authentication (good)")
                ctx.add_finding(
                    severity="info",
                    title="Redis requires authentication",
                    description=f"Redis on {host}:6379 is password protected.",
                    source="redis_enum",
                    host=host,
                    port=6379,
                    tags=["redis", "info"],
                    raw=ping_resp,
                )
            else:
                output.append(f"Unexpected response: {ping_resp}")

    except Exception as e:
        output.append(f"Redis connection failed: {e}")

    return "\n".join(output)
