"""Active subdomain scanning — httpx alive check + scoring."""
from __future__ import annotations
import subprocess
import shutil
import re
import tempfile
import os
from typing import Callable
from core.context import ScanContext

INTERESTING_KEYWORDS = [
    "admin", "api", "dev", "staging", "stage", "portal", "app",
    "dashboard", "internal", "vpn", "remote", "test", "uat",
    "jenkins", "jira", "confluence", "gitlab", "git", "ci", "cd",
    "mail", "webmail", "smtp", "ftp", "cpanel", "plesk",
]


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def _get_httpx_list_flag() -> str:
    """Detect correct httpx flag for reading from a file."""
    if not shutil.which("httpx"):
        return None
    # Try to detect version/flags
    help_output = _run(["httpx", "--help"], timeout=5)
    if "-l " in help_output or "-list" in help_output:
        return "-l"
    if "-i " in help_output or "--input" in help_output:
        return "-i"
    # Try -list (projectdiscovery httpx)
    return "-l"


def run_subdomain_scan(ctx: ScanContext, status: Callable[[str], None]) -> str:
    if not ctx.subdomains:
        return "[skipped — no subdomains to scan]"

    output = []
    alive  = []

    # --- httpx alive check ---
    if shutil.which("httpx"):
        status(f"Checking {len(ctx.subdomains)} subdomains with httpx...")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(ctx.subdomains))
            tmp = f.name

        try:
            list_flag = _get_httpx_list_flag()

            # Try projectdiscovery httpx first (most common)
            raw = _run([
                "httpx",
                list_flag, tmp,
                "-silent",
                "-status-code",
                "-title",
                "-follow-redirects",
                "-timeout", "5",
                "-threads", "20",
            ], timeout=120)

            # If that failed try without some flags
            if "Error:" in raw or "unknown flag" in raw.lower():
                raw = _run([
                    "httpx",
                    list_flag, tmp,
                    "-silent",
                    "-timeout", "5",
                ], timeout=120)

            output.append(f"=== HTTPX ALIVE CHECK ===\n{raw}")

            for line in raw.splitlines():
                line = line.strip()
                if line and ("http://" in line or "https://" in line):
                    alive.append(line)
                    url_match = re.match(r'(https?://[^\s\[]+)', line)
                    if url_match:
                        ctx.alive_hosts.append(url_match.group(1).rstrip("/"))

        except Exception as e:
            output.append(f"httpx error: {e}")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    else:
        # Fallback: basic curl check
        status("httpx not found — checking subdomains with curl...")
        output.append("=== CURL ALIVE CHECK ===")
        for sub in ctx.subdomains[:10]:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub}"
                result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", "3", "-L", url],
                    capture_output=True, text=True, timeout=8
                )
                code = result.stdout.strip()
                if code and code not in ("000", ""):
                    alive.append(f"{url} [{code}]")
                    output.append(f"  ALIVE: {url} [{code}]")
                    ctx.alive_hosts.append(url)
                    break

    # --- Score high-value subdomains ---
    high_value = []
    for sub in ctx.subdomains:
        if any(kw in sub.lower() for kw in INTERESTING_KEYWORDS):
            high_value.append(sub)

    if high_value:
        output.append(f"\n=== HIGH-VALUE SUBDOMAINS ===")
        for sub in high_value:
            matched = [kw for kw in INTERESTING_KEYWORDS if kw in sub.lower()]
            output.append(f"  {sub} (keywords: {', '.join(matched)})")

        ctx.add_finding(
            severity="high",
            title=f"High-value subdomains identified ({len(high_value)})",
            description=(
                "Subdomains suggesting sensitive services: "
                + ", ".join(high_value[:10])
            ),
            source="subdomain_scan",
            host=ctx.target_host,
            tags=["subdomains", "attack-surface", "high-value"],
            raw="\n".join(high_value),
        )

    # --- Alive summary ---
    if alive:
        ctx.add_finding(
            severity="info",
            title=f"Alive subdomains confirmed ({len(alive)})",
            description=f"{len(alive)} subdomains responding to HTTP/HTTPS.",
            source="subdomain_scan",
            host=ctx.target_host,
            tags=["subdomains", "alive"],
            raw="\n".join(alive[:20]),
        )
        output.append(f"\n=== ALIVE SUMMARY: {len(alive)} alive ===")
        for a in alive[:20]:
            output.append(f"  {a}")
    else:
        output.append("\n[no alive subdomains confirmed]")

    return "\n".join(output)
