"""Active subdomain scanning — httpx alive check + port scan on interesting ones."""
from __future__ import annotations
import subprocess
import shutil
import re
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


def run_subdomain_scan(ctx: ScanContext, status: Callable[[str], None]) -> str:
    if not ctx.subdomains:
        return "[skipped — no subdomains to scan]"

    output = []
    alive  = []

    # --- httpx alive check ---
    if shutil.which("httpx"):
        status(f"Checking {len(ctx.subdomains)} subdomains with httpx...")
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(ctx.subdomains))
            tmp = f.name
        try:
            raw = _run([
                "httpx", "-l", tmp,
                "-silent", "-status-code", "-title",
                "-tech-detect", "-follow-redirects",
                "-timeout", "5", "-threads", "20",
            ], timeout=120)
            output.append(f"=== HTTPX ALIVE CHECK ===\n{raw}")

            for line in raw.splitlines():
                line = line.strip()
                if line and "http" in line:
                    alive.append(line)
                    # Extract URL
                    url_match = re.match(r'(https?://\S+)', line)
                    if url_match:
                        u = url_match.group(1).rstrip("]"),
                        ctx.alive_hosts.append(u[0])
        finally:
            os.unlink(tmp)
    else:
        # Fallback: basic curl check on top subdomains
        status("httpx not found — checking top 10 subdomains with curl...")
        output.append("=== CURL ALIVE CHECK (httpx not installed) ===")
        for sub in ctx.subdomains[:10]:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub}"
                result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", "3", "-L", url],
                    capture_output=True, text=True, timeout=5
                )
                code = result.stdout.strip()
                if code and code not in ("000", ""):
                    alive.append(f"{url} [{code}]")
                    output.append(f"  ALIVE: {url} [{code}]")
                    ctx.alive_hosts.append(url)
                    break

    # --- Score and flag interesting subdomains ---
    high_value = []
    for sub in ctx.subdomains:
        score = sum(1 for kw in INTERESTING_KEYWORDS if kw in sub.lower())
        if score > 0:
            high_value.append((score, sub))

    high_value.sort(reverse=True)
    top = [s for _, s in high_value[:15]]

    if top:
        output.append(f"\n=== HIGH-VALUE SUBDOMAINS ===")
        for sub in top:
            matched = [kw for kw in INTERESTING_KEYWORDS if kw in sub.lower()]
            output.append(f"  {sub} (keywords: {', '.join(matched)})")

        ctx.add_finding(
            severity="high",
            title=f"High-value subdomains identified ({len(top)})",
            description=(
                f"These subdomains contain keywords suggesting sensitive services "
                f"(admin panels, dev environments, APIs, CI/CD): "
                + ", ".join(top[:10])
            ),
            source="subdomain_scan",
            host=ctx.target_host,
            tags=["subdomains", "attack-surface", "high-value"],
            raw="\n".join(top),
        )

    # --- Alive summary ---
    if alive:
        ctx.add_finding(
            severity="info",
            title=f"Alive subdomains confirmed ({len(alive)})",
            description=f"{len(alive)} subdomains responding to HTTP/HTTPS requests.",
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
