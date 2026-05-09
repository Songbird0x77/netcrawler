"""Vulnerability scanning — Nuclei template scan."""
from __future__ import annotations
import subprocess
import shutil
import json
from typing import Callable
from core.context import ScanContext


def _run(cmd: list[str], timeout: int = 300) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not installed]"


def run_vuln_scan(ctx: ScanContext, status: Callable[[str], None]) -> str:
    if not shutil.which("nuclei"):
        return "[nuclei not installed]"

    targets = []
    if ctx.target_url:
        targets.append(ctx.target_url)
    if ctx.is_web and ctx.subdomains:
        for sub in ctx.subdomains[:10]:
            targets.append(f"https://{sub}")

    if not targets:
        targets.append(ctx.target_host)

    status(f"Running Nuclei against {len(targets)} target(s)...")

    # Write targets to temp file
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    try:
        raw = _run([
            "nuclei",
            "-l", tmp,
            "-severity", "critical,high,medium",
            "-jsonl",
            "-silent",
            "-timeout", "10",
            "-c", "3",
	    "-rate-limit", "10",
        ], timeout=300)
    finally:
        os.unlink(tmp)

    # Parse JSONL output
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            severity = item.get("info", {}).get("severity", "info").lower()
            name = item.get("info", {}).get("name", "Unknown")
            description = item.get("info", {}).get("description", "")
            matched_url = item.get("matched-at", "")
            tags = item.get("info", {}).get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            ctx.add_finding(
                severity=severity,
                title=name,
                description=description,
                source="vuln_scan",
                host=ctx.target_host,
                url=matched_url,
                tags=tags,
                raw=line,
            )
        except json.JSONDecodeError:
            continue

    return raw or "[nuclei ran but produced no output — try updating templates: nuclei -update-templates]"
