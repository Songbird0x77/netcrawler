"""Directory fuzzing — ffuf with WAF-aware settings."""
from __future__ import annotations
import subprocess
import shutil
import json
import os
import tempfile
import time
import random
from typing import Callable
from core.context import ScanContext

DEFAULT_WORDLIST  = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common.txt")
FALLBACK_WORDLIST = os.path.expanduser("~/SecLists/Discovery/Web-Content/raft-large-words.txt")
LAST_RESORT       = "/usr/share/wordlists/dirb/common.txt"


def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, "[timeout]"
    except FileNotFoundError:
        return 1, f"[{cmd[0]} not installed]"


def run_dir_fuzz(ctx: ScanContext, status: Callable[[str], None]) -> str:
    if not ctx.is_web:
        return "[skipped — not a web target]"
    if not shutil.which("ffuf"):
        return "[ffuf not installed — install: go install github.com/ffuf/ffuf/v2@latest]"

    # Pick wordlist
    wordlist = None
    for wl in [DEFAULT_WORDLIST, FALLBACK_WORDLIST, LAST_RESORT]:
        if os.path.exists(wl):
            wordlist = wl
            break
    if not wordlist:
        return "[no wordlist found — run: curl -o wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt]"

    waf_detected = bool(ctx.waf_detected and ctx.waf_detected != "none")
    url = ctx.target_url.rstrip("/") + "/FUZZ"
    status(f"Running ffuf on {url} {'(WAF-aware mode)' if waf_detected else ''}...")

    out_file = tempfile.mktemp(suffix=".json")

    # Base command
    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-o", out_file,
        "-of", "json",
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-fc", "429,503,502",
        "-timeout", "10",
        "-r",   # follow redirects
        "-c",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]

    # WAF-aware settings — slower but less likely to get blocked
    if waf_detected:
        cmd += ["-t", "5", "-rate", "20", "-p", "0.1-0.3"]
    else:
        cmd += ["-t", "20", "-rate", "100"]

    returncode, raw = _run(cmd, timeout=360)

    found = []
    try:
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file) as f:
                content = f.read().strip()
            if content:
                data = json.loads(content)
                results = data.get("results", [])
                for r in results:
                    path   = r.get("input", {}).get("FUZZ", "")
                    status_code = r.get("status", 0)
                    length = r.get("length", 0)
                    words  = r.get("words", 0)
                    if path:
                        found.append(f"/{path} [{status_code}] size={length} words={words}")
                        if path not in ctx.directories:
                            ctx.directories.append(path)
        else:
            # ffuf ran but produced no JSON — parse stdout directly
            for line in raw.splitlines():
                if "[Status:" in line or "| URL |" in line:
                    found.append(line.strip())
    except (json.JSONDecodeError, KeyError):
        # Fall back to raw output parsing
        for line in raw.splitlines():
            if "[Status:" in line:
                found.append(line.strip())
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)

    if found:
        ctx.add_finding(
            severity="info",
            title=f"Directories/files discovered ({len(found)})",
            description=f"ffuf found {len(found)} accessible paths on {ctx.target_host}.",
            source="dir_fuzz",
            host=ctx.target_host,
            url=ctx.target_url,
            tags=["fuzzing", "directories"],
            raw="\n".join(found[:30]),
        )
        return "\n".join(found)

    if waf_detected:
        return f"[no results — WAF ({ctx.waf_detected}) likely blocking ffuf. Try manual fuzzing with Burp Suite or ZAP behind a VPN.]"
    return "[no directories found]"

