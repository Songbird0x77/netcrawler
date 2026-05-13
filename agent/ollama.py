"""Ollama interface for agent reasoning."""
from __future__ import annotations
import json
import os
import re
import subprocess
import urllib.request
import urllib.error
from dataclasses import dataclass

SYSTEM_PROMPT = """You are NetCrawler, an expert penetration testing AI agent.
Your job is to reason about a target, decide which tool to run next, interpret tool outputs accurately, and surface findings.

AVAILABLE TOOLS:
  passive_recon     — Subfinder + theHarvester (subdomains, emails — always run first)
  subdomain_scan    — httpx alive check + score high-value subdomains (run after passive_recon)
  dns_enum          — Zone transfer, SPF/DMARC/DKIM, subdomain takeover (run early)
  port_scan         — Nmap service/version scan (always run before service tools)
  web_fingerprint   — WhatWeb + wafw00f (web targets only — run after port_scan)
  web_crawler       — robots.txt, sitemap.xml, .env/.git probing (web targets only)
  ssl_audit         — TLS/SSL cipher audit, Heartbleed, POODLE (if port 443/8443 open)
  dir_fuzz          — ffuf directory fuzzing (web targets only — run after fingerprint)
  vuln_scan         — Nuclei template scan (ALWAYS run on web targets — WAF does not prevent this)
  ftp_enum          — FTP anonymous login (only if port 21 open)
  ssh_enum          — SSH banner + CVE check (only if port 22 open)
  smb_enum          — SMB null session, signing, EternalBlue (only if port 139/445 open)
  mysql_enum        — MySQL default credentials (only if port 3306 open)
  redis_enum        — Redis unauthenticated access (only if port 6379 open)
  mongodb_enum      — MongoDB open access (only if port 27017 open)
  done              — Finish and generate report

DECISION RULES — follow strictly:
1. Always run passive_recon first.
2. Always run dns_enum and subdomain_scan after passive_recon.
3. Always run port_scan before any service-specific tools.
4. After port_scan, map open ports to tools:
   - 21  → ftp_enum
   - 22  → ssh_enum
   - 139/445 → smb_enum
   - 80/443/8080/8443 → web_fingerprint → web_crawler → ssl_audit → dir_fuzz → vuln_scan
   - 3306 → mysql_enum
   - 6379 → redis_enum
   - 27017 → mongodb_enum
5. Never run a service tool if its port is not open.
6. Never repeat a completed tool.
7. ALWAYS run vuln_scan on web targets — even if a WAF is detected. Nuclei uses specific templates that often bypass WAFs.
8. Call done only after vuln_scan has completed on web targets.

RATE LIMITING AND SAFETY RULES — mandatory:
- Never suggest running tools in parallel — always sequential.
- All tools already have built-in rate limiting.
- This tool is for authorised penetration testing only.

Respond ONLY with valid JSON — no markdown, no extra text:
{
  "thought": "brief reasoning (1-2 sentences)",
  "action": "tool_name OR done",
  "reason": "why this tool now"
}
"""

INTERPRET_SYSTEM = """You are a senior penetration tester analysing raw tool output.

STRICT RULES:
- Report ONLY findings explicitly present in the raw output text provided.
- Do NOT use any prior knowledge about the target.
- Do NOT infer or speculate about findings not literally present in the output.
- If the output is empty, shows only errors, or shows nothing found — say exactly that.
- For each finding include the EXACT line, URL, port, or value from the raw output.
- An 'A' cipher rating means GOOD security — do NOT flag it as HIGH or CRITICAL.
- A certificate being valid means GOOD — do NOT flag valid certs as vulnerabilities.
- Only flag actual weaknesses: expired certs, weak ciphers (RC4/DES/NULL), SSLv2/v3, Heartbleed.
- Tool errors (like wrong flags) are INFO at most — not CRITICAL.
- Format: bullet points, max 8 bullets, each with [CRITICAL/HIGH/MEDIUM/LOW/INFO]
"""


@dataclass
class AgentDecision:
    thought: str
    action: str
    reason: str


def _get_host() -> str:
    # Explicit override always wins
    if os.environ.get("OLLAMA_HOST"):
        return os.environ["OLLAMA_HOST"]

    # Only use gateway IP if running inside WSL
    # WSL sets Microsoft-specific entries in /proc/version
    try:
        with open("/proc/version") as f:
            if "microsoft" in f.read().lower():
                result = subprocess.run(
                    ["ip", "route"], capture_output=True, text=True, timeout=3
                )
                for line in result.stdout.splitlines():
                    if "default" in line:
                        ip = line.split()[2]
                        return f"http://{ip}:11434"
    except Exception:
        pass

    return "http://localhost:11434"


class OllamaClient:
    def __init__(self, model: str = "deepseek-r1:14b", host: str = ""):
        self.model = model
        self.host  = host or _get_host()
        self.url   = f"{self.host}/api/chat"

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status == 200
        except Exception:
            return False

    def decide(self, context_summary: str, history: list[dict]) -> AgentDecision:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            *history[-12:],
            {
                "role": "user",
                "content": (
                    f"Current scan state:\n{context_summary}\n\n"
                    "What should we do next? Reply with JSON only."
                ),
            },
        ]
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }).encode()

        req = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                data    = json.loads(resp.read())
                content = data["message"]["content"]
                content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
                parsed  = json.loads(content)
                return AgentDecision(
                    thought=parsed.get("thought", ""),
                    action=parsed.get("action", "done"),
                    reason=parsed.get("reason", ""),
                )
        except Exception as e:
            return AgentDecision(thought=f"LLM error: {e}", action="done", reason="error")

    def interpret(self, tool_name: str, raw_output: str, context_summary: str) -> str:
        if not raw_output or raw_output.strip() in ("", "[skipped]", "[timeout]"):
            return f"[{tool_name}] produced no output."

        messages = [
            {"role": "system", "content": INTERPRET_SYSTEM},
            {"role": "user", "content": (
                f"Tool: {tool_name}\n\n"
                f"--- RAW OUTPUT START ---\n"
                f"{raw_output[:4000]}\n"
                f"--- RAW OUTPUT END ---\n\n"
                "Analyse ONLY the raw output above."
            )},
        ]
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.05},
        }).encode()

        req = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                data    = json.loads(resp.read())
                content = data["message"]["content"].strip()
                content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
                return content
        except Exception as e:
            return f"[interpretation failed: {e}]"
