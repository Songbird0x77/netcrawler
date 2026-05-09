"""Shared scan state."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
import re
from urllib.parse import urlparse


@dataclass
class Service:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""
    extra: str = ""


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    source: str
    host: str = ""
    port: int | None = None
    url: str = ""
    tags: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class ScanContext:
    raw_target: str
    model: str = "deepseek-r1:14b"
    profile: str = "default"
    verbose: bool = False
    started_at: datetime = field(default_factory=datetime.now)

    target_host: str = ""
    target_url: str = ""
    is_web: bool = False

    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)

    tech_stack: list[str] = field(default_factory=list)
    waf_detected: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    directories: list[str] = field(default_factory=list)

    findings: list[Finding] = field(default_factory=list)
    completed_stages: list[str] = field(default_factory=list)
    agent_thoughts: list[str] = field(default_factory=list)
    tool_outputs: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self.target_host, self.target_url, self.is_web = self._resolve(self.raw_target)

    @staticmethod
    def _resolve(target: str) -> tuple[str, str, bool]:
        parsed = urlparse(target)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return parsed.netloc, target, True
        if "." in target and not re.match(r"^\d+\.\d+\.\d+\.\d+(/|$)", target) and "/" not in target:
            return target, f"https://{target}", True
        return target, "", False

    def add_finding(self, **kwargs) -> Finding:
        f = Finding(**kwargs)
        self.findings.append(f)
        return f

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def summary_for_llm(self) -> str:
        counts = self.severity_counts()
        lines = [
            f"Target: {self.target_host}",
            f"Scan profile: {self.profile}",
            f"Web target: {'yes (' + self.target_url + ')' if self.is_web else 'no'}",
            f"Completed stages: {', '.join(self.completed_stages) or 'none'}",
            f"Subdomains found: {len(self.subdomains)}",
            f"Alive hosts: {len(self.alive_hosts)}",
            f"Open ports: {sorted(set(self.ports)) or 'unknown — port_scan not run yet'}",
            f"Services: {[f'{s.port}/{s.name}' for s in self.services] or 'none'}",
            f"Tech stack: {', '.join(self.tech_stack[:8]) or 'none detected'}",
            f"WAF: {self.waf_detected or 'none detected'}",
            f"Directories found: {len(self.directories)}",
            f"Findings: CRIT={counts['critical']} HIGH={counts['high']} MED={counts['medium']} LOW={counts['low']} INFO={counts['info']}",
        ]
        return "\n".join(lines)

