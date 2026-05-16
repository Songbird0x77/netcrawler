"""Scope enforcement — hard allowlist for engagement boundaries."""
from __future__ import annotations
import ipaddress
from urllib.parse import urlparse


class ScopeManager:
    def __init__(self, scope_str: str = ""):
        self.rules: list[str] = []
        self.ip_networks: list[ipaddress.IPv4Network] = []
        self.enabled = False

        if scope_str.strip():
            self.enabled = True
            for entry in scope_str.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                try:
                    self.ip_networks.append(ipaddress.IPv4Network(entry, strict=False))
                except ValueError:
                    self.rules.append(entry.lower())

    def is_in_scope(self, target: str) -> bool:
        if not self.enabled:
            return True
        parsed = urlparse(target)
        host = (parsed.netloc or parsed.path).split(":")[0].strip().lower()
        try:
            ip = ipaddress.IPv4Address(host)
            return any(ip in net for net in self.ip_networks)
        except ValueError:
            pass
        for rule in self.rules:
            if host == rule:
                return True
            if host.endswith(f".{rule}"):
                return True
            if rule.startswith("*.") and host.endswith(rule[1:]):
                return True
        return False

    def filter(self, targets: list[str]) -> list[str]:
        if not self.enabled:
            return targets
        return [t for t in targets if self.is_in_scope(t)]

    def warn(self, target: str) -> str | None:
        if not self.enabled:
            return None
        if not self.is_in_scope(target):
            return f"[SCOPE VIOLATION] {target} is out of scope — skipped"
        return None

    def summary(self) -> str:
        if not self.enabled:
            return "unrestricted"
        parts = self.rules + [str(n) for n in self.ip_networks]
        return ", ".join(parts)
