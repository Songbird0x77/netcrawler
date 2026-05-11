"""Agent loop — observe → think → act → repeat."""
from __future__ import annotations
import time
from typing import Callable
from core.context import ScanContext
from agent.ollama import OllamaClient, AgentDecision
from modules.passive_recon import run_passive_recon
from modules.web_fingerprint import run_web_fingerprint
from modules.port_scan import run_port_scan
from modules.vuln_scan import run_vuln_scan
from modules.dir_fuzz import run_dir_fuzz
from modules.subdomain_scan import run_subdomain_scan
from modules.ssl_audit import run_ssl_audit
from modules.dns_enum import run_dns_enum
from modules.web_crawler import run_web_crawler
from modules.services.ftp import run_ftp_enum
from modules.services.ssh import run_ssh_enum
from modules.services.smb import run_smb_enum
from modules.services.mysql import run_mysql_enum
from modules.services.redis import run_redis_enum
from modules.services.mongodb import run_mongodb_enum
from output.reporter import generate_report
from utils.rate_limiter import limiter

TOOL_MAP: dict[str, Callable[[ScanContext, Callable], str]] = {
    "passive_recon":   run_passive_recon,
    "subdomain_scan":  run_subdomain_scan,
    "dns_enum":        run_dns_enum,
    "port_scan":       run_port_scan,
    "web_fingerprint": run_web_fingerprint,
    "web_crawler":     run_web_crawler,
    "ssl_audit":       run_ssl_audit,
    "dir_fuzz":        run_dir_fuzz,
    "vuln_scan":       run_vuln_scan,
    "ftp_enum":        run_ftp_enum,
    "ssh_enum":        run_ssh_enum,
    "smb_enum":        run_smb_enum,
    "mysql_enum":      run_mysql_enum,
    "redis_enum":      run_redis_enum,
    "mongodb_enum":    run_mongodb_enum,
}

MAX_ITERATIONS = 25


class AgentLoop:
    def __init__(
        self,
        context: ScanContext,
        llm: OllamaClient,
        timeout_minutes: int = 0,
    ):
        self.ctx              = context
        self.llm              = llm
        self.timeout_minutes  = timeout_minutes
        self.timeout_seconds  = timeout_minutes * 60 if timeout_minutes else 0
        self.start_time       = time.time()
        self.history: list[dict] = []
        self.on_thought:  Callable = lambda t, r: None
        self.on_action:   Callable = lambda tool: None
        self.on_result:   Callable = lambda tool, interp: None
        self.on_done:     Callable = lambda: None
        self.on_timeout:  Callable = lambda: None
        self.on_error:    Callable = lambda msg: None

    def _timed_out(self) -> bool:
        if not self.timeout_seconds:
            return False
        return (time.time() - self.start_time) >= self.timeout_seconds

    def run(self):
        if not self.llm.is_available():
            self.on_error(
                f"Ollama not reachable at {self.llm.host}. "
                "Start Ollama with: ollama serve"
            )
            return

        for iteration in range(MAX_ITERATIONS):
            if self._timed_out():
                self.on_timeout()
                generate_report(self.ctx)
                self.on_done()
                return

            summary  = self.ctx.summary_for_llm()
            decision = self.llm.decide(summary, self.history)

            self.ctx.agent_thoughts.append(decision.thought)
            self.on_thought(decision.thought, decision.reason)

            if decision.action in ("done", "report") or not decision.action:
                generate_report(self.ctx)
                self.on_done()
                return

            # Fuzzy match
            tool_fn = TOOL_MAP.get(decision.action)
            if tool_fn is None:
                normalised = decision.action.replace("-", "_").strip()
                if normalised in TOOL_MAP:
                    decision.action = normalised
                    tool_fn = TOOL_MAP[normalised]
                else:
                    self.on_error(f"Unknown action: {decision.action!r}")
                    self.history.append({
                        "role": "user",
                        "content": (
                            f"{decision.action!r} is not valid. "
                            f"Valid tools: {', '.join(TOOL_MAP.keys())}."
                        ),
                    })
                    continue

            if decision.action in self.ctx.completed_stages:
                remaining = [t for t in TOOL_MAP if t not in self.ctx.completed_stages]
                self.history.append({
                    "role": "user",
                    "content": (
                        f"{decision.action} already completed. "
                        f"Remaining: {', '.join(remaining) or 'none — call done'}."
                    ),
                })
                continue

            self.on_action(decision.action)

            def status_cb(msg: str):
                self.on_thought(msg, "")

            try:
                raw_output = tool_fn(self.ctx, status_cb)
                self.ctx.tool_outputs[decision.action] = raw_output
                self.ctx.completed_stages.append(decision.action)

                interpretation = self.llm.interpret(
                    decision.action, raw_output, self.ctx.summary_for_llm()
                )
                self.on_result(decision.action, interpretation)

                self.history.append({
                    "role": "assistant",
                    "content": f"Ran {decision.action}. Findings:\n{interpretation}",
                })

            except Exception as e:
                err = f"{decision.action} failed: {e}"
                self.on_error(err)
                self.history.append({"role": "assistant", "content": err})
                self.ctx.completed_stages.append(decision.action)

            limiter.wait()

        generate_report(self.ctx)
        self.on_done()
