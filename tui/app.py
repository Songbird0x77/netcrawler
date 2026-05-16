"""NetCrawler Rich TUI."""
from __future__ import annotations
import threading
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from core.context import ScanContext
from agent.ollama import OllamaClient
from agent.loop import AgentLoop

BANNER = r"""
 ███╗   ██╗███████╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝╚══════╝╚══════╝╚═╝  ╚═╝
"""

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}

STAGE_LABEL = {
    "passive_recon":   "[blue]PASSIVE RECON[/]",
    "subdomain_scan":  "[blue]SUBDOMAIN SCAN[/]",
    "dns_enum":        "[blue]DNS ENUM[/]",
    "port_scan":       "[cyan]PORT SCAN[/]",
    "web_fingerprint": "[magenta]WEB FINGERPRINT[/]",
    "web_crawler":     "[magenta]WEB CRAWLER[/]",
    "ssl_audit":       "[magenta]SSL AUDIT[/]",
    "dir_fuzz":        "[yellow]DIR FUZZ[/]",
    "vuln_scan":       "[red]VULN SCAN[/]",
    "ftp_enum":        "[green]FTP ENUM[/]",
    "ssh_enum":        "[green]SSH ENUM[/]",
    "smb_enum":        "[green]SMB ENUM[/]",
    "mysql_enum":      "[green]MYSQL ENUM[/]",
    "redis_enum":      "[green]REDIS ENUM[/]",
    "mongodb_enum":    "[green]MONGODB ENUM[/]",
}

PROFILE_COLOR = {"stealth": "blue", "default": "cyan", "aggressive": "red"}


class NetCrawlerApp:
    def __init__(
        self,
        target: str,
        model: str,
        profile: str = "default",
        scope: str = "",
        verbose: bool = False,
        timeout_minutes: int = 0,
    ):
        self.target          = target
        self.model           = model
        self.profile         = profile
        self.scope           = scope
        self.verbose         = verbose
        self.timeout_minutes = timeout_minutes
        self.console         = Console()
        self._start_time     = None

    def run(self):
        self._print_banner()
        ctx = ScanContext(
            raw_target=self.target,
            model=self.model,
            profile=self.profile,
            verbose=self.verbose,
            scope_str=self.scope,
        )
        llm = OllamaClient(model=self.model)

        pc = PROFILE_COLOR.get(self.profile, "white")
        self.console.print(f"\n[bold green][*][/] Target  : [cyan]{ctx.target_host}[/]")
        self.console.print(f"[bold green][*][/] Web     : {'yes — ' + ctx.target_url if ctx.is_web else 'no'}")
        self.console.print(f"[bold green][*][/] Model   : [magenta]{self.model}[/]")
        self.console.print(f"[bold green][*][/] Profile : [{pc}]{self.profile.upper()}[/]")
        if self.scope:
            self.console.print(f"[bold green][*][/] Scope   : [yellow]{self.scope}[/]")
        if self.timeout_minutes:
            self.console.print(f"[bold green][*][/] Timeout : {self.timeout_minutes} minutes")
        self.console.print(f"[bold green][*][/] Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")

        if not llm.is_available():
            self.console.print("[bold red][!] Ollama is not running.[/]")
            self.console.print(f"[yellow]    Host: {llm.host}[/]")
            self.console.print(f"[yellow]    Pull model: [bold]ollama pull {self.model}[/]\n")
            return

        self.console.print(f"[dim green]    Ollama connected → {llm.host}[/]\n")

        loop = AgentLoop(
            context=ctx,
            llm=llm,
            timeout_minutes=self.timeout_minutes,
        )
        self._wire_callbacks(loop, ctx)
        self._start_time = time.time()

        agent_thread = threading.Thread(target=loop.run, daemon=True)
        agent_thread.start()
        agent_thread.join()

        self._print_summary(ctx)

    def _wire_callbacks(self, loop: AgentLoop, ctx: ScanContext):

        def on_thought(thought: str, reason: str):
            if thought:
                self.console.print(f"\n[dim cyan]  ◈ THINK[/] {thought}")
            if reason:
                self.console.print(f"[dim]         → {reason}[/]")

        def on_action(tool: str):
            label = STAGE_LABEL.get(tool, f"[white]{tool.upper()}[/]")
            self.console.print(f"\n[bold green]  ▶ RUN[/]   {label}")
            self.console.rule(characters="─", style="dim green")
            counts = ctx.severity_counts()
            self.console.print(
                f"[dim]  Findings → "
                f"[red]CRIT:{counts['critical']}[/] "
                f"[yellow]HIGH:{counts['high']}[/] "
                f"[dim yellow]MED:{counts['medium']}[/] "
                f"[cyan]LOW:{counts['low']}[/][/]"
            )

        def on_result(tool: str, interpretation: str):
            if interpretation and interpretation.strip():
                panel = Panel(
                    interpretation,
                    title=f"[bold green]{tool} — findings[/]",
                    border_style="green",
                    padding=(0, 2),
                )
                self.console.print(panel)
            recent = [f for f in ctx.findings if f.source == tool]
            for f in recent[-5:]:
                color = SEVERITY_COLOR.get(f.severity, "white")
                self.console.print(f"  [{color}][{f.severity.upper():8}][/] {f.title}")

        def on_done():
            elapsed = time.time() - self._start_time if self._start_time else 0
            self.console.print(f"\n[bold green]  ✓ Scan complete[/] [dim]({elapsed:.0f}s)[/]")

        def on_timeout():
            self.console.print(f"\n[bold yellow]  ⏱ Timeout reached — generating report...[/]")

        def on_error(msg: str):
            self.console.print(f"\n[bold red]  ✗ ERROR:[/] {msg}")

        loop.on_thought  = on_thought
        loop.on_action   = on_action
        loop.on_result   = on_result
        loop.on_done     = on_done
        loop.on_timeout  = on_timeout
        loop.on_error    = on_error

    def _print_summary(self, ctx: ScanContext):
        elapsed = time.time() - self._start_time if self._start_time else 0
        counts  = ctx.severity_counts()

        self.console.print()
        self.console.rule("[bold green] SCAN COMPLETE [/]", style="green")
        self.console.print()

        self.console.print(
            Align.center(
                f"[bold red]● CRITICAL: {counts['critical']}[/]  "
                f"[red]● HIGH: {counts['high']}[/]  "
                f"[yellow]● MEDIUM: {counts['medium']}[/]  "
                f"[cyan]● LOW: {counts['low']}[/]  "
                f"[dim]● INFO: {counts['info']}[/]"
            )
        )
        self.console.print()

        stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stats.add_column(style="dim")
        stats.add_column(style="bold cyan")
        stats.add_row("Target",      ctx.target_host)
        stats.add_row("Profile",     ctx.profile)
        if self.scope:
            stats.add_row("Scope", self.scope)
        stats.add_row("Duration",    f"{elapsed:.0f}s ({elapsed/60:.1f}m)")
        stats.add_row("Subdomains",  str(len(ctx.subdomains)))
        stats.add_row("Alive hosts", str(len(ctx.alive_hosts)))
        stats.add_row("Open ports",  str(len(set(ctx.ports))))
        stats.add_row("Tech stack",  ", ".join(ctx.tech_stack[:5]) or "none")
        stats.add_row("WAF",         ctx.waf_detected or "not detected")
        stats.add_row("Directories", str(len(ctx.directories)))
        stats.add_row("Stages run",  ", ".join(ctx.completed_stages) or "none")
        self.console.print(stats)

        if ctx.findings:
            self.console.print()
            table = Table(
                title="[bold]All Findings[/]",
                box=box.ROUNDED,
                show_lines=True,
                border_style="dim",
            )
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Title")
            table.add_column("Source",   style="dim", width=16)
            table.add_column("Location", style="cyan")

            from output.reporter import SEVERITY_ORDER
            for f in sorted(ctx.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
                color = SEVERITY_COLOR.get(f.severity, "white")
                table.add_row(
                    Text(f.severity.upper(), style=color),
                    f.title,
                    f.source,
                    (f.url or f.host or "")[:50],
                )
            self.console.print(table)

        from output.reporter import generate_report
        import os
        md_path   = generate_report(ctx)
        html_path = md_path.replace("report.md", "report.html")

        self.console.print()
        self.console.print(f"[bold green][+][/] Markdown → [underline]{md_path}[/]")
        if os.path.exists(html_path):
            self.console.print(f"[bold green][+][/] HTML     → [underline]{html_path}[/]")
            self.console.print(f"[dim]    Windows: \\\\wsl$\\Ubuntu{html_path}[/]")
        self.console.print()

    def _print_banner(self):
        self.console.print(Text(BANNER, style="bold cyan"))
        self.console.print(Align.center(Text("AI-Powered Pentesting Agent", style="bold white")))
        self.console.print(Align.center(Text(f"Powered by Ollama · {datetime.now():%Y-%m-%d}", style="dim")))
        self.console.print()
