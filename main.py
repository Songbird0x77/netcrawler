#!/usr/bin/env python3
"""NetCrawler — AI-powered pentesting agent."""
from __future__ import annotations
import typer
from tui.app import NetCrawlerApp

app = typer.Typer(
    add_completion=False,
    name="netcrawler",
    help="""
\b
NetCrawler — AI-Powered Pentesting Agent
=========================================
An autonomous recon and vulnerability scanning agent powered
by a local LLM (Ollama). Runs fully offline.

\b
Examples:
  netcrawler example.com
  netcrawler 192.168.1.1 --profile aggressive
  netcrawler example.com --model mistral --profile stealth
  netcrawler example.com --scope "example.com,api.example.com"
  netcrawler example.com --scope "192.168.1.0/24" --profile aggressive
  netcrawler example.com --timeout 30 --verbose

\b
Profiles:
  stealth     Passive recon only — no active scanning
  default     Balanced — recon, port scan, web fingerprint, service enum
  aggressive  Full scan — all modules, fuzzing, vuln detection

\b
Scope:
  Comma-separated list of allowed hosts, domains, or CIDR ranges.
  The agent will refuse to scan anything outside this list.
  The primary target is always implicitly in scope.

\b
Legal:
  Only scan targets you have explicit written permission to test.
    """,
)

PROFILES = {
    "stealth":    "Passive recon only — no active scanning",
    "default":    "Balanced — recon + port scan + web fingerprint + service enum",
    "aggressive": "Full scan — everything including fuzzing, vuln scan, all services",
}


@app.command()
def run(
    target: str = typer.Argument(
        ...,
        help="Target to scan — IP address, CIDR range, domain, or URL",
        metavar="TARGET",
    ),
    model: str = typer.Option(
        "deepseek-r1:14b",
        "--model", "-m",
        help="Ollama model to use for reasoning",
        metavar="MODEL",
    ),
    profile: str = typer.Option(
        "default",
        "--profile", "-p",
        help="Scan profile: stealth / default / aggressive",
        metavar="PROFILE",
    ),
    scope: str = typer.Option(
        "",
        "--scope", "-s",
        help='Engagement scope — comma separated hosts/CIDRs e.g. "example.com,192.168.1.0/24"',
        metavar="SCOPE",
    ),
    timeout: int = typer.Option(
        0,
        "--timeout", "-t",
        help="Max scan duration in minutes (0 = no limit)",
        metavar="MINUTES",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show raw tool output alongside AI interpretation",
    ),
):
    """Scan a TARGET using the AI-driven agent."""
    if profile not in PROFILES:
        typer.echo(f"[!] Unknown profile '{profile}'. Choose from: {', '.join(PROFILES)}")
        raise typer.Exit(1)

    tui = NetCrawlerApp(
        target=target,
        model=model,
        profile=profile,
        scope=scope,
        verbose=verbose,
        timeout_minutes=timeout,
    )
    tui.run()


if __name__ == "__main__":
    app()
