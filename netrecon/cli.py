# netrecon/cli.py
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, List

import typer

from .config import load_config
from .models import ScanProfile, ScanResult
from .orchestrator import Orchestrator
from .reporting.html_report import generate_html
from .tools.base import ToolError

app = typer.Typer(help="Internal network recon and vuln scanner.")


def _build_profile(name: str) -> ScanProfile:
    name = name.lower()
    if name == "quick":
        return ScanProfile(
            name="quick",
            use_masscan=True,
            use_naabu=True,
            use_nuclei=True,
            nuclei_templates=None,
        )
    if name == "full":
        return ScanProfile(
            name="full",
            use_masscan=True,
            use_naabu=True,
            use_nuclei=True,
            nuclei_templates="cves,default",
        )
    return ScanProfile(name=name)


@app.command()
def scan(
    targets: Optional[str] = typer.Option(
        None,
        "--targets",
        "-t",
        help="Comma-separated list of targets (IP, CIDR, hostname).",
    ),
    targets_file: Optional[Path] = typer.Option(
        None,
        "--targets-file",
        "-f",
        exists=True,
        readable=True,
        help="File with one target per line.",
    ),
    profile: str = typer.Option(
        "quick",
        "--profile",
        "-p",
        help="Scan profile (e.g. quick, full).",
    ),
    output_html: Path = typer.Option(
        Path("report.html"),
        "--output-html",
        help="Path to HTML report output.",
    ),
) -> None:
    """
    Run a scan with masscan → naabu → nuclei and produce an HTML report.
    Shows a simple phase-based progress bar if `rich` is installed.
    """
    # ---- parse targets -----------------------------------------------------
    target_specs: List[str] = []

    if targets:
        for part in targets.split(","):
            s = part.strip()
            if s:
                target_specs.append(s)

    if targets_file:
        for line in targets_file.read_text().splitlines():
            s = line.strip()
            if s:
                target_specs.append(s)

    if not target_specs:
        typer.echo("[-] No targets provided. Use --targets or --targets-file.")
        raise typer.Exit(code=1)

    cfg = load_config()
    prof = _build_profile(profile)

    try:
        orch = Orchestrator(config=cfg, profile=prof)
    except ToolError as e:
        typer.echo(f"[!] Tool error: {e}")
        raise typer.Exit(code=1)

    # ---- progress bar / fallback ------------------------------------------
    try:
        from rich.progress import Progress
        use_progress = True
    except ImportError:
        use_progress = False

    scan_result = ScanResult(profile=prof, started_at=datetime.utcnow())

    if use_progress:
        # 3 phases: masscan, naabu, nuclei
        from rich.console import Console

        console = Console()

        with Progress(console=console) as progress:
            task = progress.add_task("Scanning", total=3)

            # Phase 1: host discovery
            progress.update(task, description="Host discovery (masscan)")
            hosts = orch.discover_hosts(target_specs)
            scan_result.add_targets(hosts)
            progress.advance(task)

            # Phase 2: port scanning
            progress.update(task, description="Port scan (naabu)")
            services = orch.scan_ports(hosts)
            scan_result.add_services(services)
            progress.advance(task)

            # Phase 3: vuln scan
            progress.update(task, description="Vuln scan (nuclei)")
            findings = orch.nuclei_scan(services)
            scan_result.add_findings(findings)
            progress.advance(task)

    else:
        # Fallback: no rich installed, just run normally.
        typer.echo("[*] Running scan (install 'rich' to see a progress bar)...")
        scan_result = orch.run_scan(target_specs)

    scan_result.finished_at = datetime.utcnow()

    # ---- write report ------------------------------------------------------
    report_html = generate_html(scan_result)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(report_html, encoding="utf-8")

    typer.echo(f"[+] Scan completed. HTML report written to {output_html}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
