#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from netrecon.config import load_config
from netrecon.models import ScanProfile, ScanResult
from netrecon.orchestrator import Orchestrator
from netrecon.reporting.html_report import generate_html
from netrecon.tools.base import ToolError


def parse_targets(
    targets_opt: Optional[str],
    targets_file: Optional[Path],
) -> List[str]:
    targets: List[str] = []

    if targets_opt:
        for part in targets_opt.split(","):
            s = part.strip()
            if s:
                targets.append(s)

    if targets_file:
        for line in targets_file.read_text().splitlines():
            s = line.strip()
            if s:
                targets.append(s)

    return targets


def build_profile(args: argparse.Namespace) -> ScanProfile:
    return ScanProfile(
        name=args.profile,
        use_masscan=not args.no_masscan,
        use_naabu=not args.no_naabu,
        use_nuclei=not args.no_nuclei,
        nuclei_templates=args.nuclei_templates,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Internal network recon & vuln scanner (masscan -> naabu -> nuclei)."
    )
    parser.add_argument(
        "-t",
        "--targets",
        help="Comma-separated list of targets (IP, CIDR, hostname).",
    )
    parser.add_argument(
        "-f",
        "--targets-file",
        type=Path,
        help="File with one target per line.",
    )
    parser.add_argument(
        "-p",
        "--profile",
        default="quick",
        help="Profile name label (e.g. quick, full).",
    )
    parser.add_argument(
        "--no-masscan",
        action="store_true",
        help="Skip masscan host discovery (send targets directly to naabu).",
    )
    parser.add_argument(
        "--no-naabu",
        action="store_true",
        help="Skip naabu port scan.",
    )
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="Skip nuclei vuln scan.",
    )
    parser.add_argument(
        "--masscan-ports",
        default="1-1000",
        help="Port range/list for masscan host discovery (default: 1-1000).",
    )
    parser.add_argument(
        "--naabu-ports",
        default="1-65535",
        help="Port range/list for naabu (default: 1-65535).",
    )
    parser.add_argument(
        "--nuclei-templates",
        default=None,
        help="Nuclei templates string, e.g. 'cves,default'. If omitted, nuclei defaults are used.",
    )
    parser.add_argument(
        "--output-html",
        type=Path,
        default=Path("report.html"),
        help="Path to HTML report output.",
    )

    args = parser.parse_args()

    target_specs = parse_targets(args.targets, args.targets_file)
    if not target_specs:
        parser.error("No targets provided. Use --targets or --targets-file.")

    cfg = load_config()
    profile = build_profile(args)

    try:
        orch = Orchestrator(
            config=cfg,
            profile=profile,
            masscan_ports=args.masscan_ports,
            naabu_ports=args.naabu_ports,
        )
    except ToolError as e:
        print(f"[!] Tool error: {e}")
        raise SystemExit(1)

    # Try to use rich for a nice progress bar
    try:
        from rich.progress import Progress
        from rich.console import Console

        use_rich = True
        console = Console()
    except ImportError:
        use_rich = False
        console = None  # type: ignore[assignment]

    result = ScanResult(profile=profile, started_at=datetime.now(timezone.utc))

    if use_rich:
        with Progress(console=console) as progress:
            # total steps: masscan, naabu, nuclei (some may be skipped)
            task = progress.add_task("Scanning", total=3)

            # Phase 1: masscan
            if profile.use_masscan:
                progress.update(task, description="Host discovery (masscan)")
                try:
                    hosts = orch.discover_hosts(target_specs)
                except ToolError as e:
                    console.print(f"[red][!] masscan error:[/red] {e}")
                    hosts = []
            else:
                hosts = orch.discover_hosts(target_specs)  # just wrap targets as hosts

            result.add_targets(hosts)
            progress.advance(task)

            # Phase 2: naabu
            if profile.use_naabu:
                progress.update(task, description="Port scan (naabu)")
                try:
                    services = orch.scan_ports(hosts)
                except ToolError as e:
                    console.print(f"[red][!] naabu error:[/red] {e}")
                    services = []
            else:
                services = []

            result.add_services(services)
            progress.advance(task)

            # Phase 3: nuclei
            if profile.use_nuclei:
                progress.update(task, description="Vuln scan (nuclei)")
                try:
                    findings = orch.nuclei_scan(services)
                except ToolError as e:
                    console.print(f"[red][!] nuclei error:[/red] {e}")
                    findings = []
            else:
                findings = []

            result.add_findings(findings)
            progress.advance(task)
    else:
        print("[*] Starting scan (install 'rich' for a progress bar)")

        print("[*] Host discovery (masscan)" if profile.use_masscan else "[*] Skipping masscan")
        try:
            hosts = orch.discover_hosts(target_specs)
        except ToolError as e:
            print(f"[!] masscan error: {e}")
            hosts = []
        result.add_targets(hosts)
        print(f"[+] Discovered {len(hosts)} hosts")

        print("[*] Port scan (naabu)" if profile.use_naabu else "[*] Skipping naabu")
        try:
            services = orch.scan_ports(hosts)
        except ToolError as e:
            print(f"[!] naabu error: {e}")
            services = []
        result.add_services(services)
        print(f"[+] Discovered {len(services)} services")

        print("[*] Vulnerability scan (nuclei)" if profile.use_nuclei else "[*] Skipping nuclei")
        try:
            findings = orch.nuclei_scan(services)
        except ToolError as e:
            print(f"[!] nuclei error: {e}")
            findings = []
        result.add_findings(findings)
        print(f"[+] Got {len(findings)} findings")

    result.finished_at = datetime.now(timezone.utc)

    html = generate_html(result)
    args.output_html.parent.mkdir(parents=True, exist_ok=True)
    args.output_html.write_text(html, encoding="utf-8")

    print(f"[+] Scan completed. HTML report written to {args.output_html}")


if __name__ == "__main__":
    main()
