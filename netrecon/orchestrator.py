from __future__ import annotations

from datetime import datetime
from typing import List

from .config import AppConfig
from .models import ScanProfile, ScanResult, Target, Service, Finding
from .tools.masscan import MasscanTool
from .tools.naabu import NaabuTool
from .tools.nuclei import NucleiTool


class Orchestrator:
    def __init__(
        self,
        config: AppConfig,
        profile: ScanProfile,
        masscan_ports: str = "1-1000",
        naabu_ports: str = "1-65535",
    ) -> None:
        self.config = config
        self.profile = profile
        self.masscan_ports = masscan_ports
        self.naabu_ports = naabu_ports

        self.masscan = MasscanTool(binary=config.tool_paths.masscan)
        self.naabu = NaabuTool(binary=config.tool_paths.naabu)
        self.nuclei = NucleiTool(binary=config.tool_paths.nuclei)

    # ---- phases ------------------------------------------------------------

    def discover_hosts(self, target_specs: List[str]) -> List[Target]:
        if self.profile.use_masscan:
            return self.masscan.discover_hosts(
                targets=target_specs,
                ports=self.masscan_ports,
                timeout=self.config.default_timeout,
            )
        # no masscan: treat input as direct hosts
        return [Target(ip=t) for t in target_specs]

    def scan_ports(self, hosts: List[Target]) -> List[Service]:
        if not hosts or not self.profile.use_naabu:
            return []

        return self.naabu.scan_ports(
            targets=hosts,
            ports=self.naabu_ports,
            timeout=self.config.default_timeout,
        )

    def nuclei_scan(self, services: List[Service]) -> List[Finding]:
        if not services or not self.profile.use_nuclei:
            return []

        return self.nuclei.scan_services(
            services=services,
            templates=self.profile.nuclei_templates,
            timeout=self.config.default_timeout,
        )

    # ---- legacy helper -----------------------------------------------------

    def run_scan(self, target_specs: List[str]) -> ScanResult:
        result = ScanResult(
            profile=self.profile,
            started_at=datetime.now(timezone.utc),
        )

        hosts = self.discover_hosts(target_specs)
        result.add_targets(hosts)

        services = self.scan_ports(hosts)
        result.add_services(services)

        findings = self.nuclei_scan(services)
        result.add_findings(findings)

        result.finished_at = datetime.now(timezone.utc)
        return result
