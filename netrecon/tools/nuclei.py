from __future__ import annotations

import json
from typing import Iterable, List, Optional

from ..models import Finding, Service, Severity, Target
from .base import BaseTool, ToolError


class NucleiTool(BaseTool):
    def __init__(self, binary: str = "nuclei") -> None:
        super().__init__(name="nuclei", binary=binary)

    def _map_severity(self, sev: Optional[str]) -> Severity:
        if not sev:
            return Severity.UNKNOWN

        s = sev.lower()
        if s in ("critical", "crit"):
            return Severity.CRITICAL
        if s == "high":
            return Severity.HIGH
        if s == "medium":
            return Severity.MEDIUM
        if s == "low":
            return Severity.LOW
        if s in ("info", "informational"):
            return Severity.INFO
        return Severity.UNKNOWN

    def scan_services(
        self,
        services: Iterable[Service],
        templates: Optional[str] = None,
        timeout: int = 1800,
    ) -> List[Finding]:
        """
        Run nuclei in JSON mode against the given services.
        For now, assume HTTP-ish services and build URLs from IP + port.
        Targets are passed via stdin.
        """
        services = list(services)
        if not services:
            return []

        urls: List[str] = []
        for s in services:
            scheme = "https" if s.port in (443, 8443) else "http"
            urls.append(f"{scheme}://{s.target.ip}:{s.port}")

        urls_str = "\n".join(urls)

        args = ["-json"]
        if templates:
            args.extend(["-t", templates])

        result = self.run_command(args, input_data=urls_str, timeout=timeout)

        if result.returncode != 0:
            raise ToolError(f"nuclei failed: {result.stderr}")

        findings: List[Finding] = []
        url_to_service = {u: s for u, s in zip(urls, services)}

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = data.get("template-id", "unknown")
            info = data.get("info", {}) or {}
            name = info.get("name", template_id)
            description = info.get("description", "")
            sev = self._map_severity(info.get("severity"))
            matched_at = data.get("matched-at", "")

            service = url_to_service.get(matched_at)
            if service:
                target = service.target
            else:
                target = Target(ip="unknown")

            findings.append(
                Finding(
                    id=template_id,
                    title=name,
                    description=description,
                    severity=sev,
                    target=target,
                    service=service,
                    source_tool="nuclei",
                    raw=data,
                )
            )

        return findings
