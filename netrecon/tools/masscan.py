from __future__ import annotations

import json
from typing import List

from ..models import Target
from .base import BaseTool, ToolError


class MasscanTool(BaseTool):
    def __init__(self, binary: str = "masscan") -> None:
        super().__init__(name="masscan", binary=binary)

    def discover_hosts(
        self,
        targets: List[str],
        ports: str = "1-1000",
        rate: int = 1000,
        timeout: int = 600,
    ) -> List[Target]:
        """
        Run masscan to discover alive hosts with at least one open port.
        Uses JSONL output and extracts IPs.
        """
        if not targets:
            return []

        # masscan accepts space-separated targets
        args = [
            *targets,
            "-p",
            ports,
            "--rate",
            str(rate),
            "--wait",
            "0",
            "--output-format",
            "json",
            "--output-filename",
            "-",  # stdout
        ]

        result = self.run_command(args, timeout=timeout)

        # masscan can exit with 0 or 2 and still be useful
        if result.returncode not in (0, 2):
            raise ToolError(f"masscan failed: {result.stderr}")

        hosts: List[Target] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = data.get("ip")
            if ip:
                hosts.append(Target(ip=ip))

        unique_hosts = {t.ip: t for t in hosts}
        return list(unique_hosts.values())
