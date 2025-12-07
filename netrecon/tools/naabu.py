from __future__ import annotations

import json
from typing import Dict, List

from ..models import Service, Target
from .base import BaseTool, ToolError


class NaabuTool(BaseTool):
    def __init__(self, binary: str = "naabu") -> None:
        super().__init__(name="naabu", binary=binary)

    def scan_ports(
        self,
        targets: List[Target],
        ports: str = "1-65535",
        timeout: int = 600,
    ) -> List[Service]:
        """
        Run naabu in JSON mode and map results to Service objects.
        Hosts are passed via stdin (echo host | naabu ... style).
        """
        if not targets:
            return []

        hosts_str = "\n".join(t.ip for t in targets)

        args = [
            "-json",
            "-p",
            ports,
        ]

        result = self.run_command(args, input_data=hosts_str, timeout=timeout)

        if result.returncode != 0:
            raise ToolError(f"naabu failed: {result.stderr}")

        services: List[Service] = []
        ip_to_target: Dict[str, Target] = {t.ip: t for t in targets}

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = data.get("ip")
            port = data.get("port")
            protocol = data.get("protocol", "tcp")

            if not ip or port is None:
                continue

            target = ip_to_target.get(ip, Target(ip=ip))
            service = Service(
                target=target,
                port=int(port),
                protocol=str(protocol),
            )
            services.append(service)

        return services
