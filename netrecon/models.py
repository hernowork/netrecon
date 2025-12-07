from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class Target:
    ip: str
    hostname: Optional[str] = None


@dataclass
class Service:
    target: Target
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    target: Target
    service: Optional[Service] = None
    source_tool: str = ""
    references: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanProfile:
    name: str
    use_masscan: bool = True
    use_naabu: bool = True
    use_nuclei: bool = True
    nuclei_templates: Optional[str] = None  # e.g. "cves,default"


@dataclass
class ScanResult:
    profile: ScanProfile
    started_at: datetime
    finished_at: Optional[datetime] = None
    targets: List[Target] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def add_targets(self, targets: List[Target]) -> None:
        self.targets.extend(targets)

    def add_services(self, services: List[Service]) -> None:
        self.services.extend(services)

    def add_findings(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)