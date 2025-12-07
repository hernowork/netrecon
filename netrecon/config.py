# netrecon/config.py
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ToolPaths:
    masscan: str = "masscan"
    naabu: str = "naabu"
    nuclei: str = "nuclei"


@dataclass
class AppConfig:
    # Use default_factory for non-primitive / mutable defaults
    tool_paths: ToolPaths = field(default_factory=ToolPaths)
    max_concurrency: int = 20
    default_timeout: int = 600  # seconds
    output_dir: Path = Path("scans")


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """
    For now just return defaults.
    Later you can read a YAML/JSON file from config_path
    and override fields.
    """
    return AppConfig()
