from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


class ToolError(RuntimeError):
    """Raised when an external tool is missing or fails."""
    pass


@dataclass
class SubprocessResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass
class BaseTool:
    name: str
    binary: str

    def __post_init__(self) -> None:
        # Make sure the binary exists on PATH
        if shutil.which(self.binary) is None:
            raise ToolError(
                f"{self.name} binary '{self.binary}' not found in PATH. "
                f"Install it and ensure it's in PATH "
                f"(e.g. on macOS: brew install {self.binary} or adjust your PATH)."
            )

    def run_command(
        self,
        args: List[str],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> SubprocessResult:
        cmd = [self.binary] + args

        try:
            proc = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ToolError(f"{self.name} not found: {self.binary}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{self.name} timed out") from exc

        return SubprocessResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
        )
