"""Safe wrappers for optional external tools. Commands are always argument lists."""

import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from .exceptions import ExternalToolError


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def run_tool(command: Sequence[str], *, timeout: float = 60, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    if not command:
        raise ValueError("command cannot be empty")
    executable = find_tool(command[0])
    if executable is None:
        raise ExternalToolError(f"Optional tool '{command[0]}' is not installed or not on PATH.")
    try:
        return subprocess.run(
            [executable, *command[1:]], capture_output=True, text=True, timeout=timeout,
            cwd=cwd, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExternalToolError(f"Could not run {command[0]}: {exc}") from exc
