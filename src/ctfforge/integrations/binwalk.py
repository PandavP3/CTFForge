"""Binwalk signature scan; extraction and execution options are never passed."""
from pathlib import Path
from ._process import ProcessResult, run_bounded


def scan_signatures(path: Path, *, timeout: float = 30, output_limit: int = 1_000_000) -> ProcessResult:
    return run_bounded("binwalk", ["--signature", "--quiet", str(path.resolve())],
                       timeout=timeout, output_limit=output_limit)
