"""Fixed-argument adapters for optional Unix-style binary inspection tools."""
import shutil
from pathlib import Path

from ._process import ProcessResult, run_bounded

TOOLS = ("file", "readelf", "objdump")
READELF_MODES = {
    "header": ["-W", "-h"],
    "program-headers": ["-W", "-l"],
    "sections": ["-W", "-S"],
    "symbols": ["-W", "-s"],
    "dynamic": ["-W", "-d"],
    "relocations": ["-W", "-r"],
}
OBJDUMP_MODES = {
    "file-headers": ["-f"],
    "section-headers": ["-h"],
    "disassembly": ["-d"],
    "symbol-table": ["-t"],
    "private-headers": ["-p"],
}


def availability() -> list[dict]:
    """Return lookup status without invoking the external utilities."""
    results = []
    for name in TOOLS:
        try:
            executable = shutil.which(name)
            results.append({"tool": name, "available": executable is not None,
                            "executable": executable or None,
                            "status": "available" if executable else "not_found"})
        except OSError as exc:
            results.append({"tool": name, "available": False, "executable": None,
                            "status": "lookup_error", "error": str(exc)})
    return results


def identify_file(path: Path, *, timeout: float = 15, output_limit: int = 1_000_000) -> ProcessResult:
    return run_bounded("file", ["-b", "--", str(path.resolve())],
                       timeout=timeout, output_limit=output_limit)


def run_readelf(path: Path, mode: str, *, timeout: float = 30,
                output_limit: int = 1_000_000) -> ProcessResult:
    try:
        selected = READELF_MODES[mode]
    except KeyError as exc:
        raise ValueError(f"Unsupported readelf mode {mode!r}.") from exc
    return run_bounded("readelf", [*selected, str(path.resolve())],
                       timeout=timeout, output_limit=output_limit)


def run_objdump(path: Path, mode: str, *, timeout: float = 30,
                output_limit: int = 1_000_000) -> ProcessResult:
    try:
        selected = OBJDUMP_MODES[mode]
    except KeyError as exc:
        raise ValueError(f"Unsupported objdump mode {mode!r}.") from exc
    return run_bounded("objdump", [*selected, str(path.resolve())],
                       timeout=timeout, output_limit=output_limit)
