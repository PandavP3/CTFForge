"""Normalize solve inputs from paths, text, or stdin into immutable bytes."""

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .exceptions import CTFForgeError


@dataclass(frozen=True)
class SolverInput:
    name: str
    data: bytes
    source: str


def from_path(path: Path) -> SolverInput:
    expanded = path.expanduser()
    if not expanded.exists() or not expanded.is_file():
        raise CTFForgeError(f"Input file does not exist or is not a regular file: {expanded}")
    try:
        return SolverInput(expanded.name, expanded.read_bytes(), str(expanded.resolve()))
    except OSError as exc:
        raise CTFForgeError(f"Cannot read input file {expanded}: {exc}") from exc


def from_text(text: str) -> SolverInput:
    return SolverInput("input.txt", text.encode("utf-8"), "text input")


def from_stdin(stream: BinaryIO) -> SolverInput:
    return SolverInput("stdin.bin", stream.read(), "stdin")
