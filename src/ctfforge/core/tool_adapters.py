"""Thin registry handlers around existing shared core functions."""

from pathlib import Path

from .exceptions import CTFForgeError
from .file_detection import identify_file
from .hashing import hash_file
from .output import make_result
from .strings import extract_strings
from .tool import ToolContext, ToolResult


def _target(context: ToolContext) -> Path:
    value = context.arguments.get("file")
    if not isinstance(value, (str, Path)):
        raise CTFForgeError(
            f"Tool common {context.tool} requires a file path argument named 'file'."
        )
    target = Path(value).expanduser()
    if not target.is_file():
        raise CTFForgeError(f"Target is not a file: {target}")
    return target


def hash_tool(context: ToolContext) -> ToolResult:
    """Return the existing file hashes in the common result envelope."""
    target = _target(context)
    return make_result("common", str(target), hashes=hash_file(target))


def strings_tool(context: ToolContext) -> ToolResult:
    """Return existing printable-string extraction results."""
    target = _target(context)
    return make_result("common", str(target), strings=extract_strings(target))


def identify_tool(context: ToolContext) -> ToolResult:
    """Return the existing signature-based file identification result."""
    target = _target(context)
    return make_result("common", str(target), file_type=identify_file(target))
