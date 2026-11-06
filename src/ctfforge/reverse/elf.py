"""Detailed, read-only ELF header and table analysis."""
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import parse_elf, read_binary


def analyze(context: ToolContext) -> ToolResult:
    path, data = read_binary(context.arguments.get("file"))
    result = parse_elf(data)
    return make_result("reverse", str(path), tool="elf", file_size=len(data), **result,
                       note="ELF files are parsed as data only and are never loaded or executed.")
