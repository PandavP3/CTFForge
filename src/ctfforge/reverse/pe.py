"""Detailed, read-only PE/COFF header and section analysis."""
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import parse_pe, read_binary


def analyze(context: ToolContext) -> ToolResult:
    path, data = read_binary(context.arguments.get("file"))
    result = parse_pe(data)
    return make_result("reverse", str(path), tool="pe", file_size=len(data), **result,
                       note="PE files are parsed as data only and are never loaded or executed.")
