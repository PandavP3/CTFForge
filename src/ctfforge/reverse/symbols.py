"""Bounded PE import/export and ELF symbol-table inspection."""
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import parse_elf, parse_pe, read_binary


def analyze(context: ToolContext) -> ToolResult:
    path, data = read_binary(context.arguments.get("file"))
    if data.startswith(b"\x7fELF"):
        parsed = parse_elf(data, with_symbols=True)
        symbols = {"format": "ELF", "entries": parsed.pop("symbols"), "warnings": parsed["warnings"],
                   "tables": [section["name"] for section in parsed["sections"] if section["type"] in (2, 11)]}
    elif data.startswith(b"MZ"):
        parsed = parse_pe(data, with_symbols=True)
        symbols = {"format": "PE", **parsed.pop("symbols")}
    else:
        raise CTFForgeError("Import/export analysis supports structurally valid ELF and PE files only.")
    return make_result("reverse", str(path), tool="symbols", file_size=len(data), **symbols,
                       note="Only symbol structures present in the file are reported; stripped or unavailable symbols are not inferred.")
