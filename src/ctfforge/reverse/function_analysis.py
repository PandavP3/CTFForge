"""Report function metadata present in bounded ELF/PE symbol structures."""
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import MAX_BINARY_BYTES, parse_elf, parse_pe, read_binary


def analyze(context: ToolContext) -> ToolResult:
    path, data = read_binary(context.arguments.get("file"), maximum=MAX_BINARY_BYTES)
    if data.startswith(b"\x7fELF"):
        parsed = parse_elf(data, with_symbols=True)
        funcs = []
        for symbol in parsed["symbols"]:
            if symbol["type"] != 2 or symbol["section_index"] == 0:
                continue
            section_index = symbol["section_index"]
            if section_index >= len(parsed["sections"]):
                continue
            section = parsed["sections"][section_index]
            value = symbol["value"]
            if parsed["type_value"] == 1:
                relative = value
                address = None
            else:
                relative = value - section["address"]
                address = value
            if relative < 0 or relative > section["size"]:
                continue
            size = symbol["size"]
            if size and relative + size > section["size"]:
                continue
            funcs.append({"name": symbol["name"], "address": address, "section": section["name"],
                          "size": size, "file_offset": section["offset"] + relative,
                          "source": symbol["table"]})
        available = bool(funcs)
        warning = None if available else "No usable function symbols were found; stripped binaries may not retain them."
    elif data.startswith(b"MZ"):
        parsed = parse_pe(data, with_symbols=True)
        funcs = []
        for symbol in parsed["symbols"]["exports"]:
            rva = symbol.get("address_rva")
            if rva is None:
                continue
            section = next((row for row in parsed["sections"] if row["virtual_address"] <= rva <
                            row["virtual_address"] + max(row["virtual_size"], row["raw_size"])), None)
            funcs.append({"name": symbol["name"], "ordinal": symbol["ordinal"],
                          "address": parsed["image_base"] + rva, "address_rva": rva,
                          "size": None, "section": section["name"] if section else None,
                          "source": "PE export"})
        available = bool(funcs)
        warning = None if available else "No exported functions were found; PE imports are not function definitions."
    else:
        raise CTFForgeError("Function metadata is supported only for structurally valid ELF and PE files.")
    return make_result("reverse", str(path), tool="functions", format=parsed["format"],
                       functions=funcs[:5000], function_count=len(funcs), metadata_available=available,
                       warning=warning, parser_warnings=parsed.get("warnings", []),
                       note="Only symbol-derived function metadata is reported; boundaries are not guessed.")
