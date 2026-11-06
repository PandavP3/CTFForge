"""Lazy registration for native reverse-engineering analyzers."""
from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import InteractiveInput as I, ToolSpec


def register_reverse_tools(registry: ToolRegistry) -> None:
    file_input = I("file", "Binary file path", "path", must_exist=True)
    registry.register_category("reverse", (
        ToolSpec("info", "reverse", "Identify binary formats and summarize architecture metadata.",
                 "ctfforge.reverse.binary_info:analyze", usage="ctfforge reverse info --file FILE",
                 help="Uses signatures and structural checks; supported formats include ELF, PE, Mach-O, and common archives.",
                 interactive_inputs=(file_input,)),
        ToolSpec("strings", "reverse", "Extract bounded printable ASCII and UTF-16LE strings with offsets.",
                 "ctfforge.reverse.strings:analyze",
                 usage="ctfforge reverse strings --file FILE [--min-length 4] [--encoding ascii|utf16le|both] [--limit 10000] [--output FILE]",
                 help="Extracted text is untrusted and is never executed; output files are created exclusively and never overwritten.",
                 interactive_inputs=(file_input,
                                     I("min_length", "Minimum string length", "int", default=4, minimum=1, maximum=256),
                                     I("encoding", "String encoding mode", choices=("ascii", "utf16le", "both"), default="both"),
                                     I("limit", "Maximum strings to return", "int", default=10000, minimum=1, maximum=100000),
                                     I("output", "Optional text export path", "path", required=False))),
        ToolSpec("entropy", "reverse", "Calculate overall and block-based Shannon entropy.",
                 "ctfforge.reverse.entropy:analyze", usage="ctfforge reverse entropy --file FILE [--block-size 4096]",
                 help="High entropy may indicate compression or encryption but is not proof.",
                 interactive_inputs=(file_input,
                                     I("block_size", "Block size in bytes", "int", default=4096, minimum=256, maximum=1048576))),
        ToolSpec("elf", "reverse", "Inspect ELF headers, program headers, sections, and section names.",
                 "ctfforge.reverse.elf:analyze", usage="ctfforge reverse elf --file FILE",
                 help="Supports ELF32/ELF64 and little/big endian headers; binaries are never executed.",
                 interactive_inputs=(file_input,)),
        ToolSpec("pe", "reverse", "Inspect PE/COFF headers, optional header, directories, and sections.",
                 "ctfforge.reverse.pe:analyze", usage="ctfforge reverse pe --file FILE",
                 help="Supports PE32 and PE32+; binaries are never executed.",
                 interactive_inputs=(file_input,)),
        ToolSpec("symbols", "reverse", "Inspect ELF symbol tables and PE import/export directories.",
                 "ctfforge.reverse.symbols:analyze", usage="ctfforge reverse symbols --file FILE",
                 help="Reports only symbols present in bounded ELF/PE structures; no symbol information is invented.",
                 interactive_inputs=(file_input,)),
    ))
