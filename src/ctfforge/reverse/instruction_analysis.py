"""Bounded aggregate analysis over the shared Capstone decoder."""
from collections import Counter

from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .disassembly import MAX_DETAIL_INSTRUCTIONS, _export, _options, decode_file


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    decoded = decode_file(args.get("file"), **_options(context))
    records = decoded["instructions"]
    counts = Counter(row["mnemonic"] for row in records)
    groups = Counter(group for row in records for group in row["groups"])
    conditional = sum(1 for row in records if "jump" in row["groups"] and row["mnemonic"] not in
                      {"jmp", "jmpq", "b", "br", "bx", "jr", "j", "jrcxz", "loop"})
    result = make_result("reverse", decoded["path"], tool="instructions",
                         architecture=decoded["architecture"], bits=decoded["bits"],
                         instruction_count=len(records), unique_mnemonics=len(counts),
                         mnemonic_frequency=[{"mnemonic": name, "count": count}
                                             for name, count in counts.most_common(100)],
                         calls=groups["call"], jumps=groups["jump"], conditional_branches=conditional,
                         returns=groups["return"], decoded_bytes=decoded["decoded_bytes"],
                         undecoded_or_unprocessed_bytes=decoded["undecoded_or_unprocessed_bytes"],
                         instruction_limit_reached=decoded["instruction_limit_reached"],
                         note="Static decoded instruction counts do not establish program behavior.")
    if args.get("details"):
        result["instructions"] = records[:MAX_DETAIL_INSTRUCTIONS]
        result["details_truncated"] = len(records) > MAX_DETAIL_INSTRUCTIONS
    exported = _export(args.get("output"), decoded["path"], result)
    if exported:
        result["output_file"] = exported
    return result
