"""Lazy registration for the implemented Crypto tools."""

from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import InteractiveInput as I, ToolSpec


def register_crypto_tools(registry: ToolRegistry) -> None:
    """Register Crypto metadata without importing implementation modules."""
    registry.register_category(
        "crypto",
        (
            ToolSpec(
                category="crypto", name="xor",
                description="Analyze single-byte, known-key, and repeating-key XOR data.",
                handler_ref="ctfforge.crypto.xor:analyze",
                usage="ctfforge crypto xor (--file FILE | --input TEXT | --hex HEX) [--key BYTE | --repeat-key KEY]",
                help="Without a key, rank likely single-byte XOR plaintexts. Input is bounded to 16 MiB.",
                interactive_inputs=(
                    I("file", "Input file path (leave blank if using another input)", "path", required=False, group="source", group_rule="exactly_one", must_exist=True),
                    I("input", "Text input (leave blank if using another input)", required=False, group="source", group_rule="exactly_one"),
                    I("hex", "Hex input (leave blank if using another input)", required=False, group="source", group_rule="exactly_one"),
                    I("key", "Optional one-byte XOR key", required=False),
                    I("repeat_key", "Optional repeating XOR key", required=False),
                    I("limit", "Number of candidates to display", "int", default=10, minimum=1, maximum=256),
                ),
            ),
            ToolSpec(
                category="crypto", name="hashid",
                description="Heuristically identify common digest and password-hash formats.",
                handler_ref="ctfforge.crypto.hashid:identify",
                usage="ctfforge crypto hashid (--input HASH | --file FILE)",
                help="Identification is structural and heuristic; no cracking is performed.",
                interactive_inputs=(
                    I("file", "Hash file path (leave blank if using direct input)", "path", required=False, group="source", group_rule="exactly_one", must_exist=True),
                    I("input", "Hash text (leave blank if using a file)", required=False, group="source", group_rule="exactly_one"),
                ),
            ),
        ),
    )
