"""Lazy registration for the implemented Crypto tools."""

from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import ToolSpec


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
            ),
            ToolSpec(
                category="crypto", name="hashid",
                description="Heuristically identify common digest and password-hash formats.",
                handler_ref="ctfforge.crypto.hashid:identify",
                usage="ctfforge crypto hashid (--input HASH | --file FILE)",
                help="Identification is structural and heuristic; no cracking is performed.",
            ),
        ),
    )
