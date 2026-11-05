"""Registration for existing shared core operations."""

from .registry import ToolRegistry
from .tool import ToolSpec


def register_core_tools(registry: ToolRegistry) -> None:
    """Add existing hash, strings, and file-identification operations."""
    registry.register_category(
        "common",
        (
            ToolSpec(
                category="common",
                name="hash",
                description="Calculate MD5, SHA1, and SHA256 hashes for a file.",
                handler_ref="ctfforge.core.tool_adapters:hash_tool",
                usage="ctfforge hash FILE",
            ),
            ToolSpec(
                category="common",
                name="strings",
                description="Extract printable ASCII strings from a file.",
                handler_ref="ctfforge.core.tool_adapters:strings_tool",
                usage="ctfforge strings FILE",
            ),
            ToolSpec(
                category="common",
                name="identify",
                description="Identify a file from its leading signature bytes.",
                handler_ref="ctfforge.core.tool_adapters:identify_tool",
            ),
        ),
    )


def build_core_registry() -> ToolRegistry:
    """Return a fresh registry containing implemented shared and category tools."""
    registry = ToolRegistry()
    register_core_tools(registry)
    from ctfforge.crypto.registration import register_crypto_tools
    from ctfforge.steg.registration import register_steg_tools

    register_crypto_tools(registry)
    register_steg_tools(registry)
    return registry
