"""Lazy registration for the initial Steganography tools."""

from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import ToolSpec


def register_steg_tools(registry: ToolRegistry) -> None:
    """Register metadata and structure analyzers without loading their handlers."""
    registry.register_category(
        "steg",
        (
            ToolSpec(
                category="steg", name="metadata",
                description="Inspect image dimensions, EXIF, GPS, and text metadata.",
                handler_ref="ctfforge.steg.metadata:analyze",
                optional_dependencies=("PIL",),
                usage="ctfforge steg metadata --file IMAGE",
                help=(
                    "Supports JPEG, PNG, TIFF, and WebP. Install requirements/steg.txt for Pillow."
                ),
            ),
            ToolSpec(
                category="steg", name="structure",
                description=(
                    "Inspect file signatures, image structure, and trailing or embedded data."
                ),
                handler_ref="ctfforge.steg.structure:analyze",
                usage="ctfforge steg structure --file FILE",
                help="Supports bounded structural checks for PNG, JPEG, GIF, PDF, and ZIP.",
            ),
        ),
    )
