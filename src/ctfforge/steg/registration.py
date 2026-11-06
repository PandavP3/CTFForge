"""Lazy registration for Steganography tools."""

from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import ToolSpec


def register_steg_tools(registry: ToolRegistry) -> None:
    """Register Steganography analyzers without loading their handlers."""
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
            ToolSpec(
                category="steg", name="lsb",
                description="Heuristically analyze lossless image channel bit planes for candidate data.",
                handler_ref="ctfforge.steg.lsb:analyze",
                optional_dependencies=("PIL",),
                usage="ctfforge steg lsb --file IMAGE [--channel red|green|blue|alpha|all]",
                help=("Heuristic analysis only. Supports PNG, TIFF, BMP, GIF, and lossless WebP; "
                      "tests independent channels and bit planes 0-7. Pillow is optional."),
            ),
        ),
    )
