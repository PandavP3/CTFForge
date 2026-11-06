"""Lazy registration for Steganography tools."""

from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import InteractiveInput as I, ToolSpec


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
                interactive_inputs=(I("file", "Image file path", "path", must_exist=True),),
            ),
            ToolSpec(
                category="steg", name="structure",
                description=(
                    "Inspect file signatures, image structure, and trailing or embedded data."
                ),
                handler_ref="ctfforge.steg.structure:analyze",
                usage="ctfforge steg structure --file FILE",
                help="Supports bounded structural checks for PNG, JPEG, GIF, PDF, and ZIP.",
                interactive_inputs=(I("file", "File path", "path", must_exist=True),),
            ),
            ToolSpec(
                category="steg", name="lsb",
                description="Heuristically analyze lossless image channel bit planes for candidate data.",
                handler_ref="ctfforge.steg.lsb:analyze",
                optional_dependencies=("PIL",),
                usage="ctfforge steg lsb --file IMAGE [--channel red|green|blue|alpha|all]",
                help=("Heuristic analysis only. Supports PNG, TIFF, BMP, GIF, and lossless WebP; "
                      "tests independent channels and bit planes 0-7. Pillow is optional."),
                interactive_inputs=(
                    I("file", "Image file path", "path", must_exist=True),
                    I("channel", "Channel", choices=("red", "green", "blue", "alpha", "all"), default="all"),
                    I("bit_plane", "Bit plane (0-7)", "int", default=0, minimum=0, maximum=7),
                    I("bit_order", "Bit packing order", choices=("msb", "lsb"), default="msb"),
                    I("output", "Optional output file path", "path", required=False),
                    I("text", "Include extracted text? (yes/no)", "bool", default=False),
                ),
            ),
        ),
    )
