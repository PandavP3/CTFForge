"""Signature and structure based binary identification."""
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import parse_elf, parse_pe, read_binary

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64),
}
MACH_CPU = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000c: "AArch64", 18: "PowerPC"}
SIGNATURES = (
    (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "ZIP archive"),
    (b"\x1f\x8b", "Gzip archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"), (b"\xfd7zXZ\x00", "XZ archive"),
    (b"BZh", "Bzip2 archive"), (b"!<arch>\n", "ar archive"),
    (b"SQLite format 3\x00", "SQLite database"), (b"\x00asm", "WebAssembly module"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary"),
    (b"\xca\xfe\xba\xbf", "Mach-O universal binary (64-bit)")
)
EXTENSIONS = {".elf": "ELF", ".so": "ELF", ".o": "ELF", ".exe": "PE", ".dll": "PE",
              ".sys": "PE", ".dylib": "Mach-O", ".app": "Mach-O", ".zip": "ZIP archive",
              ".gz": "Gzip archive", ".7z": "7-Zip archive", ".rar": "RAR archive",
              ".xz": "XZ archive", ".bz2": "Bzip2 archive", ".a": "ar archive"}


def identify(data: bytes):
    if data.startswith(b"\x7fELF"):
        info = parse_elf(data)
        return "ELF", {key: info[key] for key in ("class_bits", "endianness", "machine", "type", "entry_point")}
    if data.startswith(b"MZ"):
        info = parse_pe(data)
        return "PE", {key: info[key] for key in ("class_bits", "endianness", "machine", "entry_point_rva", "image_base")}
    if data[:4] in MACHO_MAGICS:
        endian, bits = MACHO_MAGICS[data[:4]]
        if len(data) < (28 if bits == 32 else 32):
            raise CTFForgeError("Mach-O header is truncated.")
        cpu = int.from_bytes(data[4:8], "little" if endian == "<" else "big")
        return "Mach-O", {"class_bits": bits, "endianness": "little" if endian == "<" else "big",
                           "machine": MACH_CPU.get(cpu, f"unknown (0x{cpu:x})")}
    if data.startswith((b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca")):
        return "Mach-O universal binary", {"note": "Fat header recognized; slice table not parsed."}
    for signature, label in SIGNATURES:
        if data.startswith(signature):
            return label, {}
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "TAR archive", {}
    if data.startswith(b"\x00\x01\x00\x00"):
        return "TrueType font", {}
    return "Unknown", {}


def analyze(context: ToolContext) -> ToolResult:
    path, data = read_binary(context.arguments.get("file"))
    fmt, details = identify(data)
    extension = path.suffix.lower()
    expected = EXTENSIONS.get(extension)
    mismatch = bool(expected and fmt != expected and not (expected == "Mach-O" and fmt == "Mach-O"))
    findings = []
    if mismatch:
        findings.append({"severity": "info", "message": f"Extension suggests {expected}, while signature/structure indicates {fmt}."})
    if fmt == "Unknown":
        findings.append({"severity": "info", "message": "No supported format signature matched; format remains unknown."})
    return make_result("reverse", str(path), tool="info", file_size=len(data), format=fmt,
                       extension=extension or None, expected_format=expected, extension_mismatch=mismatch,
                       metadata=details, findings=findings,
                       note="Identification uses file signatures and structural validation where supported; extensions are only a comparison hint.")
