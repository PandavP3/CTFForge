"""Shared bounded Capstone setup, architecture resolution, and static decoding."""
import importlib
import json
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import MAX_BINARY_BYTES, MACHINES, PE_MACHINES, parse_elf, parse_pe, read_binary

MAX_DISASSEMBLY_BYTES = 1024 * 1024
MAX_INSTRUCTIONS = 10_000
MAX_DETAIL_INSTRUCTIONS = 2_000
MAX_EXPORT_BYTES = 8 * 1024 * 1024
ARCHITECTURES = ("x86", "arm", "arm64", "mips")


def _format_metadata(data: bytes):
    try:
        if data.startswith(b"\x7fELF"):
            info = parse_elf(data)
            machine = info["machine"]
            arch = {"x86": "x86", "x86-64": "x86", "ARM": "arm",
                    "AArch64": "arm64", "MIPS": "mips"}.get(machine)
            return {"format": "ELF", "arch": arch, "bits": info["class_bits"],
                    "endian": info["endianness"], "metadata": info}
        if data.startswith(b"MZ"):
            info = parse_pe(data)
            machine = info["machine"]
            arch = {"x86": "x86", "x86-64": "x86", "ARM": "arm", "ARMv7": "arm",
                    "AArch64": "arm64"}.get(machine)
            return {"format": "PE", "arch": arch, "bits": info["class_bits"],
                    "endian": "little", "metadata": info}
    except CTFForgeError:
        return None
    return None


def _resolve_mode(data: bytes, args: dict):
    detected = _format_metadata(data)
    arch = args.get("arch") or (detected or {}).get("arch")
    if arch not in ARCHITECTURES:
        raise CTFForgeError("Architecture is unknown. Specify --arch x86|arm|arm64|mips for raw binaries.")
    bits = args.get("bits") or (detected or {}).get("bits")
    if bits not in (16, 32, 64):
        raise CTFForgeError("Bitness is unknown. Specify --bits 16, 32, or 64.")
    if detected and detected.get("arch"):
        if arch != detected["arch"] or bits != detected["bits"]:
            raise CTFForgeError(
                f"Explicit architecture/bitness ({arch}/{bits}) conflicts with detected "
                f"{detected['format']} metadata ({detected['arch']}/{detected['bits']})."
            )
    endian = args.get("endian") or (detected or {}).get("endian")
    if arch == "x86":
        if bits not in (16, 32, 64):
            raise CTFForgeError("x86 bitness must be 16, 32, or 64.")
        if endian not in (None, "little"):
            raise CTFForgeError("x86 instructions use little-endian encoding.")
        endian = "little"
        if args.get("mode") is not None:
            raise CTFForgeError("--mode applies to ARM or MIPS, not x86.")
    elif arch == "arm":
        if bits != 32:
            raise CTFForgeError("ARM mode requires 32-bit input; use arm64 for AArch64.")
        arm_mode = args.get("mode")
        if arm_mode not in ("arm", "thumb"):
            raise CTFForgeError("Specify --mode arm or --mode thumb; the instruction mode is not guessed.")
        if endian not in ("little", "big"):
            raise CTFForgeError("Specify endianness for ARM input or use a file with reliable metadata.")
    elif arch == "arm64":
        if bits != 64:
            raise CTFForgeError("ARM64/AArch64 mode requires 64-bit input.")
        if endian not in ("little", "big"):
            raise CTFForgeError("Specify endianness for raw ARM64 input.")
        if args.get("mode") is not None:
            raise CTFForgeError("ARM64 uses a fixed instruction mode; omit --mode.")
    else:
        if bits not in (32, 64):
            raise CTFForgeError("MIPS mode supports 32-bit or 64-bit input.")
        if endian not in ("little", "big"):
            raise CTFForgeError("Specify endianness for MIPS input or use a file with reliable metadata.")
        selected_mode = args.get("mode")
        if selected_mode not in (None, "mips32", "mips64"):
            raise CTFForgeError("MIPS mode must be mips32 or mips64.")
        if selected_mode and selected_mode != f"mips{bits}":
            raise CTFForgeError("MIPS mode must match the selected bitness.")
    return {"arch": arch, "bits": bits, "endian": endian, "mode": args.get("mode"),
            "detected": detected}


def _capstone_mode(capstone, config):
    try:
        arch = config["arch"]
        if arch == "x86":
            arch_id = capstone.CS_ARCH_X86
            mode = {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32,
                    64: capstone.CS_MODE_64}[config["bits"]]
        elif arch == "arm":
            arch_id = capstone.CS_ARCH_ARM
            mode = capstone.CS_MODE_ARM if config["mode"] == "arm" else capstone.CS_MODE_THUMB
        elif arch == "arm64":
            arch_id = capstone.CS_ARCH_ARM64
            mode = 0
        else:
            arch_id = capstone.CS_ARCH_MIPS
            mode = capstone.CS_MODE_MIPS32 if config["bits"] == 32 else capstone.CS_MODE_MIPS64
        if config["endian"] == "big":
            mode |= capstone.CS_MODE_BIG_ENDIAN
    except (AttributeError, KeyError) as exc:
        raise CTFForgeError("Installed Capstone version does not support the requested architecture or mode.") from exc
    return arch_id, mode


def _virtual_address(detected, file_offset: int) -> int:
    if not detected:
        return file_offset
    info = detected["metadata"]
    if detected["format"] == "ELF":
        for segment in info["program_headers"]:
            if segment["offset"] <= file_offset < segment["offset"] + segment["file_size"]:
                return segment["virtual_address"] + file_offset - segment["offset"]
        for section in info["sections"]:
            if section["offset"] <= file_offset < section["offset"] + section["size"]:
                return section["address"] + file_offset - section["offset"]
    else:
        for section in info["sections"]:
            if section["raw_offset"] <= file_offset < section["raw_offset"] + section["raw_size"]:
                rva = section["virtual_address"] + file_offset - section["raw_offset"]
                return info["image_base"] + rva
    return None


def decode_file(path_value, *, arch=None, bits=None, endian=None, mode=None, offset=0,
                address=None, max_bytes=4096, max_instructions=1000):
    """Decode one bounded byte range; no execution or memory mapping occurs."""
    path, data = read_binary(path_value, maximum=MAX_BINARY_BYTES)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > len(data):
        raise CTFForgeError("File offset must be between zero and the file size.")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_DISASSEMBLY_BYTES:
        raise CTFForgeError(f"Byte limit must be between 1 and {MAX_DISASSEMBLY_BYTES}.")
    if (isinstance(max_instructions, bool) or not isinstance(max_instructions, int)
            or not 1 <= max_instructions <= MAX_INSTRUCTIONS):
        raise CTFForgeError(f"Instruction limit must be between 1 and {MAX_INSTRUCTIONS}.")
    config = _resolve_mode(data, {"arch": arch, "bits": bits, "endian": endian, "mode": mode})
    try:
        capstone = importlib.import_module("capstone")
    except ModuleNotFoundError as exc:
        if exc.name == "capstone" or (exc.name and exc.name.startswith("capstone.")):
            raise CTFForgeError(
                "Capstone is optional and is required for disassembly. Install it with: "
                "python -m pip install -r requirements/reverse.txt"
            ) from exc
        raise
    arch_id, mode_id = _capstone_mode(capstone, config)
    source = data[offset:offset + max_bytes]
    explicit_address = address is not None
    if address is None:
        address = _virtual_address(config["detected"], offset)
        if address is None:
            address = offset
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address <= 0xFFFFFFFFFFFFFFFF:
        raise CTFForgeError("Virtual address must be an unsigned 64-bit integer.")
    try:
        engine = capstone.Cs(arch_id, mode_id)
        engine.detail = True
        decoded = list(engine.disasm(source, address, count=max_instructions))
    except Exception as exc:
        raise CTFForgeError(f"Capstone could not decode this range: {exc}") from exc
    records = []
    decoded_bytes = 0
    for instruction in decoded[:max_instructions]:
        size = int(instruction.size)
        if size <= 0 or decoded_bytes + size > len(source):
            break
        records.append({"address": int(instruction.address), "file_offset": offset + decoded_bytes,
                        "bytes": bytes(instruction.bytes).hex(), "mnemonic": instruction.mnemonic,
                        "operands": instruction.op_str, "size": size,
                        "groups": _instruction_groups(instruction, capstone)})
        decoded_bytes += size
    limit_reached = len(records) >= max_instructions and decoded_bytes < len(source)
    stop_reason = ("empty_input" if not source else "instruction_limit" if limit_reached else
                   "decoder_stopped_with_remaining_bytes" if decoded_bytes < len(source) else "range_exhausted")
    return {"path": str(path), "architecture": config["arch"], "bits": config["bits"],
            "endianness": config["endian"], "mode": config["mode"],
            "file_offset": offset, "virtual_address": address,
            "bytes_requested": max_bytes, "bytes_read": len(source),
            "instruction_limit": max_instructions, "instructions": records,
            "instruction_count": len(records), "decoded_bytes": decoded_bytes,
            "undecoded_or_unprocessed_bytes": len(source) - decoded_bytes,
            "first_unprocessed_file_offset": offset + decoded_bytes if decoded_bytes < len(source) else None,
            "instruction_limit_reached": limit_reached,
            "unprocessed_reason": stop_reason,
            "address_basis": "explicit virtual address" if explicit_address else
            "detected file mapping" if config["detected"] and _virtual_address(config["detected"], offset) is not None
            else "file offset"}


def _instruction_groups(instruction, capstone):
    groups = set()
    for name, label in (("CS_GRP_CALL", "call"), ("CS_GRP_JUMP", "jump"), ("CS_GRP_RET", "return")):
        group = getattr(capstone, name, None)
        if group is not None:
            try:
                if instruction.group(group):
                    groups.add(label)
            except (AttributeError, TypeError):
                pass
    return sorted(groups)


def _export(path_value, source_path: str, result: dict) -> str | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        if path.resolve() == Path(source_path).resolve():
            raise CTFForgeError("Export path must not overwrite the analyzed input file.")
        payload = json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
        if len(payload) > MAX_EXPORT_BYTES:
            raise CTFForgeError(f"JSON export exceeds {MAX_EXPORT_BYTES} bytes.")
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise CTFForgeError(f"Refusing to overwrite existing export file: {path}") from exc
    except OSError as exc:
        raise CTFForgeError(f"Cannot write export {path}: {exc}") from exc
    return str(path)


def _options(context):
    args = context.arguments
    return {"arch": args.get("arch"), "bits": args.get("bits"), "endian": args.get("endian"),
            "mode": args.get("mode"), "offset": args.get("offset", 0),
            "address": args.get("address"), "max_bytes": args.get("max_bytes", 4096),
            "max_instructions": args.get("max_instructions", 1000)}


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    decoded = decode_file(args.get("file"), **_options(context))
    result = make_result("reverse", decoded["path"], tool="disasm", **decoded,
                         note="Static decoding only; undecoded/unprocessed bytes are not interpreted or executed.")
    exported = _export(args.get("output"), decoded["path"], result)
    if exported:
        result["output_file"] = exported
    return result
