"""Shared bounded ELF and PE structures for the native reverse tools."""
import struct
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError

MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_PROGRAM_HEADERS = 4096
MAX_SECTIONS = 8192
MAX_SYMBOLS = 100_000
MAX_REPORTED_SYMBOLS = 5000

MACHINES = {
    3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM",
    62: "x86-64", 183: "AArch64", 243: "RISC-V",
}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARMv7",
               0xAA64: "AArch64", 0x200: "IA-64", 0x5032: "RISC-V 32",
               0x5064: "RISC-V 64", 0x5128: "RISC-V 128"}


def read_binary(value: object, *, maximum: int = MAX_BINARY_BYTES) -> tuple[Path, bytes]:
    if not isinstance(value, (str, Path)):
        raise CTFForgeError("A binary file path is required.")
    path = Path(value).expanduser()
    try:
        if not path.is_file():
            raise CTFForgeError(f"Input is not a regular file: {path}")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise CTFForgeError(f"Cannot read {path}: {exc}") from exc
    if len(data) > maximum:
        raise CTFForgeError(f"File exceeds the {maximum}-byte processing limit.")
    return path, data


class View:
    """Bounds-checked view over an immutable file byte string."""

    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.endian = endian

    def unpack(self, fmt: str, offset: int):
        size = struct.calcsize(self.endian + fmt)
        if offset < 0 or offset + size > len(self.data):
            raise ValueError("structure lies outside the file")
        return struct.unpack_from(self.endian + fmt, self.data, offset)

    def bytes(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("range lies outside the file")
        return self.data[offset:offset + size]


def _checked_table(offset: int, count: int, entry_size: int, minimum: int, file_size: int, label: str, cap: int):
    if count > cap:
        raise ValueError(f"{label} count exceeds safety limit")
    if count and (entry_size < minimum or offset < 0 or offset + count * entry_size > file_size):
        raise ValueError(f"{label} table is truncated or malformed")


def _cstring(data: bytes, offset: int, limit: int = 4096) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("utf-8", "replace")


def parse_elf(data: bytes, *, with_symbols: bool = False) -> dict:
    if not data.startswith(b"\x7fELF"):
        raise CTFForgeError("Input does not have an ELF signature.")
    if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        raise CTFForgeError("Malformed ELF identification header.")
    bits = 32 if data[4] == 1 else 64
    endian = "<" if data[5] == 1 else ">"
    view = View(data, endian)
    fmt = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    try:
        fields = view.unpack(fmt, 16)
        e_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
        expected_header = 52 if bits == 32 else 64
        if ehsize < expected_header or ehsize > len(data):
            raise ValueError("invalid ELF header size")
        phfmt = "IIIIIIII" if bits == 32 else "IIQQQQQQ"
        shfmt = "IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"
        phmin = struct.calcsize(endian + phfmt)
        shmin = struct.calcsize(endian + shfmt)
        _checked_table(phoff, phnum, phentsize, phmin, len(data), "ELF program header", MAX_PROGRAM_HEADERS)
        _checked_table(shoff, shnum, shentsize, shmin, len(data), "ELF section header", MAX_SECTIONS)
        programs = []
        for index in range(phnum):
            entry_offset = phoff + index * phentsize
            row = view.unpack(phfmt, entry_offset)
            if bits == 32:
                p_type, p_offset, vaddr, paddr, filesz, memsz, pflags, align = row
            else:
                p_type, pflags, p_offset, vaddr, paddr, filesz, memsz, align = row
            if p_offset + filesz > len(data):
                raise ValueError("ELF program segment extends beyond file")
            programs.append({"type": p_type, "offset": p_offset, "virtual_address": vaddr,
                             "file_size": filesz, "memory_size": memsz, "flags": _elf_flags(pflags),
                             "alignment": align})
        raw_sections = []
        for index in range(shnum):
            row = view.unpack(shfmt, shoff + index * shentsize)
            name, stype, sflags, addr, offset, size, link, info, align, entsize = row
            if stype != 8 and offset + size > len(data):
                raise ValueError("ELF section extends beyond file")
            raw_sections.append({"name_offset": name, "type": stype, "flags_value": sflags,
                                 "address": addr, "offset": offset, "size": size, "link": link,
                                 "info": info, "alignment": align, "entry_size": entsize})
        if shnum and shstrndx >= shnum:
            raise ValueError("ELF section-name string table index is invalid")
        name_data = b""
        if shnum and shstrndx:
            name_section = raw_sections[shstrndx]
            name_data = view.bytes(name_section["offset"], name_section["size"])
        sections = []
        for section in raw_sections:
            item = dict(section)
            item["name"] = _cstring(name_data, section["name_offset"], 256)
            item.pop("name_offset")
            item["flags"] = _section_flags(section["flags_value"])
            item.pop("flags_value")
            sections.append(item)
    except (ValueError, struct.error) as exc:
        raise CTFForgeError(f"Malformed or truncated ELF file: {exc}") from exc
    type_names = {1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (shared object or PIE)", 4: "CORE"}
    result = {"format": "ELF", "class_bits": bits,
              "endianness": "little" if endian == "<" else "big", "version": version,
              "type": type_names.get(e_type, f"unknown ({e_type})"), "type_value": e_type,
              "machine": MACHINES.get(machine, f"unknown ({machine})"), "machine_value": machine,
              "entry_point": entry, "flags": flags, "program_headers": programs,
              "sections": sections, "warnings": []}
    if shoff and not shnum:
        result["warnings"].append("Extended ELF section numbering is not supported.")
    if with_symbols:
        result["symbols"] = _elf_symbols(data, view, bits, raw_sections, sections, result["warnings"])
    return result


def _elf_flags(flags: int) -> list[str]:
    return [name for mask, name in ((4, "read"), (2, "write"), (1, "execute")) if flags & mask]


def _section_flags(flags: int) -> list[str]:
    return [name for mask, name in ((1, "write"), (2, "alloc"), (4, "execute"), (0x10, "merge"), (0x20, "strings")) if flags & mask]


def _elf_symbols(data, view, bits, raw_sections, sections, warnings):
    output = []
    scanned = 0
    symfmt = "IIIBBH" if bits == 32 else "IBBHQQ"
    symsize = struct.calcsize(view.endian + symfmt)
    for index, section in enumerate(raw_sections):
        if section["type"] not in (2, 11):
            continue
        ent = section["entry_size"] or symsize
        if ent < symsize or section["size"] % ent or section["size"] // ent > MAX_SYMBOLS:
            warnings.append(f"Symbol table {sections[index]['name']!r} has invalid bounds or entry size.")
            continue
        if section["link"] >= len(raw_sections):
            warnings.append(f"Symbol table {sections[index]['name']!r} has invalid string table link.")
            continue
        strsec = raw_sections[section["link"]]
        if strsec["type"] != 3:
            warnings.append(f"Symbol table {sections[index]['name']!r} does not link to a string table.")
            continue
        strings = data[strsec["offset"]:strsec["offset"] + strsec["size"]]
        count = min(section["size"] // ent, max(0, 200_000 - scanned))
        for n in range(count):
            scanned += 1
            off = section["offset"] + n * ent
            try:
                row = view.unpack(symfmt, off)
                if bits == 32:
                    nameoff, value, size, info, other, shndx = row
                else:
                    nameoff, info, other, shndx, value, size = row
            except (ValueError, struct.error):
                warnings.append("Truncated ELF symbol entry.")
                break
            name = _cstring(strings, nameoff, 1024)
            if name and len(output) < MAX_REPORTED_SYMBOLS:
                output.append({"name": name, "value": value, "size": size,
                               "binding": info >> 4, "type": info & 15,
                               "section_index": shndx, "table": sections[index]["name"],
                               "file_offset": off})
            if len(output) >= MAX_REPORTED_SYMBOLS:
                warnings.append("Symbol output truncated at safety limit.")
                return output
        if scanned >= 200_000:
            warnings.append("ELF symbol scan stopped at its processing limit.")
            break
    return output


def parse_pe(data: bytes, *, with_symbols: bool = False) -> dict:
    if not data.startswith(b"MZ"):
        raise CTFForgeError("Input does not have a DOS MZ signature.")
    if len(data) < 64:
        raise CTFForgeError("Malformed or truncated PE DOS header.")
    pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise CTFForgeError("PE signature is missing or outside the file bounds.")
    try:
        machine, nsections, timestamp, symptr, nsyms, optsize, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
        if nsections > 96:
            raise ValueError("section count exceeds safety limit")
        opt = pe_offset + 24
        if opt + optsize > len(data):
            raise ValueError("optional header is truncated")
        magic = struct.unpack_from("<H", data, opt)[0] if optsize >= 2 else 0
        if magic not in (0x10b, 0x20b):
            raise ValueError("unsupported PE optional-header magic")
        is64 = magic == 0x20b
        minopt = 112 if is64 else 96
        if optsize < minopt:
            raise ValueError("optional header is too short")
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0]
        section_alignment, file_alignment = struct.unpack_from("<II", data, opt + 32)
        size_image, size_headers = struct.unpack_from("<II", data, opt + 56)
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        n_dirs = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]
        dirs_offset = opt + (112 if is64 else 96)
        n_dirs = min(n_dirs, 16, max(0, (optsize - (dirs_offset - opt)) // 8))
        directory_names = ("export", "import", "resource", "exception", "certificate", "base_relocation",
                           "debug", "architecture", "global_pointer", "tls", "load_config", "bound_import",
                           "iat", "delay_import", "clr", "reserved")
        directories = []
        for index in range(n_dirs):
            rva, size = struct.unpack_from("<II", data, dirs_offset + index * 8)
            if rva or size:
                directories.append({"name": directory_names[index], "rva": rva, "size": size})
        section_offset = opt + optsize
        if section_offset + nsections * 40 > len(data):
            raise ValueError("section table is truncated")
        sections = []
        for index in range(nsections):
            off = section_offset + index * 40
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            section_flags = struct.unpack_from("<I", data, off + 36)[0]
            if raw_size and raw_ptr + raw_size > len(data):
                raise ValueError(f"section {name!r} extends beyond file")
            permissions = [label for bit, label in ((0x40000000, "read"), (0x80000000, "write"), (0x20000000, "execute")) if section_flags & bit]
            sections.append({"name": name, "virtual_size": virtual_size, "virtual_address": virtual_addr,
                             "raw_size": raw_size, "raw_offset": raw_ptr,
                             "permissions": permissions, "characteristics": section_flags})
    except (ValueError, struct.error) as exc:
        raise CTFForgeError(f"Malformed or truncated PE file: {exc}") from exc

    def rva_offset(rva: int, size: int = 1):
        if rva < size_headers and rva + size <= len(data):
            return rva
        for section in sections:
            span = max(section["virtual_size"], section["raw_size"])
            delta = rva - section["virtual_address"]
            if 0 <= delta and delta + size <= section["raw_size"] and delta < span:
                pos = section["raw_offset"] + delta
                return pos if pos + size <= len(data) else None
        return None

    result = {"format": "PE", "class_bits": 64 if is64 else 32,
              "endianness": "little", "machine": PE_MACHINES.get(machine, f"unknown (0x{machine:04x})"),
              "machine_value": machine, "timestamp": timestamp, "entry_point_rva": entry,
              "image_base": image_base, "subsystem": subsystem,
              "section_alignment": section_alignment, "file_alignment": file_alignment,
              "size_of_image": size_image, "size_of_headers": size_headers,
              "characteristics": characteristics, "data_directories": directories,
              "sections": sections, "warnings": []}
    if with_symbols:
        result["symbols"] = _pe_symbols(data, result, rva_offset, is64)
    return result


def _pe_symbols(data, info, rva_offset, is64):
    imports, exports, warnings = [], [], info["warnings"]
    total_import_symbols = 0
    dirs = {row["name"]: row for row in info["data_directories"]}
    pointer_size = 8 if is64 else 4
    ordinal_mask = 1 << (pointer_size * 8 - 1)
    imp = dirs.get("import")
    if imp and imp["rva"]:
        if imp["size"] and imp["size"] < 20:
            warnings.append("Import directory is smaller than one descriptor.")
            pos = None
        else:
            pos = rva_offset(imp["rva"], 20)
            if imp["size"] and imp["size"] % 20:
                warnings.append("Import directory size is not a multiple of the descriptor size.")
        if pos is None:
            warnings.append("Import directory RVA does not map to file data.")
        else:
            descriptor_limit = min(4096, max(1, imp["size"] // 20)) if imp["size"] else 4096
            for index in range(descriptor_limit):
                off = pos + index * 20
                if off + 20 > len(data):
                    warnings.append("Import descriptor table is truncated."); break
                original, stamp, chain, name_rva, first = struct.unpack_from("<IIIII", data, off)
                if not (original or stamp or chain or name_rva or first): break
                namepos = rva_offset(name_rva)
                library = _cstring(data, namepos) if namepos is not None else ""
                thunk_rva = original or first
                thunk_pos = rva_offset(thunk_rva, pointer_size)
                symbols = []
                if thunk_pos is None:
                    warnings.append(f"Import thunk for {library or '<unknown library>'} is unmapped.")
                else:
                    for thunk_index in range(min(MAX_REPORTED_SYMBOLS - total_import_symbols,
                                                 max(0, (len(data) - thunk_pos) // pointer_size))):
                        toff = thunk_pos + thunk_index * pointer_size
                        if toff + pointer_size > len(data):
                            warnings.append("Import thunk table is truncated."); break
                        thunk = int.from_bytes(data[toff:toff + pointer_size], "little")
                        if thunk == 0: break
                        if thunk & ordinal_mask:
                            symbol = {"ordinal": thunk & 0xffff}
                        else:
                            sympos = rva_offset(thunk, 3)
                            symbol = {"name": _cstring(data, sympos + 2) if sympos is not None else ""}
                            if sympos is None: warnings.append("Import-by-name RVA is unmapped.")
                        symbol["file_offset"] = toff
                        symbols.append(symbol)
                        total_import_symbols += 1
                        if total_import_symbols >= MAX_REPORTED_SYMBOLS: break
                imports.append({"library": library, "symbols": symbols})
                if total_import_symbols >= MAX_REPORTED_SYMBOLS:
                    warnings.append("Import symbols truncated at safety limit.")
                    break
            else:
                warnings.append("Import descriptor limit reached.")
    exp = dirs.get("export")
    if exp and exp["rva"]:
        pos = rva_offset(exp["rva"], 40)
        if pos is None:
            warnings.append("Export directory RVA does not map to file data.")
        else:
            fields = struct.unpack_from("<IIHHIIIIIII", data, pos)
            _, _, _, _, name_rva, ordinal_base, nfunc, nname, funcs_rva, names_rva, ords_rva = fields
            nfunc, nname = min(nfunc, MAX_SYMBOLS), min(nname, MAX_SYMBOLS)
            names_pos, ords_pos, funcs_pos = rva_offset(names_rva, nname * 4), rva_offset(ords_rva, nname * 2), rva_offset(funcs_rva, nfunc * 4)
            if nname and (names_pos is None or ords_pos is None) or nfunc and funcs_pos is None:
                warnings.append("Export address/name tables are unmapped.")
            else:
                for index in range(min(nname, MAX_REPORTED_SYMBOLS)):
                    name_rva_item = struct.unpack_from("<I", data, names_pos + index * 4)[0]
                    ordinal_index = struct.unpack_from("<H", data, ords_pos + index * 2)[0]
                    name_pos = rva_offset(name_rva_item)
                    address = struct.unpack_from("<I", data, funcs_pos + ordinal_index * 4)[0] if ordinal_index < nfunc else None
                    name = _cstring(data, name_pos) if name_pos is not None else ""
                    if not name:
                        warnings.append("An export name RVA is unmapped or empty.")
                        continue
                    exports.append({"name": name, "ordinal": ordinal_base + ordinal_index,
                                    "address_rva": address})
    return {"imports": imports, "exports": exports, "warnings": warnings}
