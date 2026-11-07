import json
import struct

import pytest

from ctfforge.core.cli import main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.interactive import run_interactive
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext
from ctfforge.reverse.binary_info import analyze as binary_info
from ctfforge.reverse.entropy import analyze as entropy
from ctfforge.reverse.elf import analyze as elf
from ctfforge.reverse.formats import parse_elf, parse_pe
from ctfforge.reverse.pe import analyze as pe
from ctfforge.reverse.strings import analyze as strings, extract
from ctfforge.reverse.symbols import analyze as symbols


def ctx(tool, **arguments):
    return ToolContext("reverse", tool, arguments)


def make_elf(bits=64, endian="<", machine=None):
    machine = machine if machine is not None else (62 if bits == 64 else 3)
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "<" else 2, 1]) + b"\0" * 9
    hfmt = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    phfmt = "IIIIIIII" if bits == 32 else "IIQQQQQQ"
    shfmt = "IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"
    symfmt = "IIIBBH" if bits == 32 else "IBBHQQ"
    header_size = 52 if bits == 32 else 64
    ph_size, sh_size, sym_size = (struct.calcsize(endian + fmt) for fmt in (phfmt, shfmt, symfmt))
    phoff = header_size
    shoff = phoff + ph_size
    shnum = 4
    shstr = b"\0.shstrtab\0.strtab\0.symtab\0"
    strings = b"\0hello_symbol\0"
    shstr_offset = shoff + shnum * sh_size
    str_offset = shstr_offset + len(shstr)
    sym_offset = str_offset + len(strings)
    symbols_data = struct.pack(endian + symfmt, *([0] * (6 if bits == 32 else 6)))
    if bits == 32:
        symbols_data += struct.pack(endian + symfmt, 1, 0x8048000, 12, 0x12, 0, 1)
    else:
        symbols_data += struct.pack(endian + symfmt, 1, 0x12, 0, 1, 0x400000, 12)
    section_rows = [
        (0,) * (10 if bits == 32 else 10),
        (1, 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0),
        (11, 3, 0, 0, str_offset, len(strings), 0, 0, 1, 0),
        (19, 2, 0, 0, sym_offset, len(symbols_data), 2, 1, 4 if bits == 32 else 8, sym_size),
    ]
    sections = b"".join(struct.pack(endian + shfmt, *row) for row in section_rows)
    if bits == 32:
        ph = struct.pack(endian + phfmt, 1, 0, 0, 0, 0, 0, 5, 4)
    else:
        ph = struct.pack(endian + phfmt, 1, 5, 0, 0, 0, 0, 0, 8)
    header = struct.pack(endian + hfmt, 2, machine, 1, 0x8048000 if bits == 32 else 0x400000,
                         phoff, shoff, 0, header_size, ph_size, 1, sh_size, shnum, 1)
    return ident + header + ph + sections + shstr + strings + symbols_data


def make_pe(bits=64, with_symbols=False):
    peoff = 0x80
    optional_size = 240 if bits == 64 else 224
    data = bytearray(0x240 + 0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, peoff)
    data[peoff:peoff + 4] = b"PE\0\0"
    machine = 0x8664 if bits == 64 else 0x14c
    struct.pack_into("<HHIIIHH", data, peoff + 4, machine, 1, 0x12345678, 0, 0, optional_size, 0x2022)
    opt = peoff + 24
    struct.pack_into("<H", data, opt, 0x20b if bits == 64 else 0x10b)
    struct.pack_into("<I", data, opt + 16, 0x1010)
    struct.pack_into("<Q" if bits == 64 else "<I", data, opt + (24 if bits == 64 else 28), 0x140000000 if bits == 64 else 0x400000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<I", data, opt + (108 if bits == 64 else 92), 16)
    if with_symbols:
        directory_offset = 112 if bits == 64 else 96
        struct.pack_into("<II", data, opt + directory_offset, 0x1000, 40)  # export
        struct.pack_into("<II", data, opt + directory_offset + 8, 0x1080, 40)  # import
    section = opt + optional_size
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x240)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    if with_symbols:
        struct.pack_into("<IIHHIIIIIII", data, 0x240, 0, 0, 0, 0, 0x1040, 1, 1, 1,
                         0x1050, 0x1054, 0x1058)
        data[0x280:0x289] = b"demo.dll\0"
        struct.pack_into("<I", data, 0x290, 0x1010)
        struct.pack_into("<I", data, 0x294, 0x1060)
        struct.pack_into("<H", data, 0x298, 0)
        data[0x2a0:0x2a9] = b"Exported\0"
        struct.pack_into("<IIIII", data, 0x2c0, 0x10b0, 0, 0, 0x10a0, 0x10d0)
        data[0x2e0:0x2ed] = b"KERNEL32.dll\0"
        if bits == 64:
            struct.pack_into("<QQ", data, 0x2f0, 0x10e0, 0)
        else:
            struct.pack_into("<II", data, 0x2f0, 0x10e0, 0)
        struct.pack_into("<H", data, 0x320, 0)
        data[0x322:0x32d] = b"ImportFunc\0"
    return bytes(data)


def test_elf32_elf64_endian_architecture_and_sections():
    for bits, endian, machine, expected in ((32, "<", 3, "x86"), (64, ">", 183, "AArch64")):
        result = parse_elf(make_elf(bits, endian, machine))
        assert result["class_bits"] == bits
        assert result["endianness"] == ("little" if endian == "<" else "big")
        assert result["machine"] == expected
        assert result["sections"][1]["name"] == ".shstrtab"
        assert result["program_headers"][0]["flags"] == ["read", "execute"]


def test_elf_symbols_and_bad_signature_and_truncated_tables():
    result = parse_elf(make_elf(64), with_symbols=True)
    assert result["symbols"][0]["name"] == "hello_symbol"
    assert result["symbols"][0]["value"] == 0x400000
    with pytest.raises(CTFForgeError, match="ELF signature"):
        parse_elf(b"not ELF")
    raw = bytearray(make_elf(64))
    struct.pack_into("<Q", raw, 40, len(raw) + 100)  # section table offset
    with pytest.raises(CTFForgeError, match="section header table"):
        parse_elf(bytes(raw))


@pytest.mark.parametrize("bits", [32, 64])
def test_pe32_and_pe32_plus_sections_and_architecture(bits):
    result = parse_pe(make_pe(bits))
    assert result["class_bits"] == bits
    assert result["machine"] == ("x86-64" if bits == 64 else "x86")
    assert result["entry_point_rva"] == 0x1010
    assert result["sections"][0]["permissions"] == ["read", "execute"]


def test_pe_invalid_truncated_wrong_signature_and_symbols_empty(tmp_path):
    for raw in (b"not PE", b"MZ" + b"\0" * 12, bytes(make_pe(32)[:180])):
        with pytest.raises(CTFForgeError):
            parse_pe(raw)
    assert parse_pe(make_pe(64), with_symbols=True)["symbols"]["imports"] == []
    wrong = tmp_path / "unsupported.tmp"
    wrong.write_bytes(b"unknown format")
    try:
        with pytest.raises(CTFForgeError, match="ELF and PE"):
            symbols(ctx("symbols", file=wrong))
    finally:
        wrong.unlink()


@pytest.mark.parametrize("bits", [32, 64])
def test_pe_import_export_symbols(bits):
    result = parse_pe(make_pe(bits, with_symbols=True), with_symbols=True)
    imported = result["symbols"]["imports"][0]
    assert imported["library"] == "KERNEL32.dll"
    assert imported["symbols"][0]["name"] == "ImportFunc"
    exported = result["symbols"]["exports"][0]
    assert exported["name"] == "Exported"
    assert exported["ordinal"] == 1


def test_binary_info_macho_archive_unknown_and_extension_mismatch(tmp_path):
    file = tmp_path / "wrong.exe"
    file.write_bytes(make_elf(64))
    result = binary_info(ctx("info", file=file))
    assert result["format"] == "ELF" and result["extension_mismatch"]
    file.write_bytes(b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x01000007) + b"\0" * 24)
    assert binary_info(ctx("info", file=file))["metadata"]["machine"] == "x86-64"
    file.write_bytes(b"7z\xbc\xaf\x27\x1c")
    assert binary_info(ctx("info", file=file))["format"] == "7-Zip archive"
    file.write_bytes(b"unknown")
    assert binary_info(ctx("info", file=file))["format"] == "Unknown"


def test_strings_encodings_offsets_limits_export_and_no_overwrite(tmp_path):
    source = tmp_path / "strings.bin"
    source.write_bytes(b"\x00hello world\x00\x00\x00" + "wide text".encode("utf-16le"))
    ascii_rows = extract(source.read_bytes(), minimum=4, encoding="ascii", limit=10)
    wide_rows = extract(source.read_bytes(), minimum=4, encoding="utf16le", limit=10)
    assert ascii_rows[0]["offset"] == 1 and ascii_rows[0]["string"] == "hello world"
    assert any(row["string"] == "wide text" and row["offset"] == 15 for row in wide_rows)
    output = tmp_path / "export.txt"
    result = strings(ctx("strings", file=source, min_length=4, encoding="both", limit=2, output=output))
    assert len(result["strings"]) == 2 and output.exists()
    with pytest.raises(CTFForgeError, match="overwrite"):
        strings(ctx("strings", file=source, min_length=4, encoding="ascii", output=output))
    with pytest.raises(CTFForgeError, match="must not overwrite"):
        strings(ctx("strings", file=source, output=source))
    with pytest.raises(CTFForgeError, match="between 1 and 256"):
        extract(b"abcd", minimum=0)


def test_entropy_known_distributions_and_block_offsets(tmp_path):
    path = tmp_path / "entropy.bin"
    path.write_bytes(bytes(range(256)) * 2)
    result = entropy(ctx("entropy", file=path, block_size=256))
    assert result["overall_entropy"] == 8.0
    assert result["blocks"][0]["entropy"] == 8
    assert result["blocks"][1]["entropy"] == 8
    assert result["blocks"][1]["offset"] == 256
    assert "does not prove" in result["warning"]
    path.write_bytes(b"\0" * 512)
    assert entropy(ctx("entropy", file=path, block_size=256))["overall_entropy"] == 0
    with pytest.raises(CTFForgeError, match="Block size"):
        entropy(ctx("entropy", file=path, block_size=1))


def test_cli_registration_registry_and_interactive_tool_listing(tmp_path, capsys):
    registry = build_core_registry()
    assert [spec.name for spec in registry.list_tools("reverse")] == ["disasm", "elf", "entropy", "external-elf", "external-file", "external-objdump", "external-status", "functions", "info", "instructions", "packer", "pe", "strings", "symbols"]
    assert all(spec.interactive_inputs for spec in registry.list_tools("reverse")
               if spec.name != "external-status")
    path = tmp_path / "input.elf"
    path.write_bytes(make_elf(64))
    assert main(["reverse", "info", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "ELF"
    output = []
    choices = iter(["5", "0", "0"])
    run_interactive(registry=registry, input_fn=lambda prompt: next(choices), output=output.append)
    rendered = "\n".join(output)
    assert "[5] Reverse Engineering" in rendered
    assert "[1] disasm —" in rendered and "[14] symbols —" in rendered


def test_all_six_direct_cli_tools(tmp_path, capsys):
    elf_file = tmp_path / "sample.elf"
    elf_file.write_bytes(make_elf(64))
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(make_pe(64))
    assert main(["reverse", "info", "--file", str(elf_file)]) == 0
    capsys.readouterr()
    assert main(["reverse", "strings", "--file", str(elf_file), "--encoding", "ascii"]) == 0
    capsys.readouterr()
    assert main(["reverse", "entropy", "--file", str(elf_file)]) == 0
    capsys.readouterr()
    assert main(["reverse", "elf", "--file", str(elf_file)]) == 0
    capsys.readouterr()
    assert main(["reverse", "pe", "--file", str(pe_file)]) == 0
    capsys.readouterr()
    assert main(["reverse", "symbols", "--file", str(pe_file)]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "PE"


def test_registration_is_lazy_and_export_is_exclusive(tmp_path, monkeypatch):
    import ctfforge.core.registry as registry_module
    registry = build_core_registry()
    original = registry_module.import_module
    seen = []
    def track(module):
        seen.append(module)
        return original(module)
    monkeypatch.setattr(registry_module, "import_module", track)
    registry.list_tools("reverse")
    assert seen == []
    registry.resolve_handler("reverse", "info")
    assert seen == ["ctfforge.reverse.binary_info"]
