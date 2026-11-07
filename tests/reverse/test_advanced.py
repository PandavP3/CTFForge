import json
import struct
import sys
import types

import pytest

from ctfforge.core.cli import main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.interactive import run_interactive
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext
from ctfforge.reverse.disassembly import analyze as disasm, decode_file
from ctfforge.reverse.formats import parse_elf
from ctfforge.reverse.function_analysis import analyze as functions
from ctfforge.reverse.instruction_analysis import analyze as instructions
from ctfforge.reverse.packer_detection import analyze as packer
from test_reverse import make_elf, make_pe


def ctx(name, **args):
    return ToolContext("reverse", name, args)


class FakeInsn:
    def __init__(self, address, raw, mnemonic, groups=()):
        self.address, self.bytes, self.mnemonic = address, raw, mnemonic
        self.op_str, self.size, self._groups = "", len(raw), set(groups)

    def group(self, item):
        return item in self._groups


def fake_capstone(monkeypatch):
    module = types.SimpleNamespace(CS_ARCH_X86=1, CS_ARCH_ARM=2, CS_ARCH_ARM64=3,
        CS_ARCH_MIPS=4, CS_MODE_16=16, CS_MODE_32=32, CS_MODE_64=64,
        CS_MODE_ARM=0, CS_MODE_THUMB=1, CS_MODE_MIPS32=32, CS_MODE_MIPS64=64,
        CS_MODE_BIG_ENDIAN=0x80000000, CS_GRP_CALL=1, CS_GRP_JUMP=2, CS_GRP_RET=3)
    class Cs:
        def __init__(self, arch, mode):
            self.arch, self.mode, self.detail = arch, mode, False
            module.last_instance = self
        def disasm(self, data, address, count=0):
            rows, pos = [], 0
            while pos < len(data) and len(rows) < count:
                opcode = data[pos]
                size, name, groups = {
                    0x90: (1, "nop", ()), 0xe8: (5, "call", (1,)),
                    0xeb: (2, "jmp", (2,)), 0x74: (2, "je", (2,)),
                    0xc3: (1, "ret", (3,)),
                }.get(opcode, (0, "", ()))
                if not size or pos + size > len(data):
                    break
                rows.append(FakeInsn(address + pos, data[pos:pos + size], name, groups))
                pos += size
            return iter(rows)
    module.Cs = Cs
    monkeypatch.setitem(sys.modules, "capstone", module)
    return module


def test_disassembly_raw_offsets_limits_groups_and_analysis(tmp_path, monkeypatch):
    fake_capstone(monkeypatch)
    path = tmp_path / "raw.bin"
    path.write_bytes(bytes([0x90, 0xe8, 0, 0, 0, 0, 0xeb, 0, 0x74, 0, 0xc3, 0x90]))
    decoded = decode_file(path, arch="x86", bits=32, offset=1, address=0x401000,
                          max_bytes=8, max_instructions=2)
    assert [row["mnemonic"] for row in decoded["instructions"]] == ["call", "jmp"]
    assert decoded["instructions"][0]["address"] == 0x401000
    assert decoded["instructions"][0]["file_offset"] == 1
    assert decoded["bytes_read"] == 8 and decoded["instruction_limit_reached"] is True
    result = instructions(ctx("instructions", file=path, arch="x86", bits=32,
                              max_bytes=12, max_instructions=20, details=True))
    assert result["instruction_count"] == 6
    assert result["calls"] == result["returns"] == 1
    assert result["jumps"] == 2
    assert result["conditional_branches"] == 1
    assert result["mnemonic_frequency"][0] == {"mnemonic": "nop", "count": 2}
    assert result["undecoded_or_unprocessed_bytes"] == 0


def test_disassembly_arch_validation_empty_truncated_and_missing_capstone(tmp_path, monkeypatch):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    fake_capstone(monkeypatch)
    with pytest.raises(CTFForgeError, match="Specify --arch"):
        decode_file(path)
    with pytest.raises(CTFForgeError, match="Specify --mode"):
        decode_file(path, arch="arm", bits=32, endian="little")
    with pytest.raises(CTFForgeError, match="between 1 and"):
        decode_file(path, arch="x86", bits=32, max_bytes=0)
    decoded = decode_file(path, arch="x86", bits=32)
    assert decoded["instruction_count"] == 0
    monkeypatch.delitem(sys.modules, "capstone")
    monkeypatch.setattr("ctfforge.reverse.disassembly.importlib.import_module",
                        lambda name: (_ for _ in ()).throw(ModuleNotFoundError("missing", name="capstone")))
    with pytest.raises(CTFForgeError, match="requirements/reverse.txt"):
        decode_file(path, arch="x86", bits=32)


@pytest.mark.parametrize(("arch", "bits", "endian", "mode", "expected_arch", "expected_mode"), [
    ("arm", 32, "little", "arm", 2, 0),
    ("arm", 32, "big", "thumb", 2, 0x80000001),
    ("arm64", 64, "little", None, 3, 0),
    ("arm64", 64, "big", None, 3, 0x80000000),
    ("mips", 32, "little", "mips32", 4, 32),
    ("mips", 64, "big", "mips64", 4, 0x80000040),
])
def test_disassembly_non_x86_mode_resolution(tmp_path, monkeypatch, arch, bits, endian, mode,
                                            expected_arch, expected_mode):
    fake_capstone(monkeypatch)
    path = tmp_path / "code.bin"
    path.write_bytes(b"\x90")
    result = decode_file(path, arch=arch, bits=bits, endian=endian, mode=mode)
    assert result["architecture"] == arch and result["endianness"] == endian
    # Fake Capstone exposes the chosen mode for validation without the optional package.
    engine = sys.modules["capstone"].last_instance
    assert (engine.arch, engine.mode) == (expected_arch, expected_mode)
    assert result["instruction_count"] == 1


def test_disassembly_real_capstone_architectures_when_installed(tmp_path):
    capstone = pytest.importorskip("capstone")
    path = tmp_path / "nop.bin"
    path.write_bytes(b"\x90\xc3")
    result = decode_file(path, arch="x86", bits=64)
    assert [item["mnemonic"] for item in result["instructions"]] == ["nop", "ret"]
    assert capstone.CS_ARCH_X86


def test_functions_elf_symbols_pe_exports_and_stripped(tmp_path):
    elf = tmp_path / "symbol.elf"
    elf_data = bytearray(make_elf())
    elf_symbols = parse_elf(bytes(elf_data), with_symbols=True)["symbols"]
    symbol_offset = elf_symbols[0]["file_offset"]
    struct.pack_into("<IBBHQQ", elf_data, symbol_offset, 1, 0x12, 0, 3, 0, 12)
    elf.write_bytes(elf_data)
    result = functions(ctx("functions", file=elf))
    assert result["function_count"] == 1
    assert result["functions"][0]["name"] == "hello_symbol"
    pe = tmp_path / "export.exe"
    pe.write_bytes(make_pe(64, with_symbols=True))
    result = functions(ctx("functions", file=pe))
    assert result["functions"][0]["name"] == "Exported"
    assert result["functions"][0]["source"] == "PE export"
    stripped = tmp_path / "stripped.elf"
    raw = bytearray(make_elf())
    struct.pack_into("<H", raw, 60, 0)  # section count -> parser reports no symbols
    stripped.write_bytes(raw)
    result = functions(ctx("functions", file=stripped))
    assert not result["metadata_available"]
    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"plain data")
    with pytest.raises(CTFForgeError, match="ELF and PE"):
        functions(ctx("functions", file=unknown))


def test_packer_signatures_section_indicators_and_cautious_unknown(tmp_path):
    pe = tmp_path / "upx.exe"
    raw = bytearray(make_pe())
    raw[0x250:0x254] = b"UPX!"
    pe.write_bytes(raw)
    result = packer(ctx("packer", file=pe))
    assert any(row["kind"] == "known_signature" for row in result["indicators"])
    assert result["format"] == "PE"
    unknown = tmp_path / "random.bin"
    unknown.write_bytes(b"UPX!" + bytes(range(256)) * 4)
    result = packer(ctx("packer", file=unknown))
    assert result["format"] == "unknown"
    assert "do not establish" in result["note"]
    assert "only raw known-signature" in result["summary"]


def test_registry_cli_interactive_registration_and_export_safety(tmp_path, monkeypatch, capsys):
    fake_capstone(monkeypatch)
    registry = build_core_registry()
    names = {item.name for item in registry.list_tools("reverse")}
    assert {"disasm", "instructions", "functions", "packer"} <= names
    assert all(registry.get_tool("reverse", name).interactive_inputs
               for name in names if name not in ("external-status", "yara-status"))
    sample = tmp_path / "raw.bin"
    sample.write_bytes(b"\x90\xc3")
    assert main(["reverse", "disasm", "--file", str(sample), "--arch", "x86", "--bits", "64"]) == 0
    assert json.loads(capsys.readouterr().out)["instruction_count"] == 2
    assert main(["reverse", "instructions", "--file", str(sample), "--arch", "x86", "--bits", "64"]) == 0
    assert json.loads(capsys.readouterr().out)["instruction_count"] == 2
    assert main(["reverse", "functions", "--file", str(sample)]) == 2
    capsys.readouterr()
    output = []
    answers = iter(["5", "1", str(sample), "x86", "64", "", "", "0", "", "4096", "1000", "", "0", "0"])
    run_interactive(registry=registry, input_fn=lambda prompt: next(answers), output=output.append)
    assert "Disassembly" in "\n".join(output) or "disasm" in "\n".join(output)


def test_exclusive_json_export_never_overwrites_input(tmp_path, monkeypatch):
    fake_capstone(monkeypatch)
    source = tmp_path / "raw.bin"
    source.write_bytes(b"\x90")
    output = tmp_path / "out.json"
    result = disasm(ctx("disasm", file=source, arch="x86", bits=32, output=output))
    assert output.exists() and json.loads(output.read_text())["instruction_count"] == 1
    with pytest.raises(CTFForgeError, match="Refusing to overwrite"):
        disasm(ctx("disasm", file=source, arch="x86", bits=32, output=output))
    with pytest.raises(CTFForgeError, match="must not overwrite"):
        disasm(ctx("disasm", file=source, arch="x86", bits=32, output=source))
