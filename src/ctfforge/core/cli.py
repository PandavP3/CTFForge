"""Phase 1 command line foundation."""

import argparse
import json
import re
import sys
from pathlib import Path

from .config import load_config
from .exceptions import CTFForgeError
from .flag_format import compile_flag_pattern
from .platform import platform_info
from .registration import build_core_registry
from .runner import find_tool
from .solver import continue_session, solve
from .solver_input import from_path, from_stdin, from_text
from .tool import ToolContext, ToolResult

OPTIONAL_TOOLS = {
    "Nmap": "nmap", "Tshark": "tshark", "Wireshark": "wireshark", "ExifTool": "exiftool",
    "Binwalk": "binwalk", "FFUF": "ffuf", "Nuclei": "nuclei", "Ghidra": "ghidra",
    "JADX": "jadx", "Apktool": "apktool", "Volatility": "vol", "ROPgadget": "ROPgadget",
    "SQLmap": "sqlmap",
}
CATEGORIES = ("web", "crypto", "steg", "forensics", "pwn", "reverse", "osint", "network",
              "linux", "windows", "mobile", "cloud", "wireless", "blockchain", "ai", "misc")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctfforge", description="Modular tools for authorized CTF and lab analysis")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("doctor", help="check Python and optional external tools")
    sub.add_parser("interactive", help="launch the menu-driven CTFForge terminal interface")
    solve_parser = sub.add_parser("solve", help="analyze a challenge artifact offline-first")
    solve_parser.add_argument("--category", required=True, choices=CATEGORIES)
    solve_parser.add_argument("--flag-format", help="expected flag regular expression")
    solve_parser.add_argument("--flag-prefix", help="literal flag prefix such as CTF{")
    source = solve_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="challenge file path")
    source.add_argument("--input", help="direct UTF-8 text input")
    source.add_argument("--stdin", action="store_true", help="read binary-safe input from stdin")
    continue_parser = sub.add_parser("continue", help="resume a solve session with user-supplied output")
    continue_parser.add_argument("session_id")
    continuation = continue_parser.add_mutually_exclusive_group(required=True)
    continuation.add_argument("--result", help="text returned by an external/local operation")
    continuation.add_argument("--stdin", action="store_true", help="read continuation result from stdin")
    for command, help_text in (("hash", "calculate file hashes"), ("strings", "extract printable strings"),
                               ("detect", "search files for common or configured CTF flags")):
        item = sub.add_parser(command, help=help_text)
        item.add_argument("target", type=Path)
        if command == "detect":
            item.add_argument("--config", type=Path, help="JSON configuration file")
    crypto = sub.add_parser("crypto", help="cryptography challenge tools")
    crypto_tools = crypto.add_subparsers(dest="crypto_tool", required=True)
    xor = crypto_tools.add_parser("xor", help="analyze single-byte or keyed XOR data")
    xor_source = xor.add_mutually_exclusive_group(required=True)
    xor_source.add_argument("--file", type=Path, help="read binary data from a file (max 16 MiB)")
    xor_source.add_argument("--input", help="use direct UTF-8 text input")
    xor_source.add_argument("--hex", help="use hexadecimal input")
    xor_key = xor.add_mutually_exclusive_group()
    xor_key.add_argument("--key", help="known one-byte UTF-8 XOR key")
    xor_key.add_argument("--repeat-key", help="UTF-8 repeating XOR key")
    xor.add_argument("--limit", type=int, default=10, help="brute-force candidates to show (1-256)")
    hashid = crypto_tools.add_parser("hashid", help="identify a likely hash format")
    hashid_source = hashid.add_mutually_exclusive_group(required=True)
    hashid_source.add_argument("--input", help="hash string to inspect")
    hashid_source.add_argument("--file", type=Path, help="read ASCII hash text from a file")
    steg = sub.add_parser("steg", help="steganography artifact analysis tools")
    steg_tools = steg.add_subparsers(dest="steg_tool", required=True)
    metadata = steg_tools.add_parser("metadata", help="inspect image properties and metadata")
    metadata.add_argument("--file", required=True, type=Path, help="image file to inspect")
    structure = steg_tools.add_parser("structure", help="inspect file signatures and structure")
    structure.add_argument("--file", required=True, type=Path, help="file to inspect")
    lsb = steg_tools.add_parser(
        "lsb", help="heuristically analyze lossless image bit planes for candidate data"
    )
    lsb.add_argument("--file", required=True, type=Path, help="lossless image to inspect")
    lsb.add_argument("--channel", choices=("red", "green", "blue", "alpha", "all"),
                     default="all", help="analyze channels independently (default: all)")
    lsb.add_argument("--bit-plane", type=int, choices=range(8), default=0,
                     help="channel bit plane 0-7 (default: least-significant plane 0)")
    lsb.add_argument("--bit-order", choices=("msb", "lsb"), default="msb",
                     help="pack first traversed pixel into byte's MSB (default) or LSB")
    lsb.add_argument("--output", type=Path, help="write selected channel stream to a new binary file")
    lsb.add_argument("--text", action="store_true",
                     help="include extracted UTF-8 text for one selected channel (max 4096 characters)")
    web = sub.add_parser("web", help="offline web analyzers and controlled HTTP helpers")
    web_tools = web.add_subparsers(dest="web_tool", required=True)
    jwt = web_tools.add_parser("jwt", help="decode and statically inspect a JWT (never verifies signature)")
    jwt.add_argument("--token", required=True)
    for name, label in (("headers", "analyze HTTP response headers"),
                        ("cookies", "analyze Set-Cookie headers"),
                        ("cors", "analyze CORS response headers")):
        item = web_tools.add_parser(name, help=label)
        source = item.add_mutually_exclusive_group(required=True)
        source.add_argument("--url", help="fetch response headers from this URL")
        source.add_argument("--header", action="append", help="supplied header; repeat as needed")
    url_tool = web_tools.add_parser("url", help="inspect a URL without visiting it")
    url_tool.add_argument("--input", required=True)
    discover = web_tools.add_parser("discover", help="authorized, bounded HTTP path discovery")
    discover.add_argument("--url", required=True)
    discover.add_argument("--wordlist", required=True, type=Path)
    discover.add_argument("--timeout", type=float, default=5.0)
    discover.add_argument("--rate", type=float, default=2.0, help="requests per second (default: 2)")
    discover.add_argument("--concurrency", type=int, default=2, help="maximum workers (1-5)")
    discover.add_argument("--status", type=int, action="append", help="include status code; repeatable")
    forensics = sub.add_parser("forensics", help="offline digital forensics tools")
    forensic_tools = forensics.add_subparsers(dest="forensics_tool", required=True)
    pcap = forensic_tools.add_parser("pcap", help="analyze PCAP or PCAPNG offline")
    pcap.add_argument("--file", required=True, type=Path)
    pcap.add_argument("--backend", choices=("native", "tshark", "auto"), default="auto")
    pcap.add_argument("--format", choices=("json", "csv"), default="json")
    carve = forensic_tools.add_parser("carve", help="identify and selectively recover embedded files")
    carve.add_argument("--file", required=True, type=Path)
    carve.add_argument("--output-dir", required=True, type=Path)
    carve.add_argument("--extract-offset", type=lambda value: int(value, 0), action="append",
                       help="explicit candidate offset to recover (decimal or 0x hex); repeatable")
    carve.add_argument("--backend", choices=("native", "binwalk", "auto"), default="auto")
    logs = forensic_tools.add_parser("logs", help="analyze authentication and HTTP logs")
    logs.add_argument("--file", required=True, type=Path)
    logs.add_argument("--format", choices=("json", "csv"), default="json")
    reverse = sub.add_parser("reverse", help="native and optional external reverse-engineering tools")
    reverse_tools = reverse.add_subparsers(dest="reverse_tool", required=True)
    for name, description in (("info", "identify a binary format and architecture"),
                              ("elf", "inspect ELF headers and tables"),
                              ("pe", "inspect PE/COFF headers and sections"),
                              ("symbols", "inspect ELF symbols or PE imports and exports")):
        item = reverse_tools.add_parser(name, help=description)
        item.add_argument("--file", required=True, type=Path)
    strings = reverse_tools.add_parser("strings", help="extract printable strings with offsets")
    strings.add_argument("--file", required=True, type=Path)
    strings.add_argument("--min-length", type=int, default=4)
    strings.add_argument("--encoding", choices=("ascii", "utf16le", "both"), default="both")
    strings.add_argument("--limit", type=int, default=10000)
    strings.add_argument("--output", type=Path, help="optional text export path; existing files are not overwritten")
    entropy = reverse_tools.add_parser("entropy", help="calculate overall and block entropy")
    entropy.add_argument("--file", required=True, type=Path)
    entropy.add_argument("--block-size", type=int, default=4096)
    for name, description in (("disasm", "disassemble a bounded binary range"),
                              ("instructions", "summarize decoded instructions")):
        item = reverse_tools.add_parser(name, help=description)
        item.add_argument("--file", required=True, type=Path)
        item.add_argument("--arch", choices=("x86", "arm", "arm64", "mips"))
        item.add_argument("--bits", type=int, choices=(16, 32, 64))
        item.add_argument("--endian", choices=("little", "big"))
        item.add_argument("--mode", choices=("arm", "thumb", "mips32", "mips64"))
        item.add_argument("--offset", type=lambda value: int(value, 0), default=0)
        item.add_argument("--address", "--virtual-address", dest="address", type=lambda value: int(value, 0))
        item.add_argument("--max-bytes", type=int, default=4096)
        item.add_argument("--max-instructions", type=int, default=1000)
        item.add_argument("--output", type=Path, help="optional exclusive-create JSON export")
        if name == "instructions":
            item.add_argument("--details", action="store_true")
    for name, description in (("functions", "list symbol-derived functions"),
                              ("packer", "inspect static packer indicators")):
        item = reverse_tools.add_parser(name, help=description)
        item.add_argument("--file", required=True, type=Path)
    reverse_tools.add_parser("external-status", help="check optional file/readelf/objdump availability")
    external_file = reverse_tools.add_parser("external-file", help="identify a file with external file utility")
    external_file.add_argument("--file", required=True, type=Path)
    external_file.add_argument("--max-output", type=int, default=1_000_000)
    external_elf = reverse_tools.add_parser("external-elf", help="analyze an ELF file with readelf")
    external_elf.add_argument("--file", required=True, type=Path)
    external_elf.add_argument("--mode", choices=("header", "program-headers", "sections", "symbols", "dynamic", "relocations"), default="header")
    external_elf.add_argument("--max-output", type=int, default=1_000_000)
    external_objdump = reverse_tools.add_parser("external-objdump", help="analyze a binary with objdump")
    external_objdump.add_argument("--file", required=True, type=Path)
    external_objdump.add_argument("--mode", choices=("file-headers", "section-headers", "disassembly", "symbol-table", "private-headers"), default="file-headers")
    external_objdump.add_argument("--max-output", type=int, default=1_000_000)
    return parser


def _doctor() -> int:
    print("CTFForge Environment Check\n")
    print(f"Python       ✓ {sys.version.split()[0]}")
    found = 0
    for label, executable in OPTIONAL_TOOLS.items():
        path = find_tool(executable)
        found += path is not None
        print(f"{label:<12} {'✓' if path else '✗'}" + (f" {path}" if path else ""))
    print(f"\nStatus: {'READY' if found == len(OPTIONAL_TOOLS) else 'PARTIAL'}")
    return 0


def _iter_files(target: Path):
    if target.is_file():
        yield target
    elif target.is_dir():
        yield from sorted(path for path in target.rglob("*") if path.is_file())
    else:
        raise CTFForgeError(f"Target does not exist or is not a regular file/directory: {target}")


def _detect(target: Path, config_path: Path | None) -> int:
    patterns = load_config(config_path)["flag_patterns"]
    compiled = []
    try:
        compiled = [re.compile(pattern) for pattern in patterns]
    except re.error as exc:
        raise CTFForgeError(f"Invalid flag pattern in configuration: {exc}") from exc
    matches: set[str] = set()
    for path in _iter_files(target):
        try:
            text = path.read_bytes().decode("utf-8", errors="ignore")
            for pattern in compiled:
                matches.update(pattern.findall(text))
        except OSError as exc:
            print(f"Warning: cannot read {path}: {exc}", file=sys.stderr)
    if matches:
        print("Potential Flags\n")
        for index, flag in enumerate(sorted(matches), start=1):
            print(f"[{index}] {flag}")
    else:
        print("No potential flags found.")
    return 0


def _run_common_tool(name: str, target: Path) -> ToolResult:
    registry = build_core_registry()
    handler = registry.resolve_handler("common", name)
    return handler(ToolContext("common", name, {"file": target}))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "interactive":
            from .interactive import run_interactive
            return run_interactive()
        if args.command == "doctor":
            return _doctor()
        if args.command == "solve":
            if args.flag_format is None and args.flag_prefix is None:
                raise CTFForgeError("Provide --flag-format or --flag-prefix.")
            compile_flag_pattern(args.flag_format, args.flag_prefix)
            if args.file is not None:
                artifact = from_path(args.file)
            elif args.input is not None:
                artifact = from_text(args.input)
            else:
                artifact = from_stdin(sys.stdin.buffer)
            state, result = solve(artifact, args.category,
                                  args.flag_format or re.escape(args.flag_prefix or "") + r"[^}\r\n]+}",
                                  flag_prefix=args.flag_prefix)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if state["status"] == "SOLVED" else 1
        if args.command == "continue":
            result_text = args.result if args.result is not None else sys.stdin.buffer.read().decode("utf-8", errors="replace")
            state, result = continue_session(args.session_id, result_text)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if state["status"] == "SOLVED" else 1
        if args.command == "detect":
            return _detect(args.target.expanduser(), args.config.expanduser() if args.config else None)
        if args.command == "crypto":
            registry = build_core_registry()
            handler = registry.resolve_handler("crypto", args.crypto_tool)
            arguments = vars(args).copy()
            arguments.pop("command", None)
            arguments.pop("crypto_tool", None)
            if args.crypto_tool == "hashid" and args.file is not None:
                arguments["file"] = args.file
            result = handler(ToolContext("crypto", args.crypto_tool, arguments))
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        if args.command == "steg":
            registry = build_core_registry()
            handler = registry.resolve_handler("steg", args.steg_tool)
            arguments = vars(args).copy()
            arguments.pop("command", None)
            arguments.pop("steg_tool", None)
            result = handler(ToolContext("steg", args.steg_tool, arguments))
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        if args.command == "web":
            registry = build_core_registry()
            handler = registry.resolve_handler("web", args.web_tool)
            arguments = vars(args).copy()
            arguments.pop("command", None)
            arguments.pop("web_tool", None)
            result = handler(ToolContext("web", args.web_tool, arguments))
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        if args.command == "forensics":
            registry = build_core_registry()
            handler = registry.resolve_handler("forensics", args.forensics_tool)
            arguments = vars(args).copy()
            arguments.pop("command", None)
            arguments.pop("forensics_tool", None)
            result = handler(ToolContext("forensics", args.forensics_tool, arguments))
            if args.forensics_tool in ("logs", "pcap") and args.format == "csv":
                import csv
                import io
                buffer = io.StringIO()
                if args.forensics_tool == "logs":
                    fields = ("line", "timestamp", "source_ip", "username", "event_type", "status", "path", "source")
                    rows = result["timeline"]
                else:
                    fields = ("protocol", "endpoint_a", "endpoint_b", "packets")
                    rows = result["observations"]["conversations"]
                writer = csv.DictWriter(buffer, fieldnames=fields)
                writer.writeheader()
                writer.writerows({key: event.get(key) for key in fields} for event in rows)
                print(buffer.getvalue(), end="")
            else:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        if args.command == "reverse":
            registry = build_core_registry()
            handler = registry.resolve_handler("reverse", args.reverse_tool)
            arguments = vars(args).copy()
            arguments.pop("command", None)
            arguments.pop("reverse_tool", None)
            result = handler(ToolContext("reverse", args.reverse_tool, arguments))
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        target = args.target.expanduser()
        if not target.is_file():
            raise CTFForgeError(f"Target is not a file: {target}")
        if args.command == "hash":
            result = _run_common_tool("hash", target)
            print(json.dumps({"target": result["target"], "hashes": result["hashes"]}, indent=2))
        elif args.command == "strings":
            result = _run_common_tool("strings", target)
            print("\n".join(result["strings"]))
        return 0
    except (CTFForgeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
