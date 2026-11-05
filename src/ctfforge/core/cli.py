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
            result = handler(ToolContext("steg", args.steg_tool, {"file": args.file}))
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
