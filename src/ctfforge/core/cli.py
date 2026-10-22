"""Phase 1 command line foundation."""

import argparse
import json
import re
import sys
from pathlib import Path

from .config import load_config
from .exceptions import CTFForgeError
from .file_detection import identify_file
from .flag_format import compile_flag_pattern
from .hashing import hash_file
from .platform import platform_info
from .runner import find_tool
from .solver import continue_session, solve
from .solver_input import from_path, from_stdin, from_text
from .strings import extract_strings

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
        target = args.target.expanduser()
        if not target.is_file():
            raise CTFForgeError(f"Target is not a file: {target}")
        if args.command == "hash":
            print(json.dumps({"target": str(target), "hashes": hash_file(target)}, indent=2))
        elif args.command == "strings":
            print("\n".join(extract_strings(target)))
        return 0
    except (CTFForgeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
