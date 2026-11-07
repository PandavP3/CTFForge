"""Loop-driven interactive terminal launcher for registered CTFForge tools."""
import json
import os
import sys
import csv
import io
from pathlib import Path
from typing import Callable

from .exceptions import CTFForgeError
from .registration import build_core_registry
from .registry import MissingOptionalDependencyError, ToolRegistry
from .tool import InteractiveInput, ToolContext, ToolSpec

CATEGORY_MENU = (
    ("crypto", "Cryptography"),
    ("web", "Web Exploitation"),
    ("steg", "Steganography"),
    ("forensics", "Digital Forensics"),
    ("reverse", "Reverse Engineering"),
    ("pwn", "Binary Exploitation"),
    ("osint", "OSINT"),
    ("network", "Network Analysis"),
    ("linux", "Linux"),
    ("windows", "Windows / AD"),
    ("mobile", "Mobile"),
    ("cloud", "Cloud"),
    ("wireless", "Wireless"),
    ("blockchain", "Blockchain"),
    ("common", "Miscellaneous"),
)

BANNER = """      ██████╗████████╗███████╗
     ██╔════╝╚══██╔══╝██╔════╝
     ██║        ██║   █████╗
     ██║        ██║   ██╔══╝
     ╚██████╗   ██║   ██║
      ╚═════╝   ╚═╝   ╚═╝
          CTFForge"""
ASCII_BANNER = r"""   _______ ______ ______
  / ____/ //_/ / / / /
 / /   / ,< / /_/ /
/ /___/ /| |/ __  /
\____/_/ |_/_/ /_/
       CTFForge"""


class _Navigation(Exception):
    def __init__(self, destination: str):
        self.destination = destination


def _render_value(spec: InteractiveInput, text: str):
    if spec.choices and text not in spec.choices:
        raise ValueError("Choose one of: " + ", ".join(spec.choices))
    if spec.value_type == "path":
        value = Path(text).expanduser()
        if spec.must_exist and not value.is_file():
            raise ValueError(f"File does not exist or is not a regular file: {value}")
        return value
    if spec.value_type == "int":
        value = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    elif spec.value_type == "float":
        value = float(text)
    else:
        value = None
    if value is not None:
        if spec.minimum is not None and value < spec.minimum:
            raise ValueError(f"Value must be at least {spec.minimum}.")
        if spec.maximum is not None and value > spec.maximum:
            raise ValueError(f"Value must be at most {spec.maximum}.")
        return value
    if spec.value_type == "bool":
        normalized = text.strip().lower()
        if normalized in ("y", "yes", "true", "1"):
            return True
        if normalized in ("n", "no", "false", "0"):
            return False
        raise ValueError("Enter yes or no.")
    return text


def collect_inputs(spec: ToolSpec, input_fn: Callable[[str], str], emit: Callable[[str], None]):
    """Prompt using the ToolSpec schema; return normalized handler arguments."""
    while True:
        values = {}
        for item in spec.interactive_inputs:
            if item.choices:
                emit("Options: " + ", ".join(item.choices))
            if item.multiple:
                collected = []
                while True:
                    prompt = f"{item.prompt}{' [optional]' if not item.required else ''}: "
                    answer = input_fn(prompt)
                    command = answer.strip().lower()
                    if command in (":back", ":b"):
                        raise _Navigation("category")
                    if command in (":home", ":h"):
                        raise _Navigation("home")
                    if command in (":exit", ":q"):
                        raise _Navigation("exit")
                    if not answer.strip():
                        break
                    try:
                        collected.append(_render_value(item, answer.strip()))
                    except ValueError as exc:
                        emit(f"Invalid value: {exc}")
                if collected:
                    values[item.name] = collected
                elif item.required:
                    emit(f"{item.name} requires at least one value.")
            else:
                default = f" [{item.default}]" if item.default is not None else ""
                optional = " (optional; press Enter to skip)" if not item.required and item.default is None else ""
                while True:
                    answer = input_fn(f"{item.prompt}{default}{optional}: ")
                    command = answer.strip().lower()
                    if command in (":back", ":b"):
                        raise _Navigation("category")
                    if command in (":home", ":h"):
                        raise _Navigation("home")
                    if command in (":exit", ":q"):
                        raise _Navigation("exit")
                    if not answer.strip():
                        if item.default is not None:
                            values[item.name] = item.default
                        elif item.required:
                            emit("A value is required.")
                            continue
                        break
                    try:
                        value = answer.strip() if item.choices or item.value_type != "str" else answer
                        values[item.name] = _render_value(item, value)
                    except ValueError as exc:
                        emit(f"Invalid value: {exc}")
                        continue
                    break
        invalid_groups = []
        groups = {}
        for item in spec.interactive_inputs:
            if item.group and item.group_rule == "exactly_one":
                groups.setdefault(item.group, []).append(item.name)
        for group, names in groups.items():
            provided = [name for name in names if values.get(name) not in (None, "", [])]
            if len(provided) != 1:
                invalid_groups.append(group)
        if not invalid_groups:
            return values
        emit("Choose exactly one input for: " + ", ".join(invalid_groups) + ". Please try again.")


def _terminal_unicode_supported(output_stream) -> bool:
    encoding = getattr(output_stream, "encoding", None) or "utf-8"
    try:
        BANNER.encode(encoding)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


def run_interactive(*, registry: ToolRegistry | None = None,
                    input_fn: Callable[[str], str] | None = None,
                    output: Callable[[str], None] | None = None) -> int:
    """Run the interactive UI; all tool work is delegated to registered handlers."""
    registry = registry or build_core_registry()
    input_fn = input_fn or input
    stream = sys.stdout
    custom_output = output is not None
    output = output or (lambda text: print(text, file=stream))
    tty = bool(getattr(stream, "isatty", lambda: False)())
    windows_ansi = (os.name != "nt" or os.environ.get("WT_SESSION") or os.environ.get("ANSICON")
                    or os.environ.get("FORCE_COLOR") or os.environ.get("TERM"))
    color = bool(not custom_output and tty and windows_ansi and not os.environ.get("NO_COLOR")
                 and os.environ.get("TERM", "") != "dumb")

    def emit(text: str = ""):
        if color:
            output(f"\033[36m{text}\033[0m")
        else:
            output(text)

    def read(prompt: str) -> str:
        answer = input_fn(prompt)
        if answer is None:
            raise EOFError
        return answer

    def print_banner():
        output(BANNER if _terminal_unicode_supported(stream) else ASCII_BANNER)
        emit("=" * 52)

    category = None
    tool = None
    state = "home"
    print_banner()
    while True:
        try:
            if state == "home":
                registered = set(registry.list_categories())
                emit("\nCTFForge Categories")
                for index, (key, label) in enumerate(CATEGORY_MENU, 1):
                    available = key in registered or (key == "common" and "misc" in registered)
                    suffix = "" if available else "  (Coming Soon)"
                    emit(f"[{index}] {label}{suffix}")
                emit("[0] Exit")
                choice = read("Select category: ").strip()
                if not choice:
                    emit("Enter a menu number.")
                    continue
                if choice == "0":
                    emit("Goodbye.")
                    return 0
                if not choice.isdecimal() or not 1 <= int(choice) <= len(CATEGORY_MENU):
                    emit("Invalid category selection.")
                    continue
                key, _ = CATEGORY_MENU[int(choice) - 1]
                available = key in registered or (key == "common" and "misc" in registered)
                if not available:
                    emit("That category is coming soon.")
                    continue
                category = key
                state = "category"
            elif state == "category":
                categories = ("common", "misc") if category == "common" else (category,)
                tools = tuple(spec for actual in categories if actual in registry.list_categories()
                              for spec in registry.list_tools(actual))
                label = dict(CATEGORY_MENU).get(category, category.title())
                emit(f"\n{label} Tools")
                for index, item in enumerate(tools, 1):
                    description = item.description.strip()
                    if len(description) > 110:
                        description = description[:107].rstrip() + "..."
                    emit(f"[{index}] {item.name} — {description}")
                emit("[b] Back   [h] Home   [0] Exit")
                choice = read("Select tool: ").strip()
                if choice.lower() in ("b", "back"):
                    state = "home"
                    continue
                if choice.lower() in ("h", "home"):
                    state = "home"
                    continue
                if choice == "0":
                    emit("Goodbye.")
                    return 0
                if not choice.isdecimal() or not 1 <= int(choice) <= len(tools):
                    emit("Invalid tool selection.")
                    continue
                tool = tools[int(choice) - 1]
                state = "tool"
            elif state == "tool":
                emit(f"\n{tool.name}: {tool.description}")
                if tool.usage:
                    emit(f"Usage: {tool.usage}")
                if tool.help:
                    emit(tool.help)
                if not tool.interactive_inputs:
                    arguments = {}
                else:
                    arguments = collect_inputs(tool, read, emit)
                try:
                    handler = registry.resolve_handler(tool.category, tool.name)
                    result = handler(ToolContext(tool.category, tool.name, arguments))
                    emit("\nResult")
                    if category == "forensics" and tool.name in ("logs", "pcap") and arguments.get("format") == "csv":
                        fields = (("line", "timestamp", "source_ip", "username", "event_type", "status", "path", "source")
                                  if tool.name == "logs" else ("protocol", "endpoint_a", "endpoint_b", "packets"))
                        rows = result["timeline"] if tool.name == "logs" else result["observations"]["conversations"]
                        buffer = io.StringIO()
                        writer = csv.DictWriter(buffer, fieldnames=fields)
                        writer.writeheader()
                        writer.writerows({key: row.get(key) for key in fields} for row in rows)
                        emit(buffer.getvalue())
                    else:
                        emit(json.dumps(result, indent=2, ensure_ascii=False, default=str))
                except MissingOptionalDependencyError as exc:
                    emit(f"Optional dependency unavailable: {exc}")
                except (CTFForgeError, OSError, ValueError) as exc:
                    emit(f"Tool error: {exc}")
                except Exception as exc:  # Keep an unexpected handler failure inside the UI.
                    emit(f"Tool failed: {type(exc).__name__}: {exc}")
                state = "after_tool"
            elif state == "after_tool":
                emit("[1] Run this tool again   [2] Tools in this category")
                emit("[h] Home   [0] Exit")
                choice = read("Next action: ").strip()
                if choice == "1":
                    state = "tool"
                elif choice == "2" or choice.lower() in ("b", "back"):
                    state = "category"
                elif choice.lower() in ("h", "home"):
                    state = "home"
                elif choice == "0":
                    emit("Goodbye.")
                    return 0
                else:
                    emit("Invalid selection.")
        except _Navigation as navigation:
            if navigation.destination == "exit":
                emit("Goodbye.")
                return 0
            state = "home" if navigation.destination == "home" else "category"
        except (EOFError, KeyboardInterrupt):
            emit("\nInput closed. Goodbye.")
            return 0
