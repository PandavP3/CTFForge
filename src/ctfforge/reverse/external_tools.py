"""Registry handlers for optional external binary inspection utilities."""
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ctfforge.integrations import reverse_tools

MAX_OUTPUT = 2_000_000


def _input_path(value) -> Path:
    if not isinstance(value, (str, Path)):
        raise CTFForgeError("A binary file path is required.")
    path = Path(value).expanduser()
    try:
        if not path.is_file():
            raise CTFForgeError(f"Input is not a regular file: {path}")
    except OSError as exc:
        raise CTFForgeError(f"Cannot access input file {path}: {exc}") from exc
    return path


def _limit(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_OUTPUT:
        raise CTFForgeError(f"Output limit must be between 1 and {MAX_OUTPUT} bytes per stream.")
    return value


def _result(path: Path, tool: str, process, **details) -> ToolResult:
    status = ("unavailable" if not process.available else "timed_out" if process.timed_out else
              "success" if process.returncode == 0 else "failed")
    result = make_result("reverse", str(path), tool=tool, input_filename=path.name,
                         executable_available=process.available, execution_status=status,
                         stdout=process.stdout, stderr=process.stderr, return_code=process.returncode,
                         timed_out=process.timed_out, output_truncated=process.output_truncated,
                         error=process.error, **details)
    if tool == "external-file":
        result["identification"] = process.stdout.strip()
    return result


def availability(context: ToolContext) -> ToolResult:
    tools = reverse_tools.availability()
    return make_result("reverse", "external tool availability", tool="external-status",
                       tools=tools, available_count=sum(row["available"] for row in tools),
                       note="Availability is determined by executable lookup only; no tool is invoked or installed.")


def file_identification(context: ToolContext) -> ToolResult:
    args = context.arguments
    path = _input_path(args.get("file"))
    limit = _limit(args.get("max_output", 1_000_000))
    process = reverse_tools.identify_file(path, output_limit=limit)
    return _result(path, "external-file", process,
                   identification=process.stdout.strip(), output_limit_per_stream=limit)


def elf_analysis(context: ToolContext) -> ToolResult:
    args = context.arguments
    path = _input_path(args.get("file"))
    mode = args.get("mode", "header")
    limit = _limit(args.get("max_output", 1_000_000))
    process = reverse_tools.run_readelf(path, mode, output_limit=limit)
    return _result(path, "external-elf", process, mode=mode, output_limit_per_stream=limit)


def objdump_analysis(context: ToolContext) -> ToolResult:
    args = context.arguments
    path = _input_path(args.get("file"))
    mode = args.get("mode", "file-headers")
    limit = _limit(args.get("max_output", 1_000_000))
    process = reverse_tools.run_objdump(path, mode, output_limit=limit)
    return _result(path, "external-objdump", process, mode=mode, output_limit_per_stream=limit)
