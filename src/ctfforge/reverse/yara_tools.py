"""Optional, bounded YARA rule validation and single-file scanning."""
import importlib
import json
import math
import time
from collections import OrderedDict
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

MAX_RULE_FILE_BYTES = 5 * 1024 * 1024
MAX_TARGET_FILE_BYTES = 128 * 1024 * 1024
MAX_SCAN_TIMEOUT = 60
MAX_MATCHES = 1000
MAX_STRING_INSTANCES = 5000
MAX_EXPORT_BYTES = 8 * 1024 * 1024


def _load_yara():
    try:
        return importlib.import_module("yara")
    except (ImportError, OSError) as exc:
        raise CTFForgeError(
            "YARA support is optional. Install yara-python with: "
            "python -m pip install -r requirements/reverse.txt"
        ) from exc


def _rule_source(value) -> tuple[Path, str]:
    path = _regular_file(value, "YARA rules")
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_RULE_FILE_BYTES + 1)
    except OSError as exc:
        raise CTFForgeError(f"Cannot read YARA rules file {path}: {exc}") from exc
    if len(data) > MAX_RULE_FILE_BYTES:
        raise CTFForgeError(f"YARA rules exceed the {MAX_RULE_FILE_BYTES}-byte limit.")
    try:
        source = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CTFForgeError("YARA rules must be valid UTF-8 text.") from exc
    return path, source


def _regular_file(value, label: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise CTFForgeError(f"A {label} file path is required.")
    path = Path(value).expanduser()
    try:
        if not path.is_file():
            raise CTFForgeError(f"{label} path is not a regular file: {path}")
    except OSError as exc:
        raise CTFForgeError(f"Cannot access {label} file {path}: {exc}") from exc
    return path


def _compile(yara, source: str):
    try:
        # A single source file only; avoid resolving implicit include files.
        return yara.compile(source=source, includes=False)
    except Exception as exc:
        raise CTFForgeError(f"YARA rule compilation failed: {exc}") from exc


def _version(yara) -> str | None:
    value = getattr(yara, "__version__", None)
    if value is None:
        version_func = getattr(yara, "version", None)
        if callable(version_func):
            try:
                value = version_func()
            except Exception:
                value = None
    return str(value) if value is not None else None


def availability(context: ToolContext) -> ToolResult:
    try:
        yara = importlib.import_module("yara")
    except (ImportError, OSError) as exc:
        return make_result("reverse", "YARA availability", tool="yara-status", installed=False,
                           version=None, error=str(exc),
                           installation="python -m pip install -r requirements/reverse.txt")
    return make_result("reverse", "YARA availability", tool="yara-status", installed=True,
                       version=_version(yara), error=None)


def validate(context: ToolContext) -> ToolResult:
    path, source = _rule_source(context.arguments.get("rules"))
    yara = _load_yara()
    try:
        _compile(yara, source)
    except CTFForgeError as exc:
        return make_result("reverse", str(path), tool="yara-validate", status="invalid",
                           valid=False, rule_file_size=path.stat().st_size, yara_version=_version(yara),
                           error=str(exc), note="Compilation validates rules only; no target file was scanned.")
    return make_result("reverse", str(path), tool="yara-validate", status="valid", valid=True,
                       rule_file_size=path.stat().st_size, yara_version=_version(yara),
                       note="Rules compiled successfully; no target file was scanned.")


def _instance_rows(match):
    """Yield only string identifiers and offsets across old and new yara-python APIs."""
    for string_match in getattr(match, "strings", ()) or ():
        if isinstance(string_match, (tuple, list)):
            if len(string_match) >= 2:
                yield str(string_match[1]), string_match[0]
            continue
        identifier = getattr(string_match, "identifier", None)
        instances = getattr(string_match, "instances", None)
        if instances is not None:
            for instance in instances:
                yield str(identifier or ""), getattr(instance, "offset", None)
        elif identifier is not None:
            # Compatibility with APIs exposing one offset directly.
            yield str(identifier), getattr(string_match, "offset", None)


def _match_records(matches):
    reported = []
    emitted_instances = 0
    instances_truncated = False
    for match in matches[:MAX_MATCHES]:
        grouped: OrderedDict[str, list[int | None]] = OrderedDict()
        match_instance_count = 0
        if emitted_instances >= MAX_STRING_INSTANCES:
            if getattr(match, "strings", ()):
                instances_truncated = True
        else:
            for identifier, offset in _instance_rows(match):
                if emitted_instances >= MAX_STRING_INSTANCES:
                    instances_truncated = True
                    break
                grouped.setdefault(identifier, []).append(offset if isinstance(offset, int) else None)
                emitted_instances += 1
                match_instance_count += 1
        reported.append({
            "rule": str(getattr(match, "rule", "")),
            "namespace": str(getattr(match, "namespace", "default")),
            "tags": [str(tag) for tag in (getattr(match, "tags", ()) or ())],
            "metadata": _json_safe(getattr(match, "meta", {}) or {}),
            "string_instance_count": match_instance_count,
            "strings": [{"identifier": identifier, "offsets": offsets}
                        for identifier, offsets in grouped.items()],
        })
    return reported, emitted_instances, instances_truncated


def _json_safe(value):
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_safe(item) for item in value]
    return str(value)


def _timeout(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_SCAN_TIMEOUT:
        raise CTFForgeError(f"YARA timeout must be an integer from 1 to {MAX_SCAN_TIMEOUT} seconds.")
    return value


def _target_file(value) -> tuple[Path, int]:
    path = _regular_file(value, "Target")
    try:
        with path.open("rb") as stream:
            stat = Path(path).stat()
            size = stat.st_size
            stream.fileno()  # Confirm the file can be opened without loading it into memory.
    except OSError as exc:
        raise CTFForgeError(f"Cannot read target file {path}: {exc}") from exc
    if size > MAX_TARGET_FILE_BYTES:
        raise CTFForgeError(f"Target file exceeds the {MAX_TARGET_FILE_BYTES}-byte scan limit.")
    return path, size


def _export(path_value, target: Path, rules: Path, result: dict) -> str | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        resolved = path.resolve()
        if resolved in (target.resolve(), rules.resolve()):
            raise CTFForgeError("YARA export must not overwrite the target or rules file.")
        if not path.parent.is_dir():
            raise CTFForgeError(f"YARA export directory does not exist: {path.parent}")
        result["output_file"] = str(path)
        payload = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(payload) > MAX_EXPORT_BYTES:
            raise CTFForgeError(f"YARA JSON export exceeds {MAX_EXPORT_BYTES} bytes.")
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise CTFForgeError(f"Refusing to overwrite existing YARA export: {path}") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise CTFForgeError(f"Cannot write YARA export {path}: {exc}") from exc
    return str(path)


def scan(context: ToolContext) -> ToolResult:
    args = context.arguments
    target, target_size = _target_file(args.get("file"))
    rules_path, source = _rule_source(args.get("rules"))
    timeout = _timeout(args.get("timeout", 10))
    yara = _load_yara()
    rules = _compile(yara, source)
    started = time.perf_counter()
    try:
        raw_matches = rules.match(filepath=str(target), timeout=timeout)
    except Exception as exc:
        timeout_type = getattr(yara, "TimeoutError", None)
        if timeout_type is not None and isinstance(exc, timeout_type):
            duration = round(time.perf_counter() - started, 6)
            result = make_result("reverse", str(target), tool="yara", status="timed_out",
                                 target_filename=target.name, target_size=target_size,
                                 rules_file=str(rules_path), yara_version=_version(yara),
                                 timeout_seconds=timeout, duration_seconds=duration,
                                 matches=[], match_count=None, reported_match_count=0,
                                 results_complete=False, matches_truncated=False,
                                 string_instance_count=0, string_instances_truncated=False,
                                 truncated=False, error=f"YARA scan exceeded its {timeout}-second timeout.")
            exported = _export(args.get("output"), target, rules_path, result)
            if exported:
                result["output_file"] = exported
            return result
        raise CTFForgeError(f"YARA scan failed: {exc}") from exc
    duration = round(time.perf_counter() - started, 6)
    raw_matches = list(raw_matches or ())
    match_rows, instance_count, instances_truncated = _match_records(raw_matches)
    matches_truncated = len(raw_matches) > MAX_MATCHES
    truncated = matches_truncated or instances_truncated
    result = make_result("reverse", str(target), tool="yara", status="complete",
                         target_filename=target.name, target_size=target_size,
                         rules_file=str(rules_path), yara_version=_version(yara),
                         timeout_seconds=timeout, duration_seconds=duration,
                         matches=match_rows, match_count=len(raw_matches),
                         reported_match_count=len(match_rows), results_complete=not truncated,
                         matches_truncated=matches_truncated,
                         string_instance_count=instance_count,
                         string_instances_truncated=instances_truncated,
                         truncated=truncated,
                         note="A YARA match is a signature indicator, not proof of malware infection.")
    exported = _export(args.get("output"), target, rules_path, result)
    if exported:
        result["output_file"] = exported
    return result
