"""Validation and matching for a challenge-specific expected flag format."""

import re

from .exceptions import CTFForgeError


def compile_flag_pattern(flag_format: str | None, flag_prefix: str | None) -> re.Pattern[str]:
    if flag_format is None and flag_prefix is None:
        raise CTFForgeError("Provide --flag-format or --flag-prefix.")
    if flag_prefix is not None and not flag_prefix:
        raise CTFForgeError("--flag-prefix cannot be empty.")
    expression = flag_format if flag_format is not None else re.escape(flag_prefix or "") + r"[^}\r\n]+}"
    try:
        pattern = re.compile(expression)
    except re.error as exc:
        raise CTFForgeError(f"Invalid flag format regular expression: {exc}") from exc
    if flag_format is not None and flag_prefix is not None:
        sample = flag_prefix + "example}"
        match = pattern.search(sample)
        if match is None or not match.group(0).startswith(flag_prefix):
            raise CTFForgeError("--flag-format and --flag-prefix do not describe a compatible flag.")
    return pattern


def find_flags(text: str, pattern: re.Pattern[str]) -> list[str]:
    return sorted({match.group(0) for match in pattern.finditer(text)})
