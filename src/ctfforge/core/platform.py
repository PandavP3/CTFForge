"""Portable platform information and capability checks."""

import platform as _platform
import sys


def current_platform() -> str:
    """Return a normalized platform name."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return sys.platform


def platform_info() -> dict[str, str]:
    return {"system": current_platform(), "release": _platform.release(), "python": sys.version.split()[0]}


def require_platform(*supported: str) -> None:
    """Raise a friendly error when a feature is unavailable on this OS."""
    from .exceptions import CTFForgeError

    actual = current_platform()
    if actual not in supported:
        raise CTFForgeError(f"This feature requires {', '.join(supported)}; detected {actual}.")
