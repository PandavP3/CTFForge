"""Configuration loading with safe defaults and no mandatory YAML dependency."""

import json
from pathlib import Path
from typing import Any

from .exceptions import ConfigurationError

DEFAULT_CONFIG: dict[str, Any] = {
    "flag_patterns": [r"flag\{[^\r\n}]+\}", r"CTF\{[^\r\n}]+\}", r"FLAG\{[^\r\n}]+\}",
                      r"THM\{[^\r\n}]+\}", r"HTB\{[^\r\n}]+\}", r"picoCTF\{[^\r\n}]+\}"],
    "max_file_bytes": 64 * 1024 * 1024,
}


def default_config_path() -> Path:
    """Return a per-user config path without assuming a particular OS home path."""
    return Path.home() / ".ctfforge" / "config.json"


def load_config(path: Path | None = None) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    config_path = path or default_config_path()
    if not config_path.exists():
        return config
    try:
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read configuration {config_path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigurationError("Configuration root must be a JSON object.")
    config.update(loaded)
    if not isinstance(config.get("flag_patterns"), list) or not all(
        isinstance(item, str) for item in config["flag_patterns"]
    ):
        raise ConfigurationError("flag_patterns must be a list of regular-expression strings.")
    return config
