"""Shared metadata and call contract for registered tools."""

import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, TypeAlias

from .exceptions import CTFForgeError

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]*$")


def _valid_identifier(value: str, label: str) -> None:
    if not _IDENTIFIER.fullmatch(value):
        raise CTFForgeError(
            f"Invalid {label} {value!r}; use lowercase letters, digits, underscores, or hyphens."
        )


@dataclass(frozen=True)
class ToolSpec:
    """Declarative metadata for one independently implemented tool.

    ``handler_ref`` uses ``package.module:callable`` syntax. Optional dependency
    names are Python import names and are checked only when that handler is loaded.
    """

    name: str
    category: str
    description: str
    handler_ref: str
    optional_dependencies: tuple[str, ...] = ()
    usage: str | None = None
    help: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.optional_dependencies, str):
            raise CTFForgeError("Optional dependencies must be a tuple of Python import names.")
        object.__setattr__(self, "optional_dependencies", tuple(self.optional_dependencies))
        _valid_identifier(self.category, "category")
        _valid_identifier(self.name, "tool name")
        if not self.description.strip():
            raise CTFForgeError("Tool description cannot be empty.")
        module_name, separator, attribute = self.handler_ref.partition(":")
        valid_handler = _valid_dotted_name(module_name) and _valid_dotted_name(attribute)
        if not separator or not valid_handler:
            raise CTFForgeError(
                f"Invalid handler reference {self.handler_ref!r}; expected 'module.path:callable'."
            )
        if any(not isinstance(dependency, str) or not _valid_dotted_name(dependency)
               for dependency in self.optional_dependencies):
            raise CTFForgeError("Optional dependencies must be Python import names.")
        if len(set(self.optional_dependencies)) != len(self.optional_dependencies):
            raise CTFForgeError("Optional dependency names must be unique.")
        if self.usage is not None and not self.usage.strip():
            raise CTFForgeError("Tool usage metadata cannot be empty when provided.")
        if self.help is not None and not self.help.strip():
            raise CTFForgeError("Tool help metadata cannot be empty when provided.")


def _valid_dotted_name(value: str) -> bool:
    return bool(value) and all(part.isidentifier() for part in value.split("."))


@dataclass(frozen=True)
class ToolContext:
    """Normalized arguments passed to a tool by CLI or interactive dispatch."""

    category: str
    tool: str
    arguments: Mapping[str, object]


ToolResult: TypeAlias = dict[str, Any]


class ToolHandler(Protocol):
    """A handler receives one context and returns a common result dictionary."""

    def __call__(self, context: ToolContext, /) -> ToolResult: ...
