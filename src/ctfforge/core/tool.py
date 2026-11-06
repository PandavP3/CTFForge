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
class InteractiveInput:
    """A validated prompt definition for the optional interactive launcher."""

    name: str
    prompt: str
    value_type: str = "str"
    required: bool = True
    default: object | None = None
    choices: tuple[str, ...] = ()
    multiple: bool = False
    group: str | None = None
    group_rule: str | None = None
    must_exist: bool = False
    minimum: int | float | None = None
    maximum: int | float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "choices", tuple(self.choices))
        if not self.name.isidentifier() or not self.prompt.strip():
            raise CTFForgeError("Interactive input needs a valid name and non-empty prompt.")
        if self.value_type not in {"str", "path", "int", "float", "bool"}:
            raise CTFForgeError(f"Unsupported interactive input type {self.value_type!r}.")
        if self.group_rule not in (None, "exactly_one"):
            raise CTFForgeError("Interactive input group rule must be exactly_one when provided.")
        if self.group_rule and not self.group:
            raise CTFForgeError("Interactive input group rules require a group name.")
        if self.choices and self.value_type != "str":
            raise CTFForgeError("Interactive choices must use string values.")
        if self.default is not None and self.choices and str(self.default) not in self.choices:
            raise CTFForgeError("Interactive input default must be one of its choices.")
        if (self.minimum is not None or self.maximum is not None) and self.value_type not in ("int", "float"):
            raise CTFForgeError("Interactive input bounds require an integer or float type.")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise CTFForgeError("Interactive input minimum cannot exceed its maximum.")


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
    interactive_inputs: tuple[InteractiveInput, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.optional_dependencies, str):
            raise CTFForgeError("Optional dependencies must be a tuple of Python import names.")
        object.__setattr__(self, "optional_dependencies", tuple(self.optional_dependencies))
        object.__setattr__(self, "interactive_inputs", tuple(self.interactive_inputs))
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
        if any(not isinstance(item, InteractiveInput) for item in self.interactive_inputs):
            raise CTFForgeError("Interactive inputs must be InteractiveInput definitions.")
        names = [item.name for item in self.interactive_inputs]
        if len(names) != len(set(names)):
            raise CTFForgeError("Interactive input names must be unique within a tool.")
        group_rules: dict[str, set[str | None]] = {}
        for item in self.interactive_inputs:
            if item.group:
                group_rules.setdefault(item.group, set()).add(item.group_rule)
        if any(len(rules) > 1 for rules in group_rules.values()):
            raise CTFForgeError("Interactive input group members must use a consistent group rule.")


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
