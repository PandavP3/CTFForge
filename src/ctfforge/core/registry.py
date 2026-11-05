"""Instance-scoped registry with lazy handler loading."""

from importlib import import_module
from typing import Iterable, cast

from .exceptions import CTFForgeError
from .tool import ToolHandler, ToolSpec


class RegistryError(CTFForgeError):
    """Base error for tool registration and lookup failures."""


class DuplicateToolError(RegistryError):
    """Raised when a category already contains a tool with the same name."""


class UnknownCategoryError(RegistryError):
    """Raised when a requested category has no registered tools."""


class UnknownToolError(RegistryError):
    """Raised when a requested tool is absent from a registered category."""


class HandlerResolutionError(RegistryError):
    """Raised when a handler reference cannot be imported or resolved."""


class MissingOptionalDependencyError(HandlerResolutionError):
    """Raised when a selected handler cannot load a declared optional package."""


class ToolRegistry:
    """Stores metadata without importing tool modules until resolution is requested."""

    def __init__(self) -> None:
        self._tools: dict[str, dict[str, ToolSpec]] = {}
        self._resolved_handlers: dict[tuple[str, str], ToolHandler] = {}

    def register_tool(self, spec: ToolSpec) -> None:
        """Register one tool, creating its category if necessary."""
        self.register_category(spec.category, (spec,))

    def register_category(self, category: str, tools: Iterable[ToolSpec]) -> None:
        """Register a batch atomically; every spec must belong to ``category``."""
        pending = tuple(tools)
        if not pending:
            raise RegistryError(f"Cannot register category {category!r} without any tools.")
        if any(spec.category != category for spec in pending):
            wrong = sorted({spec.category for spec in pending if spec.category != category})
            raise RegistryError(
                f"All tools registered under {category!r} must use that category; "
                f"found {', '.join(wrong)}."
            )

        names = [spec.name for spec in pending]
        seen: set[str] = set()
        duplicates_in_batch: set[str] = set()
        for name in names:
            if name in seen:
                duplicates_in_batch.add(name)
            seen.add(name)
        duplicates_in_batch = sorted(duplicates_in_batch)
        if duplicates_in_batch:
            raise DuplicateToolError(
                f"Duplicate tool name(s) in category {category!r}: "
                f"{', '.join(duplicates_in_batch)}."
            )

        existing = self._tools.get(category, {})
        duplicates_registered = sorted(set(names).intersection(existing))
        if duplicates_registered:
            raise DuplicateToolError(
                f"Tool(s) already registered in category {category!r}: "
                f"{', '.join(duplicates_registered)}."
            )

        category_tools = self._tools.setdefault(category, {})
        category_tools.update((spec.name, spec) for spec in pending)

    def list_categories(self) -> tuple[str, ...]:
        """Return registered categories in stable alphabetical order."""
        return tuple(sorted(self._tools))

    def list_tools(self, category: str) -> tuple[ToolSpec, ...]:
        """Return the metadata for tools in a category, sorted by tool name."""
        category_tools = self._tools.get(category)
        if category_tools is None:
            raise self._unknown_category(category)
        return tuple(category_tools[name] for name in sorted(category_tools))

    def get_tool(self, category: str, name: str) -> ToolSpec:
        """Find a tool or raise an error that includes available choices."""
        category_tools = self._tools.get(category)
        if category_tools is None:
            raise self._unknown_category(category)
        spec = category_tools.get(name)
        if spec is None:
            available = ", ".join(sorted(category_tools))
            suffix = f" Available tools: {available}." if available else ""
            raise UnknownToolError(f"Unknown tool {category} {name}.{suffix}")
        return spec

    def resolve_handler(self, category: str, name: str) -> ToolHandler:
        """Import and return the selected callable without running it."""
        spec = self.get_tool(category, name)
        key = (category, name)
        cached = self._resolved_handlers.get(key)
        if cached is not None:
            return cached

        module_name, _, attribute_path = spec.handler_ref.partition(":")
        try:
            module = import_module(module_name)
        except ModuleNotFoundError as exc:
            if self._is_declared_dependency(exc.name, spec):
                raise MissingOptionalDependencyError(
                    self._dependency_message(spec, exc.name or "unknown dependency")
                ) from exc
            if exc.name == module_name or (exc.name and module_name.startswith(exc.name + ".")):
                message = f"Handler module {module_name!r} for {category} {name} was not found."
            else:
                missing = exc.name or "unknown module"
                message = (
                    f"Could not load handler for {category} {name}: imported module {missing!r} "
                    "is missing. Declare optional imports in ToolSpec and the category "
                    "requirements file."
                )
            raise HandlerResolutionError(message) from exc
        except (ImportError, OSError) as exc:
            raise HandlerResolutionError(
                f"Could not import handler module {module_name!r} for {category} {name}: {exc}"
            ) from exc

        handler: object = module
        for attribute in attribute_path.split("."):
            try:
                handler = getattr(handler, attribute)
            except AttributeError as exc:
                raise HandlerResolutionError(
                    f"Handler {spec.handler_ref!r} for {category} {name} has no attribute "
                    f"{attribute!r}."
                ) from exc
        if not callable(handler):
            raise HandlerResolutionError(
                f"Handler reference {spec.handler_ref!r} for {category} {name} is not callable."
            )

        resolved = cast(ToolHandler, handler)
        self._resolved_handlers[key] = resolved
        return resolved

    @staticmethod
    def _is_declared_dependency(missing_name: str | None, spec: ToolSpec) -> bool:
        if not missing_name:
            return False
        return any(
            missing_name == dependency
            or missing_name.startswith(dependency + ".")
            or dependency.startswith(missing_name + ".")
            for dependency in spec.optional_dependencies
        )

    @staticmethod
    def _dependency_message(spec: ToolSpec, dependency: str) -> str:
        return (
            f"Tool {spec.category} {spec.name} requires optional Python dependency "
            f"{dependency!r}. Install the dependencies listed in requirements/{spec.category}.txt."
        )

    def _unknown_category(self, category: str) -> UnknownCategoryError:
        available = ", ".join(self.list_categories())
        suffix = (
            f" Available categories: {available}."
            if available
            else " No tools are registered yet."
        )
        return UnknownCategoryError(f"Unknown category {category!r}.{suffix}")
