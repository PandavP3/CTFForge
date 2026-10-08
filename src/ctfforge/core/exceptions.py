class CTFForgeError(Exception):
    """Base error suitable for presenting to a CTFForge user."""


class FriendlyDependencyError(CTFForgeError):
    """An optional dependency required by a requested feature is unavailable."""


class ExternalToolError(CTFForgeError):
    """An external command could not be run successfully."""


class ConfigurationError(CTFForgeError):
    """Configuration is malformed or cannot be read."""
