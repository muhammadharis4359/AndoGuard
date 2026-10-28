"""AndoGuard custom exception hierarchy.

Provides structured, actionable errors instead of raw tracebacks for expected failures.
"""


class AndoGuardError(Exception):
    """Base class for all AndoGuard exceptions."""

    def __init__(self, message: str, remediation: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation

    def __str__(self) -> str:
        if self.remediation:
            return f"{self.message}\nRemediation: {self.remediation}"
        return self.message


class TargetNotFoundError(AndoGuardError):
    """Raised when the specified target file or directory does not exist."""

    def __init__(self, path: str) -> None:
        super().__init__(
            message=f"Target path not found: '{path}'",
            remediation="Verify the file path exists and has read permissions.",
        )


class InvalidTargetError(AndoGuardError):
    """Raised when the target is corrupt, empty, or not a recognized Android binary."""

    def __init__(
        self, path: str, reason: str = "Unrecognized or corrupt file format"
    ) -> None:
        super().__init__(
            message=f"Invalid target '{path}': {reason}",
            remediation="Provide a valid Android APK, DEX, ODEX, OAT, or VDEX file.",
        )


class UnsupportedFormatError(InvalidTargetError):
    """Raised when a specific container or format cannot be parsed by available adapters."""

    def __init__(self, format_name: str, details: str | None = None) -> None:
        msg = f"Format '{format_name}' is currently unsupported or partially quickened."
        if details:
            msg += f" Details: {details}"
        super().__init__(
            path=format_name,
            reason=msg,
        )


class SessionError(AndoGuardError):
    """Base class for session persistence and state errors."""


class SessionNotFoundError(SessionError):
    """Raised when a requested session ID or name cannot be found."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Session not found: '{identifier}'",
            remediation="Run 'andoguard sessions' to view all active and past sessions.",
        )


class SessionActiveError(SessionError):
    """Raised when attempting an operation requiring an active session without one."""

    def __init__(self) -> None:
        super().__init__(
            message="No active session found.",
            remediation="Open a target with 'andoguard open <file>' or resume with 'andoguard resume <id>'.",
        )


class BackendError(AndoGuardError):
    """Base exception for Android parser and disassembly backend failures."""


class AdapterNotAvailableError(BackendError):
    """Raised when a requested adapter is not installed or lacks required capabilities."""

    def __init__(self, adapter_name: str, required_capability: str) -> None:
        super().__init__(
            message=f"Adapter '{adapter_name}' lacks capability: '{required_capability}'",
            remediation=f"Install optional extras or upgrade dependencies for '{adapter_name}'.",
        )


class ConcurrencyError(AndoGuardError):
    """Raised when a concurrent backend execution failure or timeout occurs."""

    def __init__(self, message: str, remediation: str | None = None) -> None:
        super().__init__(message=message, remediation=remediation)


class ConfigurationError(AndoGuardError):
    """Raised when configuration validation or loading fails."""
