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


class DynamicInstrumentationError(AndoGuardError):
    """Base exception for Frida and dynamic runtime instrumentation failures."""


class FridaUnavailableError(DynamicInstrumentationError):
    """Raised when Frida is not installed or frida-server is unreachable."""

    def __init__(self, details: str = "Frida runtime is not available.") -> None:
        super().__init__(
            message=f"Frida bridge failure: {details}",
            remediation="Install frida with 'pip install frida frida-tools' and ensure frida-server is running on device.",
        )


class DeviceNotFoundError(DynamicInstrumentationError):
    """Raised when the specified target device or emulator is not connected."""

    def __init__(self, device_id: str | None = None) -> None:
        dev_msg = f"'{device_id}'" if device_id else "any USB or emulator device"
        super().__init__(
            message=f"No connected Android device found matching {dev_msg}.",
            remediation="Connect device via USB with ADB debugging enabled or run 'adb devices'.",
        )


class ProcessNotFoundError(DynamicInstrumentationError):
    """Raised when target process or package cannot be found on device."""

    def __init__(self, target: str) -> None:
        super().__init__(
            message=f"Process or package '{target}' not found running on device.",
            remediation="Verify package name or spawn it with 'andoguard dynamic spawn <package>'.",
        )


class HookError(DynamicInstrumentationError):
    """Raised when hook script compilation or injection fails."""

    def __init__(self, message: str, script: str | None = None) -> None:
        super().__init__(
            message=f"Hook injection failed: {message}",
            remediation="Review hook script syntax, class/method names, and parameters.",
        )


class AiError(AndoGuardError):
    """Base exception for AI reasoning and LLM provider failures."""


class AiProviderUnavailableError(AiError):
    """Raised when the specified AI provider is not reachable or unconfigured."""

    def __init__(self, provider: str, details: str = "Missing API key or host unreachable.") -> None:
        super().__init__(
            message=f"AI provider '{provider}' is not available: {details}",
            remediation="Set appropriate environment variable (e.g. GEMINI_API_KEY, OPENAI_API_KEY) or check service status.",
        )


class AiAuthenticationError(AiError):
    """Raised when AI provider rejects credentials."""

    def __init__(self, provider: str) -> None:
        super().__init__(
            message=f"Authentication failed for AI provider '{provider}'.",
            remediation="Verify API key or token validity.",
        )


class AiRateLimitError(AiError):
    """Raised when AI provider rate limit is exceeded."""

    def __init__(self, provider: str) -> None:
        super().__init__(
            message=f"Rate limit exceeded for AI provider '{provider}'.",
            remediation="Wait before retrying or use a provider with higher quotas.",
        )

