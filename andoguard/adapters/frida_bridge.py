"""Frida bridge interface and device connection manager stub.

Full dynamic instrumentation capabilities are implemented in Milestone 5.
"""

from typing import Any


class FridaBridge:
    """Wrapper over Frida Python API for dynamic instrumentation."""

    def __init__(self) -> None:
        self._device: Any | None = None

    @property
    def is_available(self) -> bool:
        """Check if Frida package is installed."""
        try:
            import frida  # noqa: F401

            return True
        except ImportError:
            return False
