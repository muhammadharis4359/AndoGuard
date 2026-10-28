"""Runtime detection of available Android analysis backends and capabilities."""

import importlib
import logging
from pathlib import Path

from andoguard.adapters.ag_v4 import AgV4Adapter
from andoguard.adapters.ag_v5 import AgV5Adapter
from andoguard.adapters.backend import BackendAdapter
from andoguard.adapters.fallback import FallbackAdapter
from andoguard.models import BackendCapabilities

logger = logging.getLogger(__name__)


def detect_androguard_version() -> str | None:
    """Detect installed androguard package version string if present."""
    try:
        ag = importlib.import_module("androguard")
        return str(getattr(ag, "__version__", "unknown"))
    except ImportError:
        return None


def get_available_backends() -> list[BackendCapabilities]:
    """Return a list of all detected backends and their capability sets."""
    backends: list[BackendCapabilities] = []

    version = detect_androguard_version()
    if version:
        major = version.split(".")[0]
        if major == "5":
            v5_adapter = AgV5Adapter()
            backends.append(v5_adapter.get_capabilities())
            v5_adapter.close()
        elif major in ("4", "3", "unknown"):
            v4_adapter = AgV4Adapter()
            backends.append(v4_adapter.get_capabilities())
            v4_adapter.close()

    fallback = FallbackAdapter()
    backends.append(fallback.get_capabilities())
    fallback.close()

    return backends


def select_backend_class(prefer: str | None = None) -> type[BackendAdapter]:
    """Select the best available backend class according to preference and environment."""
    version = detect_androguard_version()

    if prefer:
        pref = prefer.lower()
        if "v5" in pref:
            return AgV5Adapter
        if "v4" in pref:
            return AgV4Adapter
        if "fallback" in pref or "builtin" in pref:
            return FallbackAdapter

    # Automatic selection: prefer v5, then v4, then fallback
    if version:
        major = version.split(".")[0]
        if major == "5":
            return AgV5Adapter
        return AgV4Adapter

    return FallbackAdapter


def create_backend(
    target_path: Path | None = None, prefer: str | None = None
) -> BackendAdapter:
    """Instantiate and return the optimal backend adapter."""
    backend_cls = select_backend_class(prefer=prefer)
    return backend_cls(target_path=target_path)
