"""Adapter layer isolating third-party Android analysis libraries."""

from andoguard.adapters.ag_v4 import AgV4Adapter
from andoguard.adapters.ag_v5 import AgV5Adapter
from andoguard.adapters.backend import BackendAdapter, BackendExecutor
from andoguard.adapters.detect import (
    create_backend,
    detect_androguard_version,
    get_available_backends,
    select_backend_class,
)
from andoguard.adapters.fallback import FallbackAdapter
from andoguard.adapters.frida_bridge import FridaBridge

__all__ = [
    "BackendAdapter",
    "BackendExecutor",
    "AgV4Adapter",
    "AgV5Adapter",
    "FallbackAdapter",
    "FridaBridge",
    "create_backend",
    "detect_androguard_version",
    "get_available_backends",
    "select_backend_class",
]
