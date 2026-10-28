"""Tests for adapter detection, fallback, and capability contracts."""

from pathlib import Path

import pytest

from andoguard.adapters.ag_v4 import AgV4Adapter
from andoguard.adapters.detect import (
    detect_androguard_version,
    get_available_backends,
    select_backend_class,
)
from andoguard.adapters.fallback import FallbackAdapter
from andoguard.models import TargetType


def test_detect_available_backends() -> None:
    backends = get_available_backends()
    assert len(backends) >= 1
    # Fallback backend must always be available
    assert any(b.backend_name == "builtin-fallback" for b in backends)


def test_fallback_adapter_apk(sample_apk_path: Path) -> None:
    adapter = FallbackAdapter()
    try:
        adapter.open(sample_apk_path)
        info = adapter.get_target_info()
        assert info.target_type == TargetType.APK
        assert info.dex_count == 1
        assert len(adapter.get_files()) >= 4
    finally:
        adapter.close()


def test_fallback_adapter_dex(sample_dex_path: Path) -> None:
    adapter = FallbackAdapter()
    try:
        adapter.open(sample_dex_path)
        info = adapter.get_target_info()
        assert info.target_type == TargetType.DEX
        assert info.dex_count == 1
    finally:
        adapter.close()


def test_select_backend_preference() -> None:
    fallback_cls = select_backend_class(prefer="fallback")
    assert fallback_cls == FallbackAdapter


def test_ag_v4_adapter_contract(sample_apk_path: Path) -> None:
    version = detect_androguard_version()
    if not version:
        pytest.skip("Androguard not installed in test environment")

    adapter = AgV4Adapter()
    try:
        adapter.open(sample_apk_path)
        info = adapter.get_target_info()
        assert info.target_type == TargetType.APK
        assert info.dex_count >= 1
        caps = adapter.get_capabilities()
        assert caps.has_apk_support is True
        assert caps.has_dex_support is True
    finally:
        adapter.close()
