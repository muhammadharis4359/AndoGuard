"""Tests for pure-Python format parsers (APK and DEX)."""

from pathlib import Path

import pytest

from andoguard.errors import InvalidTargetError
from andoguard.formats.apk import inspect_apk, is_apk_archive
from andoguard.formats.dex import (
    is_dex_file,
    parse_dex_header,
)


def test_dex_header_parsing(minimal_dex_bytes: bytes) -> None:
    assert is_dex_file(minimal_dex_bytes) is True
    assert is_dex_file(b"NOT_DEX_BYTES") is False

    header = parse_dex_header(minimal_dex_bytes)
    assert header.version == "035"
    assert header.header_size == 0x70
    assert header.class_defs_size == 0


def test_dex_corrupt_fails(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.dex"
    corrupt.write_bytes(b"dex\n035\x00" + b"\x00" * 20)  # less than 112 bytes
    with pytest.raises(InvalidTargetError):
        parse_dex_header(corrupt.read_bytes())


def test_apk_inspection(sample_apk_path: Path) -> None:
    assert is_apk_archive(sample_apk_path) is True

    structure = inspect_apk(sample_apk_path)
    assert structure.has_manifest is True
    assert "classes.dex" in structure.dex_files
    assert any("libnative.so" in lib for lib in structure.native_libs)
    assert any("secret.txt" in a for a in structure.assets_files)
    assert any("CERT.RSA" in c for c in structure.certificate_files)


def test_multidex_apk_inspection(sample_multidex_apk_path: Path) -> None:
    assert is_apk_archive(sample_multidex_apk_path) is True
    structure = inspect_apk(sample_multidex_apk_path)
    assert len(structure.dex_files) == 2
    assert "classes.dex" in structure.dex_files
    assert "classes2.dex" in structure.dex_files
