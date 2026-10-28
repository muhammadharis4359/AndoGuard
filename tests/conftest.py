"""Pytest fixtures for AndoGuard test suite."""

import struct
import zipfile
from pathlib import Path

import pytest

from andoguard.config import AndoGuardConfig
from andoguard.session.store import SessionStore


def create_minimal_dex_bytes() -> bytes:
    """Construct a minimal valid DEX binary (140 bytes) with valid header, map_list, and checksums."""
    import hashlib
    import zlib

    magic = b"dex\n035\x00"
    map_off = 112
    file_size = 140
    header_size = 0x70
    endian_tag = 0x12345678

    body = struct.pack(
        "<20I",
        file_size,
        header_size,
        endian_tag,
        0,  # link_size
        0,  # link_off
        map_off,
        0,  # string_ids_size
        0,  # string_ids_off
        0,  # type_ids_size
        0,  # type_ids_off
        0,  # proto_ids_size
        0,  # proto_ids_off
        0,  # field_ids_size
        0,  # field_ids_off
        0,  # method_ids_size
        0,  # method_ids_off
        0,  # class_defs_size
        0,  # class_defs_off
        28,  # data_size (map_list)
        map_off,  # data_off
    )
    # map_list: 2 items (HEADER_ITEM and MAP_LIST)
    map_list = (
        struct.pack("<I", 2)
        + struct.pack("<HHII", 0, 0, 1, 0)
        + struct.pack("<HHII", 4096, 0, 1, map_off)
    )
    full_body = body + map_list
    sha1 = hashlib.sha1(full_body).digest()
    adler = zlib.adler32(sha1 + full_body)
    return magic + struct.pack("<I", adler) + sha1 + full_body


@pytest.fixture
def minimal_dex_bytes() -> bytes:
    return create_minimal_dex_bytes()


@pytest.fixture
def sample_dex_path(tmp_path: Path, minimal_dex_bytes: bytes) -> Path:
    dex_file = tmp_path / "classes.dex"
    dex_file.write_bytes(minimal_dex_bytes)
    return dex_file


@pytest.fixture
def sample_apk_path(tmp_path: Path, minimal_dex_bytes: bytes) -> Path:
    apk_file = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr(
            "AndroidManifest.xml",
            b"<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='com.example.testapp' />",
        )
        zf.writestr("classes.dex", minimal_dex_bytes)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("assets/secret.txt", b"secret_token_12345")
        zf.writestr("META-INF/CERT.RSA", b"dummy_cert_data")
    return apk_file


@pytest.fixture
def sample_multidex_apk_path(tmp_path: Path, minimal_dex_bytes: bytes) -> Path:
    apk_file = tmp_path / "multidex_sample.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr(
            "AndroidManifest.xml", b"<manifest package='com.example.multidex'/>"
        )
        zf.writestr("classes.dex", minimal_dex_bytes)
        zf.writestr("classes2.dex", minimal_dex_bytes)
    return apk_file


@pytest.fixture
def test_config(tmp_path: Path) -> AndoGuardConfig:
    work_dir = tmp_path / "andoguard_work"
    cfg = AndoGuardConfig(work_dir=work_dir)
    cfg.ensure_directories()
    return cfg


@pytest.fixture
def test_store(test_config: AndoGuardConfig) -> SessionStore:
    return SessionStore(config=test_config)
