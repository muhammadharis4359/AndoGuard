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


def generate_test_cert_der() -> bytes:
    """Generate a real self-signed DER certificate for test fixtures."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "AndoGuard Test"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "AndoGuard Security"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(12345678901234567890)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def sample_apk_path(tmp_path: Path, minimal_dex_bytes: bytes) -> Path:
    apk_file = tmp_path / "sample.apk"
    manifest_content = (
        b"<manifest xmlns:android='http://schemas.android.com/apk/res/android' "
        b"package='com.example.testapp' android:versionCode='10' android:versionName='1.0.0'>\n"
        b"  <uses-sdk android:minSdkVersion='24' android:targetSdkVersion='33'/>\n"
        b"  <uses-permission android:name='android.permission.INTERNET'/>\n"
        b"  <uses-permission android:name='android.permission.ACCESS_NETWORK_STATE'/>\n"
        b"  <permission android:name='com.example.testapp.CUSTOM_PERM'/>\n"
        b"  <application android:name='.App' android:debuggable='true' android:allowBackup='true' android:usesCleartextTraffic='true'>\n"
        b"    <activity android:name='.MainActivity' android:exported='true'>\n"
        b"      <intent-filter>\n"
        b"        <action android:name='android.intent.action.MAIN'/>\n"
        b"        <category android:name='android.intent.category.LAUNCHER'/>\n"
        b"      </intent-filter>\n"
        b"    </activity>\n"
        b"    <service android:name='.SecretService' android:exported='false'/>\n"
        b"  </application>\n"
        b"</manifest>"
    )
    cert_bytes = generate_test_cert_der()

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
        zf.writestr("classes.dex", minimal_dex_bytes)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("assets/secret.txt", b"secret_token_12345")
        zf.writestr("META-INF/CERT.RSA", cert_bytes)
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
