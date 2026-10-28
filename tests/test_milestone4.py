"""Comprehensive tests for Milestone 4: Xrefs, FTS5 Search, Secrets, Vulns, Native ELF, and Diff."""

import json
import struct
from pathlib import Path

from typer.testing import CliRunner

from andoguard.api import AndoGuard
from andoguard.cli.main import app
from andoguard.formats.elf import is_elf_file, parse_elf_bytes
from andoguard.models import (
    ManifestComponent,
    ManifestData,
    ManifestSecurityFlags,
    SeverityLevel,
    StringItem,
)
from andoguard.static.diff import diff_andoguard_instances
from andoguard.static.secrets import scan_strings_for_secrets
from andoguard.static.vulns import audit_target_vulnerabilities

runner = CliRunner()


def create_synthetic_elf_bytes(bits: int = 64, machine: int = 0xB7) -> bytes:
    """Construct a minimal valid ELF header."""
    ei_class = 2 if bits == 64 else 1
    magic = b"\x7fELF" + bytes([ei_class, 1, 1, 0]) + b"\x00" * 8
    endian = "<"
    if bits == 32:
        # 52 bytes header
        header = struct.pack(
            f"{endian}16sHHIIIIIHHHHHH",
            magic,
            3,  # ET_DYN
            machine,
            1,  # EV_CURRENT
            0x1000,
            0,
            52,  # shoff
            0,
            52,
            0,
            0,
            40,  # shentsize
            0,   # shnum
            0,
        )
    else:
        # 64 bytes header
        header = struct.pack(
            f"{endian}16sHHIQQQIHHHHHH",
            magic,
            3,  # ET_DYN
            machine,
            1,  # EV_CURRENT
            0x1000,
            0,
            64,  # shoff
            0,
            64,
            0,
            0,
            64,  # shentsize
            0,   # shnum
            0,
        )
    return header


def test_elf_parser() -> None:
    """Test ELF parsing for 32-bit and 64-bit architectures."""
    elf64 = create_synthetic_elf_bytes(bits=64, machine=0xB7)
    assert is_elf_file(elf64)
    info64 = parse_elf_bytes(elf64, "libtest64.so")
    assert info64.arch == "AArch64"
    assert info64.bits == 64
    assert info64.endianness == "little"

    elf32 = create_synthetic_elf_bytes(bits=32, machine=0x28)
    assert is_elf_file(elf32)
    info32 = parse_elf_bytes(elf32, "libtest32.so")
    assert info32.arch == "ARM"
    assert info32.bits == 32

    # Non-ELF bytes
    assert not is_elf_file(b"PK\x03\x04")
    invalid_info = parse_elf_bytes(b"not_an_elf")
    assert invalid_info.arch == "unknown"


def test_secrets_scanner() -> None:
    """Test secret pattern detection and entropy filtering."""
    items = [
        StringItem(value="AKIA1234567890ABCDEF", length=20, source="dex"),
        StringItem(value="AIzaSyB1234567890abcdefghijklmnopqrstu", length=39, source="res"),
        StringItem(value="-----BEGIN RSA PRIVATE KEY-----", length=31, source="asset"),
        StringItem(value="normal_app_string_value", length=23, source="dex"),
        StringItem(value="4f8a9b2c1d3e7f6a5b4c3d2e1f0a9b8c", length=32, source="dex"),
    ]
    findings = scan_strings_for_secrets(items, min_entropy=3.5)
    types = [f.secret_type for f in findings]

    assert "AWS Access Key" in types
    assert "Google API Key" in types
    assert "Private Key Header" in types
    assert any("High-Entropy" in t or "Generic" in t for t in types)


def test_vulns_scanner_masvs() -> None:
    """Test MASVS security audit checks."""
    manifest = ManifestData(
        security_flags=ManifestSecurityFlags(
            debuggable=True,
            uses_cleartext_traffic=True,
            allow_backup=True,
            test_only=True,
        ),
        components=[
            ManifestComponent(
                name="com.example.ExportedAct",
                component_type="activity",
                exported=True,
                permission=None,
            )
        ],
    )
    strings = [
        "AES/ECB/PKCS5Padding",
        "MD5",
        "TrustAllCertificates",
    ]

    report = audit_target_vulnerabilities("testapp", manifest=manifest, strings=strings)
    masvs_ids = {f.masvs_id for f in report.findings}

    assert "MASVS-CODE-2" in masvs_ids
    assert "MASVS-NETWORK-1" in masvs_ids
    assert "MASVS-STORAGE-2" in masvs_ids
    assert "MASVS-PLATFORM-1" in masvs_ids
    assert "MASVS-CRYPTO-1" in masvs_ids
    assert "MASVS-CRYPTO-2" in masvs_ids
    assert "MASVS-NETWORK-2" in masvs_ids

    assert report.summary[SeverityLevel.CRITICAL.value] >= 2
    assert report.summary[SeverityLevel.HIGH.value] >= 2


def test_api_m4_features(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test Xrefs, search, secrets, vulns, and native methods on AndoGuard API."""
    with AndoGuard.open(
        sample_apk_path, session_name="m4-api-test", work_dir=tmp_path
    ) as ag:
        # Xrefs
        xref_res = ag.xrefs("Lcom/example/MainActivity;")
        assert xref_res.target == "Lcom/example/MainActivity;"
        assert isinstance(xref_res.xrefs_to, list)

        # Secrets
        secrets = ag.secrets()
        assert isinstance(secrets, list)

        # Vulns
        vulns_rep = ag.vulns()
        assert vulns_rep.target is not None
        assert isinstance(vulns_rep.findings, list)

        # Search index and search
        count = ag.build_search_index()
        assert count >= 0
        search_res = ag.search("com.example")
        assert isinstance(search_res, list)

        # Native libs
        native_libs = ag.native()
        assert isinstance(native_libs, list)


def test_diff_engine(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test APK structural diff engine."""
    with AndoGuard.open(
        sample_apk_path, session_name="m4-diff-1", work_dir=tmp_path
    ) as ag1:
        with AndoGuard.open(
            sample_apk_path, session_name="m4-diff-2", work_dir=tmp_path
        ) as ag2:
            diff_res = diff_andoguard_instances(ag1, ag2)
            assert diff_res.added_files == []
            assert diff_res.removed_files == []
            assert diff_res.added_classes == []


def test_cli_xrefs_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard xrefs' command."""
    runner.invoke(app, ["open", str(sample_apk_path), "--work-dir", str(tmp_path)])

    res = runner.invoke(
        app,
        ["xrefs", "Lcom/example/MainActivity;", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["xrefs", "Lcom/example/MainActivity;", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert "target" in parsed
    assert "xrefs_to" in parsed


def test_cli_search_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard search' command."""
    runner.invoke(app, ["open", str(sample_apk_path), "--work-dir", str(tmp_path)])

    res = runner.invoke(
        app,
        ["search", "com.example", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["search", "com.example", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert isinstance(parsed, list)


def test_cli_secrets_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard secrets' command."""
    runner.invoke(app, ["open", str(sample_apk_path), "--work-dir", str(tmp_path)])

    res = runner.invoke(
        app,
        ["secrets", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["secrets", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert isinstance(parsed, list)


def test_cli_vulns_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard vulns' command."""
    runner.invoke(app, ["open", str(sample_apk_path), "--work-dir", str(tmp_path)])

    res = runner.invoke(
        app,
        ["vulns", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["vulns", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert "findings" in parsed
    assert "summary" in parsed


def test_cli_native_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard native' command."""
    runner.invoke(app, ["open", str(sample_apk_path), "--work-dir", str(tmp_path)])

    res = runner.invoke(
        app,
        ["native", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["native", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert isinstance(parsed, list)


def test_cli_diff_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard diff' command."""
    runner.invoke(app, ["open", str(sample_apk_path), "--work-dir", str(tmp_path)])

    res = runner.invoke(
        app,
        ["diff", str(sample_apk_path), "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["diff", str(sample_apk_path), "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert "added_files" in parsed
    assert "removed_files" in parsed
