"""Comprehensive tests for Milestone 2: Manifest, Resources, Files, Certs, and Strings."""

import json
from pathlib import Path

from typer.testing import CliRunner

from andoguard.api import AndoGuard
from andoguard.cli.main import app
from andoguard.formats.arsc import parse_arsc_resources
from andoguard.formats.axml import axml_to_string, is_axml, parse_axml_to_element
from andoguard.formats.certs import extract_certificates_from_apk
from andoguard.static.entropy import calculate_shannon_entropy

runner = CliRunner()


def test_shannon_entropy_calculation() -> None:
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaa") == 0.0
    # High entropy random string
    h_entropy = calculate_shannon_entropy("4f8a9b2c1d3e7f6a5b4c")
    assert h_entropy > 3.0


def test_axml_parser_plain_xml() -> None:
    xml_data = b"<manifest package='com.test'><application/></manifest>"
    elem = parse_axml_to_element(xml_data)
    assert elem is not None
    assert elem.attrib.get("package") == "com.test"
    as_str = axml_to_string(xml_data)
    assert "com.test" in as_str
    assert not is_axml(xml_data)


def test_arsc_parser_empty() -> None:
    res = parse_arsc_resources(b"")
    assert res == []


def test_manifest_facade_and_data(sample_apk_path: Path, tmp_path: Path) -> None:
    with AndoGuard.open(
        sample_apk_path, session_name="m2-manifest-test", work_dir=tmp_path
    ) as ag:
        data = ag.manifest.data()
        assert data.package_name == "com.example.testapp"
        assert data.version_code == 10
        assert data.version_name == "1.0.0"
        assert data.min_sdk_version == 24
        assert data.target_sdk_version == 33

        # Permissions
        perms = ag.manifest.permissions()
        assert "android.permission.INTERNET" in perms
        assert "android.permission.ACCESS_NETWORK_STATE" in perms
        assert "com.example.testapp.CUSTOM_PERM" in ag.manifest.declared_permissions()

        # Security flags
        flags = ag.manifest.security_flags()
        assert flags.debuggable is True
        assert flags.allow_backup is True
        assert flags.uses_cleartext_traffic is True

        # Components
        exported = ag.manifest.exported_components()
        assert len(exported) >= 1
        exported_names = [c.name for c in exported]
        assert any("MainActivity" in name for name in exported_names)

        # Raw XML
        raw_xml = ag.manifest.xml()
        assert raw_xml is not None
        assert "com.example.testapp" in raw_xml


def test_file_entries_inspection(sample_apk_path: Path, tmp_path: Path) -> None:
    with AndoGuard.open(
        sample_apk_path, session_name="m2-files-test", work_dir=tmp_path
    ) as ag:
        all_files = ag.file_entries()
        assert len(all_files) >= 5

        so_files = ag.file_entries(so_only=True)
        assert len(so_files) == 1
        assert so_files[0].path == "lib/arm64-v8a/libnative.so"
        assert so_files[0].is_so is True

        asset_files = ag.file_entries(assets_only=True)
        assert len(asset_files) == 1
        assert asset_files[0].path == "assets/secret.txt"
        assert asset_files[0].is_asset is True


def test_certificates_and_signatures(sample_apk_path: Path, tmp_path: Path) -> None:
    report = extract_certificates_from_apk(sample_apk_path)
    assert report.is_signed is True
    assert report.v1_signature is True
    assert len(report.certificates) >= 1

    cert = report.certificates[0]
    assert "AndoGuard Test" in cert.subject
    assert len(cert.sha256_fingerprint) == 64
    assert len(cert.sha1_fingerprint) == 40
    assert cert.is_self_signed is True

    with AndoGuard.open(
        sample_apk_path, session_name="m2-certs-test", work_dir=tmp_path
    ) as ag:
        ag_report = ag.certs()
        assert ag_report.is_signed is True
        assert len(ag_report.certificates) >= 1


def test_string_items_extraction(sample_apk_path: Path, tmp_path: Path) -> None:
    with AndoGuard.open(
        sample_apk_path, session_name="m2-strings-test", work_dir=tmp_path
    ) as ag:
        items = ag.string_items(min_len=3, entropy=True)
        if len(items) >= 2:
            assert items[0].entropy >= items[1].entropy


def test_cli_manifest_command(sample_apk_path: Path, tmp_path: Path) -> None:
    # Open first
    open_res = runner.invoke(
        app,
        ["open", str(sample_apk_path), "--name", "cli-m2", "--work-dir", str(tmp_path)],
    )
    assert open_res.exit_code == 0

    # Manifest human readable
    man_res = runner.invoke(app, ["manifest", "--work-dir", str(tmp_path)])
    assert man_res.exit_code == 0
    assert (
        "Manifest Overview" in man_res.output or "com.example.testapp" in man_res.output
    )

    # Manifest raw
    raw_res = runner.invoke(app, ["manifest", "--raw", "--work-dir", str(tmp_path)])
    assert raw_res.exit_code == 0
    assert "com.example.testapp" in raw_res.output

    # Manifest json
    json_res = runner.invoke(app, ["manifest", "--json", "--work-dir", str(tmp_path)])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert parsed["package_name"] == "com.example.testapp"
    assert parsed["security_flags"]["debuggable"] is True


def test_cli_certs_command(sample_apk_path: Path, tmp_path: Path) -> None:
    open_res = runner.invoke(
        app,
        [
            "open",
            str(sample_apk_path),
            "--name",
            "cli-certs",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert open_res.exit_code == 0

    certs_res = runner.invoke(app, ["certs", "--work-dir", str(tmp_path)])
    assert certs_res.exit_code == 0
    assert "Signed Status" in certs_res.output

    json_res = runner.invoke(app, ["certs", "--json", "--work-dir", str(tmp_path)])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert parsed["is_signed"] is True
    assert len(parsed["certificates"]) >= 1


def test_cli_files_command(sample_apk_path: Path, tmp_path: Path) -> None:
    open_res = runner.invoke(
        app,
        [
            "open",
            str(sample_apk_path),
            "--name",
            "cli-files",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert open_res.exit_code == 0

    files_res = runner.invoke(app, ["files", "--work-dir", str(tmp_path)])
    assert files_res.exit_code == 0
    assert "classes.dex" in files_res.output

    so_res = runner.invoke(app, ["files", "--so", "--work-dir", str(tmp_path)])
    assert so_res.exit_code == 0
    assert "libnative.so" in so_res.output

    assets_res = runner.invoke(app, ["files", "--assets", "--work-dir", str(tmp_path)])
    assert assets_res.exit_code == 0
    assert "secret.txt" in assets_res.output

    json_res = runner.invoke(app, ["files", "--json", "--work-dir", str(tmp_path)])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert any(item["path"] == "classes.dex" for item in parsed)


def test_cli_strings_command(sample_apk_path: Path, tmp_path: Path) -> None:
    open_res = runner.invoke(
        app,
        [
            "open",
            str(sample_apk_path),
            "--name",
            "cli-strings",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert open_res.exit_code == 0

    str_res = runner.invoke(app, ["strings", "--work-dir", str(tmp_path)])
    assert str_res.exit_code == 0

    ent_res = runner.invoke(app, ["strings", "--entropy", "--work-dir", str(tmp_path)])
    assert ent_res.exit_code == 0

    json_res = runner.invoke(app, ["strings", "--json", "--work-dir", str(tmp_path)])
    assert json_res.exit_code == 0
