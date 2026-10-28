"""Demonstration of AndoGuard public library API."""

import tempfile
import zipfile
from pathlib import Path

from andoguard import AndoGuard


def create_minimal_apk(path: Path) -> None:
    """Create a minimal synthetic APK fixture for demonstration."""
    import hashlib
    import struct
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
        0,
        0,
        map_off,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        28,
        map_off,
    )
    map_list = (
        struct.pack("<I", 2)
        + struct.pack("<HHII", 0, 0, 1, 0)
        + struct.pack("<HHII", 4096, 0, 1, map_off)
    )
    full_body = body + map_list
    sha1 = hashlib.sha1(full_body).digest()
    adler = zlib.adler32(sha1 + full_body)
    dex_bytes = magic + struct.pack("<I", adler) + sha1 + full_body

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.demo'/>")
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("assets/config.json", b'{"key": "value"}')


def main() -> None:
    print("=== AndoGuard Public Library API Demo ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        apk_path = Path(tmpdir) / "demo_app.apk"
        create_minimal_apk(apk_path)

        # 1. Open target and initialize a persistent session
        ag = AndoGuard.open(
            apk_path, session_name="demo-session", work_dir=Path(tmpdir) / ".andoguard"
        )
        print(f"[+] Opened target: {apk_path.name}")
        print(
            f"[+] Session ID: {ag.session_record.session_id} (Name: {ag.session_record.name})"
        )

        # 2. Inspect target metadata
        info = ag.info()
        print(f"[+] Format: {info.target_type.value.upper()}")
        print(f"[+] SHA-256: {info.sha256}")
        print(f"[+] DEX files count: {info.dex_count}")

        # 3. List files within container
        files = ag.files()
        print(f"[+] Files in APK ({len(files)}): {files}")

        # 4. Clean up resources
        ag.close()
        print("[+] Session closed successfully.")


if __name__ == "__main__":
    main()
