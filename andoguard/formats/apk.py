"""Pure-Python Android Application Package (APK) container inspector."""

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from andoguard.errors import InvalidTargetError


@dataclass
class ApkStructure:
    """Structural breakdown of an APK archive."""

    file_list: list[str]
    has_manifest: bool = False
    dex_files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    certificate_files: list[str] = field(default_factory=list)
    assets_files: list[str] = field(default_factory=list)
    res_files: list[str] = field(default_factory=list)


def is_apk_archive(path: Path) -> bool:
    """Check if the file is a valid zip archive containing Android structures."""
    if not path.is_file():
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            namelist = set(zf.namelist())
            return "AndroidManifest.xml" in namelist or any(
                n.endswith(".dex") for n in namelist
            )
    except (zipfile.BadZipFile, OSError):
        return False


def inspect_apk(path: Path) -> ApkStructure:
    """Inspect and catalog the contents of an APK file."""
    if not path.is_file():
        raise InvalidTargetError(str(path), "File does not exist.")

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            dex_files = [n for n in names if n.endswith(".dex")]
            native_libs = [
                n for n in names if n.startswith("lib/") and n.endswith(".so")
            ]
            cert_files = [
                n
                for n in names
                if n.startswith("META-INF/")
                and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))
            ]
            assets = [n for n in names if n.startswith("assets/")]
            res = [n for n in names if n.startswith("res/") or n == "resources.arsc"]

            return ApkStructure(
                file_list=names,
                has_manifest="AndroidManifest.xml" in names,
                dex_files=dex_files,
                native_libs=native_libs,
                certificate_files=cert_files,
                assets_files=assets,
                res_files=res,
            )
    except zipfile.BadZipFile as err:
        raise InvalidTargetError(
            str(path), f"Corrupted ZIP / APK archive: {err}"
        ) from err
