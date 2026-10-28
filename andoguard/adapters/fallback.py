"""Pure-Python built-in fallback adapter for offline analysis without external packages."""

from pathlib import Path
from typing import Any

from andoguard.adapters.backend import BackendAdapter
from andoguard.errors import InvalidTargetError
from andoguard.formats.apk import inspect_apk, is_apk_archive
from andoguard.formats.dex import (
    extract_dex_strings,
    is_dex_file,
    parse_dex_header,
)
from andoguard.models import BackendCapabilities, TargetInfo, TargetType
from andoguard.session.store import compute_file_hashes


class FallbackAdapter(BackendAdapter):
    """Pure-Python adapter providing baseline static analysis."""

    def __init__(self, target_path: Path | None = None) -> None:
        super().__init__(target_path)
        self._target_path = target_path
        self._target_type = TargetType.UNKNOWN
        self._target_info: TargetInfo | None = None
        self._files: list[str] = []
        self._strings: list[str] = []
        self._dex_classes_count = 0

    @property
    def name(self) -> str:
        return "builtin-fallback"

    def get_capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            backend_name=self.name,
            version="1.0.0-builtin",
            has_apk_support=True,
            has_dex_support=True,
            has_manifest_support=False,
            has_axml_support=False,
            has_arsc_support=False,
            has_disasm=False,
            has_decompile=False,
            has_xrefs=False,
            has_native_support=True,
            has_v5_features=False,
        )

    def open(self, target_path: Path) -> None:
        self._executor.submit(self._open_internal, target_path)

    def _open_internal(self, target_path: Path) -> None:
        if not target_path.exists():
            raise InvalidTargetError(str(target_path), "Target path does not exist.")

        self._target_path = target_path
        size, md5, sha1, sha256 = compute_file_hashes(target_path)

        with open(target_path, "rb") as f:
            header_bytes = f.read(128)

        if is_apk_archive(target_path):
            self._target_type = TargetType.APK
            structure = inspect_apk(target_path)
            self._files = structure.file_list
            self._target_info = TargetInfo(
                target_path=str(target_path.resolve()),
                target_type=self._target_type,
                file_size=size,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                dex_count=len(structure.dex_files),
                extra_metadata={
                    "native_libs": structure.native_libs,
                    "has_manifest": structure.has_manifest,
                    "cert_files": structure.certificate_files,
                },
            )
        elif is_dex_file(header_bytes):
            self._target_type = TargetType.DEX
            with open(target_path, "rb") as f:
                all_bytes = f.read()
            dex_header = parse_dex_header(all_bytes)
            self._dex_classes_count = dex_header.class_defs_size
            self._strings = extract_dex_strings(all_bytes, limit=1000)
            self._target_info = TargetInfo(
                target_path=str(target_path.resolve()),
                target_type=self._target_type,
                file_size=size,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                dex_count=1,
                extra_metadata={
                    "dex_version": dex_header.version,
                    "class_defs_count": dex_header.class_defs_size,
                    "string_ids_count": dex_header.string_ids_size,
                },
            )
        else:
            self._target_type = TargetType.UNKNOWN
            self._target_info = TargetInfo(
                target_path=str(target_path.resolve()),
                target_type=self._target_type,
                file_size=size,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
            )

    def close(self) -> None:
        self._executor.shutdown()

    def get_target_info(self) -> TargetInfo:
        return self._executor.submit(self._get_target_info_internal)

    def _get_target_info_internal(self) -> TargetInfo:
        if not self._target_info:
            raise InvalidTargetError("None", "No target opened.")
        return self._target_info

    def get_manifest_xml(self) -> str | None:
        return None

    def get_permissions(self) -> list[str]:
        return []

    def get_components(self) -> dict[str, list[str]]:
        return {"activities": [], "services": [], "receivers": [], "providers": []}

    def get_files(self) -> list[str]:
        return self._executor.submit(lambda: list(self._files))

    def get_classes(self, grep: str | None = None, pkg: str | None = None) -> list[str]:
        return []

    def get_methods(self, class_name: str) -> list[str]:
        return []

    def disassemble(self, class_name: str, method_name: str | None = None) -> list[str]:
        return ["Disassembly unavailable in built-in fallback mode."]

    def decompile(self, class_name: str, method_name: str | None = None) -> str | None:
        return "// Decompilation unavailable in built-in fallback mode."

    def get_strings(self, min_len: int = 4, entropy: bool = False) -> list[str]:
        return self._executor.submit(
            lambda: [s for s in self._strings if len(s) >= min_len]
        )

    def get_certificates(self) -> list[dict[str, Any]]:
        return []
