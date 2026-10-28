"""Pure-Python built-in fallback adapter for offline analysis without external packages."""

import zipfile
from pathlib import Path
from typing import Any

from andoguard.adapters.backend import BackendAdapter
from andoguard.errors import InvalidTargetError
from andoguard.formats.apk import inspect_apk, is_apk_archive
from andoguard.formats.arsc import parse_arsc_resources
from andoguard.formats.axml import axml_to_string, parse_axml_to_element
from andoguard.formats.certs import extract_certificates_from_apk
from andoguard.formats.dex import (
    extract_dex_strings,
    is_dex_file,
    parse_dex_header,
)
from andoguard.formats.manifest import parse_manifest_element
from andoguard.models import (
    ApkFileEntry,
    BackendCapabilities,
    ClassDetail,
    CodeResult,
    DisasmResult,
    ManifestData,
    ResourceEntry,
    SignatureReport,
    StringItem,
    TargetInfo,
    TargetType,
)
from andoguard.session.store import compute_file_hashes
from andoguard.static.entropy import calculate_shannon_entropy


class FallbackAdapter(BackendAdapter):
    """Pure-Python adapter providing baseline static analysis."""

    def __init__(self, target_path: Path | None = None) -> None:
        super().__init__(target_path)
        self._target_path = target_path
        self._target_type = TargetType.UNKNOWN
        self._target_info: TargetInfo | None = None
        self._files: list[str] = []
        self._file_entries: list[ApkFileEntry] = []
        self._strings: list[str] = []
        self._manifest_data: ManifestData | None = None
        self._resources: list[ResourceEntry] = []
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
            has_manifest_support=True,
            has_axml_support=True,
            has_arsc_support=True,
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

            # Read detailed file entries from zip
            self._file_entries = []
            try:
                with zipfile.ZipFile(target_path, "r") as zf:
                    for info in zf.infolist():
                        p = info.filename
                        is_so = p.startswith("lib/") and p.endswith(".so")
                        is_asset = p.startswith("assets/")
                        is_dex = p.endswith(".dex")
                        self._file_entries.append(
                            ApkFileEntry(
                                path=p,
                                size=info.file_size,
                                is_so=is_so,
                                is_asset=is_asset,
                                is_dex=is_dex,
                                crc=info.CRC,
                            )
                        )

                    # Extract manifest
                    if "AndroidManifest.xml" in zf.namelist():
                        manifest_bytes = zf.read("AndroidManifest.xml")
                        raw_xml = axml_to_string(manifest_bytes)
                        elem = parse_axml_to_element(manifest_bytes)
                        if elem is not None:
                            self._manifest_data = parse_manifest_element(
                                elem, raw_xml=raw_xml
                            )

                    # Extract resources
                    if "resources.arsc" in zf.namelist():
                        arsc_bytes = zf.read("resources.arsc")
                        self._resources = parse_arsc_resources(arsc_bytes)

                    # Extract strings from all DEX files
                    for dex_name in structure.dex_files:
                        dex_bytes = zf.read(dex_name)
                        dex_strings = extract_dex_strings(dex_bytes, limit=5000)
                        self._strings.extend(dex_strings)
            except Exception:
                pass

            m = self._manifest_data
            self._target_info = TargetInfo(
                target_path=str(target_path.resolve()),
                target_type=self._target_type,
                file_size=size,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                package_name=m.package_name if m else None,
                version_code=m.version_code if m else None,
                version_name=m.version_name if m else None,
                min_sdk_version=m.min_sdk_version if m else None,
                target_sdk_version=m.target_sdk_version if m else None,
                dex_count=len(structure.dex_files),
                permissions_count=len(m.permissions) if m else 0,
                activities_count=len(
                    [c for c in m.components if c.component_type == "activity"]
                )
                if m
                else 0,
                services_count=len(
                    [c for c in m.components if c.component_type == "service"]
                )
                if m
                else 0,
                receivers_count=len(
                    [c for c in m.components if c.component_type == "receiver"]
                )
                if m
                else 0,
                providers_count=len(
                    [c for c in m.components if c.component_type == "provider"]
                )
                if m
                else 0,
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
            self._strings = extract_dex_strings(all_bytes, limit=10000)
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
        return self._executor.submit(
            lambda: self._manifest_data.raw_xml if self._manifest_data else None
        )

    def get_permissions(self) -> list[str]:
        return self._executor.submit(
            lambda: list(self._manifest_data.permissions) if self._manifest_data else []
        )

    def get_components(self) -> dict[str, list[str]]:
        return self._executor.submit(self._get_components_internal)

    def _get_components_internal(self) -> dict[str, list[str]]:
        if not self._manifest_data:
            return {"activities": [], "services": [], "receivers": [], "providers": []}
        return {
            "activities": [
                c.name
                for c in self._manifest_data.components
                if c.component_type == "activity"
            ],
            "services": [
                c.name
                for c in self._manifest_data.components
                if c.component_type == "service"
            ],
            "receivers": [
                c.name
                for c in self._manifest_data.components
                if c.component_type == "receiver"
            ],
            "providers": [
                c.name
                for c in self._manifest_data.components
                if c.component_type == "provider"
            ],
        }

    def get_files(self) -> list[str]:
        return self._executor.submit(lambda: list(self._files))

    def get_manifest_data(self) -> ManifestData:
        return self._executor.submit(lambda: self._manifest_data or ManifestData())

    def get_resources(
        self, res_type: str | None = None, grep: str | None = None
    ) -> list[ResourceEntry]:
        return self._executor.submit(self._get_resources_internal, res_type, grep)

    def _get_resources_internal(
        self, res_type: str | None = None, grep: str | None = None
    ) -> list[ResourceEntry]:
        results: list[ResourceEntry] = []
        for r in self._resources:
            if res_type and r.res_type.lower() != res_type.lower():
                continue
            if (
                grep
                and grep.lower() not in r.name.lower()
                and (not r.value or grep.lower() not in r.value.lower())
            ):
                continue
            results.append(r)
        return results

    def get_file_entries(
        self, so_only: bool = False, assets_only: bool = False
    ) -> list[ApkFileEntry]:
        return self._executor.submit(
            self._get_file_entries_internal, so_only, assets_only
        )

    def _get_file_entries_internal(
        self, so_only: bool = False, assets_only: bool = False
    ) -> list[ApkFileEntry]:
        entries: list[ApkFileEntry] = []
        for e in self._file_entries:
            if so_only and not e.is_so:
                continue
            if assets_only and not e.is_asset:
                continue
            entries.append(e)
        return entries

    def get_signature_report(self) -> SignatureReport:
        return self._executor.submit(self._get_signature_report_internal)

    def _get_signature_report_internal(self) -> SignatureReport:
        if not self._target_path:
            return SignatureReport(is_signed=False)
        return extract_certificates_from_apk(self._target_path)

    def get_string_items(
        self, min_len: int = 4, calculate_entropy: bool = False
    ) -> list[StringItem]:
        return self._executor.submit(
            self._get_string_items_internal, min_len, calculate_entropy
        )

    def _get_string_items_internal(
        self, min_len: int = 4, calculate_entropy: bool = False
    ) -> list[StringItem]:
        unique_strings = {s for s in self._strings if len(s) >= min_len}
        items: list[StringItem] = []
        for s in unique_strings:
            ent = calculate_shannon_entropy(s) if calculate_entropy else 0.0
            items.append(StringItem(value=s, length=len(s), entropy=ent, source="dex"))

        if calculate_entropy:
            items.sort(key=lambda x: x.entropy, reverse=True)
        else:
            items.sort(key=lambda x: x.value)
        return items

    def get_classes(self, grep: str | None = None, pkg: str | None = None) -> list[str]:
        return []

    def get_methods(self, class_name: str) -> list[str]:
        return []

    def disassemble(self, class_name: str, method_name: str | None = None) -> list[str]:
        return ["Disassembly unavailable in built-in fallback mode."]

    def decompile(self, class_name: str, method_name: str | None = None) -> str | None:
        return "// Decompilation unavailable in built-in fallback mode."

    def get_class_detail(self, class_name: str) -> ClassDetail | None:
        return None

    def get_fields(self, class_name: str) -> list[str]:
        return []

    def disassemble_method(
        self, class_name: str, method_name: str | None = None, cfg: bool = False
    ) -> DisasmResult:
        target_repr = f"{class_name}#{method_name}" if method_name else class_name
        return DisasmResult(
            target=target_repr,
            instructions=["// Disassembly unavailable in built-in fallback mode."],
            cfg=None,
        )

    def decompile_source(
        self,
        class_name: str,
        method_name: str | None = None,
        lang: str = "java",
        cfg: bool = False,
    ) -> CodeResult:
        target_repr = f"{class_name}#{method_name}" if method_name else class_name
        return CodeResult(
            target=target_repr,
            language=lang,
            source="// Decompilation unavailable in built-in fallback mode.",
            cfg=None,
        )

    def get_strings(self, min_len: int = 4, entropy: bool = False) -> list[str]:
        return [item.value for item in self.get_string_items(min_len, entropy)]

    def get_certificates(self) -> list[dict[str, Any]]:
        rep = self.get_signature_report()
        return [
            {
                "issuer": c.issuer,
                "subject": c.subject,
                "sha256": c.sha256_fingerprint,
                "serial_number": c.serial_number,
            }
            for c in rep.certificates
        ]
