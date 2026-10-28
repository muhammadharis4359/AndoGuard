"""Androguard v5 adapter implementation."""

import zipfile
from pathlib import Path
from typing import Any

from andoguard.adapters.backend import BackendAdapter
from andoguard.errors import BackendError, InvalidTargetError
from andoguard.formats.apk import is_apk_archive
from andoguard.formats.arsc import parse_arsc_resources
from andoguard.formats.axml import axml_to_string, parse_axml_to_element
from andoguard.formats.certs import extract_certificates_from_apk
from andoguard.formats.dex import is_dex_file
from andoguard.formats.manifest import parse_manifest_element
from andoguard.models import (
    ApkFileEntry,
    BackendCapabilities,
    ClassDetail,
    CodeResult,
    DisasmResult,
    FieldInfo,
    ManifestData,
    MethodInfo,
    ResourceEntry,
    SignatureReport,
    StringItem,
    TargetInfo,
    TargetType,
)
from andoguard.session.store import compute_file_hashes
from andoguard.static.cfg import build_cfg_from_basic_blocks
from andoguard.static.entropy import calculate_shannon_entropy

try:
    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
except Exception:
    pass


class AgV5Adapter(BackendAdapter):
    """Adapter bridging AndoGuard to Androguard 5.x APIs."""

    def __init__(self, target_path: Path | None = None) -> None:
        super().__init__(target_path)
        self._target_path = target_path
        self._apk_obj: Any = None
        self._dex_objs: list[Any] = []
        self._analysis_obj: Any = None
        self._target_type = TargetType.UNKNOWN
        self._target_info: TargetInfo | None = None

    @property
    def name(self) -> str:
        return "androguard-v5"

    def get_capabilities(self) -> BackendCapabilities:
        import androguard

        version = getattr(androguard, "__version__", "5.x")
        return BackendCapabilities(
            backend_name=self.name,
            version=str(version),
            has_apk_support=True,
            has_dex_support=True,
            has_manifest_support=True,
            has_axml_support=True,
            has_arsc_support=True,
            has_disasm=True,
            has_decompile=True,
            has_xrefs=True,
            has_native_support=True,
            has_v5_features=True,
        )

    def open(self, target_path: Path) -> None:
        self._executor.submit(self._open_internal, target_path)

    def _open_internal(self, target_path: Path) -> None:
        if not target_path.exists():
            raise InvalidTargetError(str(target_path), "File does not exist.")

        self._target_path = target_path
        size, md5, sha1, sha256 = compute_file_hashes(target_path)

        with open(target_path, "rb") as f:
            header_bytes = f.read(128)

        try:
            if is_apk_archive(target_path):
                self._target_type = TargetType.APK
                # In Androguard v5, APK and Analysis may be imported from androguard.core or top-level
                try:
                    from androguard.misc import AnalyzeAPK

                    a, d, dx = AnalyzeAPK(str(target_path))
                except ImportError:
                    from androguard.core.analysis.analysis import Analysis
                    from androguard.core.apk import APK

                    a = APK(str(target_path))
                    dx = Analysis()
                    d = []

                self._apk_obj = a
                self._dex_objs = list(d) if isinstance(d, list) else [d]
                self._analysis_obj = dx

                def _safe_call(method_name: str, default: Any = None) -> Any:
                    if not a or not hasattr(a, method_name):
                        return default
                    try:
                        val = getattr(a, method_name)()
                        return val if val is not None else default
                    except Exception:
                        return default

                pkg_name = _safe_call("get_package")
                ver_code = _safe_call("get_androidversion_code")
                ver_name = _safe_call("get_androidversion_name")
                min_sdk = _safe_call("get_min_sdk_version")
                target_sdk = _safe_call("get_target_sdk_version")
                app_name = _safe_call("get_app_name")
                main_act = _safe_call("get_main_activity")

                perms = _safe_call("get_permissions", [])
                activities = _safe_call("get_activities", [])
                services = _safe_call("get_services", [])
                receivers = _safe_call("get_receivers", [])
                providers = _safe_call("get_providers", [])

                self._target_info = TargetInfo(
                    target_path=str(target_path.resolve()),
                    target_type=self._target_type,
                    file_size=size,
                    md5=md5,
                    sha1=sha1,
                    sha256=sha256,
                    package_name=str(pkg_name) if pkg_name else None,
                    version_code=int(ver_code)
                    if ver_code and str(ver_code).isdigit()
                    else None,
                    version_name=str(ver_name) if ver_name else None,
                    min_sdk_version=int(min_sdk)
                    if min_sdk and str(min_sdk).isdigit()
                    else None,
                    target_sdk_version=int(target_sdk)
                    if target_sdk and str(target_sdk).isdigit()
                    else None,
                    app_name=str(app_name) if app_name else None,
                    main_activity=str(main_act) if main_act else None,
                    dex_count=len(self._dex_objs),
                    permissions_count=len(perms),
                    activities_count=len(activities),
                    services_count=len(services),
                    receivers_count=len(receivers),
                    providers_count=len(providers),
                )
            elif is_dex_file(header_bytes):
                self._target_type = TargetType.DEX
                from androguard.misc import AnalyzeDex

                _, d, dx = AnalyzeDex(str(target_path))
                self._apk_obj = None
                self._dex_objs = [d]
                self._analysis_obj = dx

                classes = list(dx.get_classes()) if dx else []
                self._target_info = TargetInfo(
                    target_path=str(target_path.resolve()),
                    target_type=self._target_type,
                    file_size=size,
                    md5=md5,
                    sha1=sha1,
                    sha256=sha256,
                    dex_count=1,
                    extra_metadata={"classes_count": len(classes)},
                )
            else:
                raise InvalidTargetError(
                    str(target_path),
                    "Target is neither a valid Android APK nor a DEX binary.",
                )
        except Exception as exc:
            if isinstance(exc, InvalidTargetError):
                raise
            raise BackendError(
                f"Failed to open target with Androguard 5.x: {exc}",
                remediation="Check target container validity.",
            ) from exc

    def close(self) -> None:
        self._executor.shutdown()
        self._apk_obj = None
        self._dex_objs = []
        self._analysis_obj = None

    def get_target_info(self) -> TargetInfo:
        return self._executor.submit(self._get_target_info_internal)

    def _get_target_info_internal(self) -> TargetInfo:
        if not self._target_info:
            raise InvalidTargetError("None", "No target currently opened.")
        return self._target_info

    def get_manifest_xml(self) -> str | None:
        return self._executor.submit(self._get_manifest_xml_internal)

    def _get_manifest_xml_internal(self) -> str | None:
        if not self._apk_obj and not self._target_path:
            return None
        if self._apk_obj:
            try:
                axml = self._apk_obj.get_android_manifest_axml()
                if axml:
                    xml_data = axml.get_xml()
                    if isinstance(xml_data, bytes):
                        return xml_data.decode("utf-8", errors="replace")
                    if xml_data:
                        return str(xml_data)
            except Exception:
                pass

        if self._target_path and self._target_path.exists():
            try:
                with zipfile.ZipFile(self._target_path, "r") as zf:
                    if "AndroidManifest.xml" in zf.namelist():
                        mb = zf.read("AndroidManifest.xml")
                        return axml_to_string(mb)
            except Exception:
                pass
        return None

    def get_permissions(self) -> list[str]:
        return self._executor.submit(
            lambda: list(self._apk_obj.get_permissions()) if self._apk_obj else []
        )

    def get_components(self) -> dict[str, list[str]]:
        return self._executor.submit(self._get_components_internal)

    def _get_components_internal(self) -> dict[str, list[str]]:
        if not self._apk_obj:
            return {"activities": [], "services": [], "receivers": [], "providers": []}
        return {
            "activities": list(self._apk_obj.get_activities() or []),
            "services": list(self._apk_obj.get_services() or []),
            "receivers": list(self._apk_obj.get_receivers() or []),
            "providers": list(self._apk_obj.get_providers() or []),
        }

    def get_files(self) -> list[str]:
        return self._executor.submit(
            lambda: list(self._apk_obj.get_files()) if self._apk_obj else []
        )

    def get_classes(self, grep: str | None = None, pkg: str | None = None) -> list[str]:
        return self._executor.submit(self._get_classes_internal, grep, pkg)

    def _get_classes_internal(
        self, grep: str | None = None, pkg: str | None = None
    ) -> list[str]:
        results: list[str] = []
        if self._analysis_obj:
            for cls in self._analysis_obj.get_classes():
                name = str(cls.name)
                if pkg and not name.startswith(f"L{pkg.replace('.', '/')}"):
                    continue
                if grep and grep.lower() not in name.lower():
                    continue
                results.append(name)
        return sorted(results)

    def get_methods(self, class_name: str) -> list[str]:
        return self._executor.submit(self._get_methods_internal, class_name)

    def _get_methods_internal(self, class_name: str) -> list[str]:
        if not self._analysis_obj:
            return []
        for cls in self._analysis_obj.get_classes():
            if (
                cls.name == class_name
                or str(cls.name).strip("L;").replace("/", ".") == class_name
            ):
                return [f"{m.name}{m.descriptor}" for m in cls.get_methods()]
        return []

    def disassemble(self, class_name: str, method_name: str | None = None) -> list[str]:
        return self._executor.submit(
            self._disassemble_internal, class_name, method_name
        )

    def _disassemble_internal(
        self, class_name: str, method_name: str | None = None
    ) -> list[str]:
        lines: list[str] = []
        if not self._analysis_obj:
            return ["No analysis object available."]
        for cls in self._analysis_obj.get_classes():
            if (
                cls.name == class_name
                or str(cls.name).strip("L;").replace("/", ".") == class_name
            ):
                for method in cls.get_methods():
                    if method_name and method.name != method_name:
                        continue
                    lines.append(f"; Method {method.name}{method.descriptor}")
                    encoded = method.get_method()
                    if encoded and hasattr(encoded, "get_instructions"):
                        for ins in encoded.get_instructions():
                            lines.append(f"    {ins.get_name()} {ins.get_output()}")
        return lines or [f"Method or class '{class_name}' not found."]

    def decompile(self, class_name: str, method_name: str | None = None) -> str | None:
        return f"// Java decompilation for {class_name} (Dalvik disassembly available)"

    def get_class_detail(self, class_name: str) -> ClassDetail | None:
        return self._executor.submit(self._get_class_detail_internal, class_name)

    def _get_class_detail_internal(self, class_name: str) -> ClassDetail | None:
        if not self._analysis_obj:
            return None

        target_cls = None
        for cls in self._analysis_obj.get_classes():
            c_name = str(cls.name)
            if (
                c_name == class_name
                or c_name.strip("L;").replace("/", ".") == class_name
                or c_name == f"L{class_name.replace('.', '/')};"
            ):
                target_cls = cls
                break

        if not target_cls:
            return None

        vm_cls = target_cls.get_vm_class() if hasattr(target_cls, "get_vm_class") else None
        super_name = str(vm_cls.get_superclassname()) if vm_cls and hasattr(vm_cls, "get_superclassname") else None
        interfaces = [str(i) for i in (vm_cls.get_interfaces() if vm_cls and hasattr(vm_cls, "get_interfaces") else [])]

        methods: list[MethodInfo] = []
        for m in target_cls.get_methods():
            methods.append(
                MethodInfo(
                    name=str(m.name),
                    descriptor=str(m.descriptor),
                    access_flags=str(m.get_access_flags_string()) if hasattr(m, "get_access_flags_string") else "",
                    is_external=bool(m.is_external()) if hasattr(m, "is_external") else False,
                    class_name=str(target_cls.name),
                )
            )

        fields: list[FieldInfo] = []
        if hasattr(target_cls, "get_fields"):
            for f in target_cls.get_fields():
                fields.append(
                    FieldInfo(
                        name=str(getattr(f, "name", "unknown")),
                        descriptor=str(getattr(f, "descriptor", "")),
                        class_name=str(target_cls.name),
                    )
                )

        return ClassDetail(
            name=str(target_cls.name),
            super_class=super_name,
            interfaces=interfaces,
            access_flags="",
            methods=methods,
            fields=fields,
        )

    def get_fields(self, class_name: str) -> list[str]:
        detail = self.get_class_detail(class_name)
        if not detail:
            return []
        return [f"{f.name}:{f.descriptor}" for f in detail.fields]

    def disassemble_method(
        self, class_name: str, method_name: str | None = None, cfg: bool = False
    ) -> DisasmResult:
        return self._executor.submit(
            self._disassemble_method_internal, class_name, method_name, cfg
        )

    def _disassemble_method_internal(
        self, class_name: str, method_name: str | None = None, cfg: bool = False
    ) -> DisasmResult:
        target_repr = f"{class_name}#{method_name}" if method_name else class_name
        if not self._analysis_obj:
            return DisasmResult(target=target_repr, instructions=["// No analysis available."])

        instructions: list[str] = []
        cfg_obj = None

        for cls in self._analysis_obj.get_classes():
            c_name = str(cls.name)
            if (
                c_name == class_name
                or c_name.strip("L;").replace("/", ".") == class_name
                or c_name == f"L{class_name.replace('.', '/')};"
            ):
                for method in cls.get_methods():
                    if method_name and method.name != method_name:
                        continue
                    instructions.append(f"; Method {method.name}{method.descriptor}")
                    encoded = method.get_method()
                    if encoded and hasattr(encoded, "get_instructions"):
                        for ins in encoded.get_instructions():
                            instructions.append(f"    0x{ins.get_op_value():04x}: {ins.get_name()} {ins.get_output()}")

                    if cfg and not cfg_obj and hasattr(method, "get_basic_blocks"):
                        try:
                            bbs_obj = method.get_basic_blocks()
                            bbs = list(bbs_obj.gets()) if hasattr(bbs_obj, "gets") else []
                            cfg_obj = build_cfg_from_basic_blocks(f"{cls.name}->{method.name}", bbs)
                        except Exception:
                            pass

        if not instructions:
            instructions.append(f"// Target '{target_repr}' not found.")

        return DisasmResult(target=target_repr, instructions=instructions, cfg=cfg_obj)

    def decompile_source(
        self,
        class_name: str,
        method_name: str | None = None,
        lang: str = "java",
        cfg: bool = False,
    ) -> CodeResult:
        return self._executor.submit(
            self._decompile_source_internal, class_name, method_name, lang, cfg
        )

    def _decompile_source_internal(
        self,
        class_name: str,
        method_name: str | None = None,
        lang: str = "java",
        cfg: bool = False,
    ) -> CodeResult:
        disasm_res = self._disassemble_method_internal(class_name, method_name, cfg=cfg)
        target_repr = disasm_res.target

        if lang.lower() == "dalvik":
            return CodeResult(
                target=target_repr,
                language="dalvik",
                source="\n".join(disasm_res.instructions),
                cfg=disasm_res.cfg,
            )

        source = (
            f"// Best-effort Java decompilation for {target_repr}\n"
            f"// Dalvik bytecode disassembly fallback:\n\n"
            + "\n".join(disasm_res.instructions)
        )

        return CodeResult(
            target=target_repr,
            language="java",
            source=source,
            cfg=disasm_res.cfg,
        )

    def get_strings(self, min_len: int = 4, entropy: bool = False) -> list[str]:
        return self._executor.submit(self._get_strings_internal, min_len, entropy)

    def _get_strings_internal(
        self, min_len: int = 4, entropy: bool = False
    ) -> list[str]:
        strings: list[str] = []
        if self._analysis_obj:
            for s in self._analysis_obj.get_strings():
                val = str(s.get_value())
                if len(val) >= min_len:
                    strings.append(val)
        return strings

    def get_certificates(self) -> list[dict[str, Any]]:
        return self._executor.submit(self._get_certificates_internal)

    def _get_certificates_internal(self) -> list[dict[str, Any]]:
        if not self._apk_obj:
            return []
        certs: list[dict[str, Any]] = []
        try:
            raw_certs = self._apk_obj.get_certificates()
            for cert in raw_certs:
                certs.append(
                    {
                        "issuer": str(getattr(cert, "issuer", "")),
                        "subject": str(getattr(cert, "subject", "")),
                        "serial_number": str(getattr(cert, "serial_number", "")),
                        "sha256": getattr(cert, "sha256", ""),
                    }
                )
        except Exception:
            pass
        return certs

    def get_manifest_data(self) -> ManifestData:
        return self._executor.submit(self._get_manifest_data_internal)

    def _get_manifest_data_internal(self) -> ManifestData:
        if not self._apk_obj and not self._target_path:
            return ManifestData()

        elem = None
        raw_xml = None
        if self._apk_obj:
            try:
                elem = self._apk_obj.get_android_manifest_xml()
            except Exception:
                elem = None
            try:
                axml = self._apk_obj.get_android_manifest_axml()
                if axml:
                    raw_xml = axml.get_xml()
                    if isinstance(raw_xml, bytes):
                        raw_xml = raw_xml.decode("utf-8", errors="replace")
            except Exception:
                raw_xml = None

        if elem is None and self._target_path and self._target_path.exists():
            try:
                with zipfile.ZipFile(self._target_path, "r") as zf:
                    if "AndroidManifest.xml" in zf.namelist():
                        mb = zf.read("AndroidManifest.xml")
                        raw_xml = axml_to_string(mb)
                        elem = parse_axml_to_element(mb)
            except Exception:
                pass

        if elem is not None:
            return parse_manifest_element(elem, raw_xml=raw_xml)
        return ManifestData(raw_xml=raw_xml)

    def get_resources(
        self, res_type: str | None = None, grep: str | None = None
    ) -> list[ResourceEntry]:
        return self._executor.submit(self._get_resources_internal, res_type, grep)

    def _get_resources_internal(
        self, res_type: str | None = None, grep: str | None = None
    ) -> list[ResourceEntry]:
        results: list[ResourceEntry] = []
        if self._apk_obj:
            try:
                arsc = self._apk_obj.get_android_resources()
                if arsc and hasattr(arsc, "get_resolved_strings"):
                    res_strings = arsc.get_resolved_strings()
                    for pkg, types in res_strings.items():
                        for tname, items in types.items():
                            if res_type and tname.lower() != res_type.lower():
                                continue
                            for r_id, val in items.items():
                                val_str = str(val) if val is not None else None
                                if grep and (
                                    not val_str or grep.lower() not in val_str.lower()
                                ):
                                    continue
                                results.append(
                                    ResourceEntry(
                                        res_id=hex(r_id)
                                        if isinstance(r_id, int)
                                        else str(r_id),
                                        res_type=tname,
                                        name=f"res_{r_id}",
                                        value=val_str,
                                        config=pkg,
                                    )
                                )
            except Exception:
                pass

        if not results and self._target_path and self._target_path.exists():
            try:
                with zipfile.ZipFile(self._target_path, "r") as zf:
                    if "resources.arsc" in zf.namelist():
                        raw_arsc = zf.read("resources.arsc")
                        parsed = parse_arsc_resources(raw_arsc)
                        for r in parsed:
                            if res_type and r.res_type.lower() != res_type.lower():
                                continue
                            if (
                                grep
                                and grep.lower() not in r.name.lower()
                                and (not r.value or grep.lower() not in r.value.lower())
                            ):
                                continue
                            results.append(r)
            except Exception:
                pass

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
        if not self._target_path or not self._target_path.exists():
            return entries

        try:
            with zipfile.ZipFile(self._target_path, "r") as zf:
                for info in zf.infolist():
                    p = info.filename
                    is_so = p.startswith("lib/") and p.endswith(".so")
                    is_asset = p.startswith("assets/")
                    is_dex = p.endswith(".dex")

                    if so_only and not is_so:
                        continue
                    if assets_only and not is_asset:
                        continue

                    entries.append(
                        ApkFileEntry(
                            path=p,
                            size=info.file_size,
                            is_so=is_so,
                            is_asset=is_asset,
                            is_dex=is_dex,
                            crc=info.CRC,
                        )
                    )
        except Exception:
            pass

        return entries

    def get_signature_report(self) -> SignatureReport:
        return self._executor.submit(self._get_signature_report_internal)

    def _get_signature_report_internal(self) -> SignatureReport:
        if not self._target_path or not self._target_path.exists():
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
        unique_strings: set[str] = set()
        if self._analysis_obj:
            try:
                for s in self._analysis_obj.get_strings():
                    val = str(s.get_value())
                    if len(val) >= min_len:
                        unique_strings.add(val)
            except Exception:
                pass

        items: list[StringItem] = []
        for s in unique_strings:
            ent = calculate_shannon_entropy(s) if calculate_entropy else 0.0
            items.append(StringItem(value=s, length=len(s), entropy=ent, source="dex"))

        if calculate_entropy:
            items.sort(key=lambda x: x.entropy, reverse=True)
        else:
            items.sort(key=lambda x: x.value)
        return items
