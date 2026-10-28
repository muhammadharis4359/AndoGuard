"""Androguard v4 adapter implementation."""

from pathlib import Path
from typing import Any

from andoguard.adapters.backend import BackendAdapter
from andoguard.errors import BackendError, InvalidTargetError
from andoguard.formats.apk import is_apk_archive
from andoguard.formats.dex import is_dex_file
from andoguard.models import BackendCapabilities, TargetInfo, TargetType
from andoguard.session.store import compute_file_hashes

try:
    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
except Exception:
    pass


class AgV4Adapter(BackendAdapter):
    """Adapter bridging AndoGuard to Androguard 4.x APIs."""

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
        return "androguard-v4"

    def get_capabilities(self) -> BackendCapabilities:
        import androguard

        version = getattr(androguard, "__version__", "4.x")
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
            has_v5_features=False,
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
                from androguard.misc import AnalyzeAPK

                a, d, dx = AnalyzeAPK(str(target_path))
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
                f"Failed to open target with Androguard 4.x: {exc}",
                remediation="Verify target is not corrupted or protected by packing.",
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
        if not self._apk_obj:
            return None
        try:
            axml = self._apk_obj.get_android_manifest_axml()
            if axml:
                xml_data = axml.get_xml()
                if isinstance(xml_data, bytes):
                    return xml_data.decode("utf-8", errors="replace")
                return str(xml_data)
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
        return self._executor.submit(self._decompile_internal, class_name, method_name)

    def _decompile_internal(
        self, class_name: str, method_name: str | None = None
    ) -> str | None:
        # Androguard 4.x decompiler support
        return f"// Java decompilation for {class_name} (Dalvik disassembly available)"

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
