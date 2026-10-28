"""Public library API for AndoGuard."""

from pathlib import Path
from typing import Any

from andoguard.adapters.backend import BackendAdapter
from andoguard.adapters.detect import create_backend
from andoguard.ai.cache import AiCacheManager
from andoguard.ai.prompts import (
    build_ask_prompt,
    build_explain_prompt,
    build_triage_prompt,
)
from andoguard.ai.provider import get_ai_provider
from andoguard.config import AndoGuardConfig
from andoguard.dynamic.bypasses import generate_combined_bypass
from andoguard.dynamic.generator import (
    generate_java_class_hook,
    generate_java_method_hook,
    generate_native_hook,
)
from andoguard.dynamic.memory import (
    generate_memory_dump_script,
    generate_memory_search_script,
)
from andoguard.dynamic.tracer import generate_pattern_tracer_script
from andoguard.errors import (
    SessionNotFoundError,
    TargetNotFoundError,
)
from andoguard.formats.elf import parse_elf_bytes
from andoguard.models import (
    AdaptiveRunResult,
    AnalysisMode,
    ApkDiffResult,
    ApkFileEntry,
    ClassDetail,
    CodeResult,
    DeviceInfo,
    DisasmResult,
    ElfInfo,
    ManifestComponent,
    ManifestData,
    ManifestSecurityFlags,
    ProcessInfo,
    ResourceEntry,
    SearchResultItem,
    SecretFinding,
    SessionRecord,
    SignatureReport,
    StringItem,
    TargetInfo,
    TraceEvent,
    VulnerabilityReport,
    XrefResult,
)
from andoguard.session.store import SessionStore
from andoguard.static.diff import diff_andoguard_instances
from andoguard.static.secrets import scan_strings_for_secrets
from andoguard.static.vulns import audit_target_vulnerabilities


class ManifestFacade:
    """Helper facade for manifest queries."""

    def __init__(self, backend: BackendAdapter) -> None:
        self._backend = backend

    def data(self) -> ManifestData:
        """Return the structured ManifestData object."""
        return self._backend.get_manifest_data()

    def xml(self) -> str | None:
        """Return the decoded XML manifest string."""
        return self._backend.get_manifest_xml()

    def permissions(self) -> list[str]:
        """Return all declared and requested permissions."""
        data = self.data()
        return data.permissions if data else self._backend.get_permissions()

    def declared_permissions(self) -> list[str]:
        """Return all custom permissions declared by the app."""
        data = self.data()
        return data.declared_permissions if data else []

    def components(self) -> list[ManifestComponent]:
        """Return all declared components."""
        data = self.data()
        return data.components if data else []

    def exported_components(self) -> list[ManifestComponent]:
        """Return list of exported Android components."""
        return [c for c in self.components() if c.exported]

    def security_flags(self) -> ManifestSecurityFlags:
        """Return security flags defined in the manifest."""
        data = self.data()
        return data.security_flags if data else ManifestSecurityFlags()


class AndoGuard:
    """Main facade for AndoGuard reverse engineering and security auditing."""

    def __init__(
        self,
        backend: BackendAdapter,
        session_store: SessionStore,
        session_record: SessionRecord,
        target_info: TargetInfo,
    ) -> None:
        self.backend = backend
        self.session_store = session_store
        self.session_record = session_record
        self.target_info = target_info
        self.manifest = ManifestFacade(backend)

    @classmethod
    def open(
        cls,
        target_path: str | Path,
        session_name: str | None = None,
        mode: str | AnalysisMode = AnalysisMode.STATIC,
        work_dir: str | Path | None = None,
        prefer_backend: str | None = None,
    ) -> "AndoGuard":
        """Open an Android target (APK, DEX, etc.) and create or link a session."""
        path = Path(target_path)
        if not path.exists():
            raise TargetNotFoundError(str(path))

        cfg = AndoGuardConfig.load()
        if work_dir:
            cfg.work_dir = Path(work_dir)
            cfg.ensure_directories()

        if isinstance(mode, str):
            try:
                mode = AnalysisMode(mode.lower())
            except ValueError:
                mode = AnalysisMode.STATIC

        store = SessionStore(config=cfg)
        backend = create_backend(target_path=path, prefer=prefer_backend)
        backend.open(path)

        info = backend.get_target_info()
        session = store.create_session(
            target=info,
            name=session_name,
            mode=mode,
        )
        store.set_active_session(session.session_id)

        return cls(
            backend=backend,
            session_store=store,
            session_record=session,
            target_info=info,
        )

    @classmethod
    def resume(
        cls,
        session_identifier: str,
        work_dir: str | Path | None = None,
        prefer_backend: str | None = None,
    ) -> "AndoGuard":
        """Resume an existing session by ID or name."""
        cfg = AndoGuardConfig.load()
        if work_dir:
            cfg.work_dir = Path(work_dir)
            cfg.ensure_directories()

        store = SessionStore(config=cfg)
        session = store.get_session(session_identifier)
        if not session:
            raise SessionNotFoundError(session_identifier)

        store.set_active_session(session.session_id)

        target_path = Path(session.target_path)
        if not target_path.exists():
            raise TargetNotFoundError(str(target_path))

        backend = create_backend(target_path=target_path, prefer=prefer_backend)
        backend.open(target_path)
        info = backend.get_target_info()

        return cls(
            backend=backend,
            session_store=store,
            session_record=session,
            target_info=info,
        )

    def info(self) -> TargetInfo:
        """Get structured target information."""
        return self.backend.get_target_info()

    def classes(self, grep: str | None = None, pkg: str | None = None) -> list[str]:
        """List class names, optionally filtered by keyword or package."""
        return self.backend.get_classes(grep=grep, pkg=pkg)

    def methods(self, class_name: str) -> list[str]:
        """List methods of a class."""
        return self.backend.get_methods(class_name=class_name)

    def disassemble(self, class_name: str, method_name: str | None = None) -> list[str]:
        """Disassemble Dalvik bytecode for a class or specific method."""
        return self.backend.disassemble(class_name, method_name)

    def decompile(self, class_name: str, method_name: str | None = None) -> str | None:
        """Decompile Dalvik bytecode to Java source."""
        return self.backend.decompile(class_name, method_name)

    def class_detail(self, class_name: str) -> ClassDetail | None:
        """Extract detailed class structure with methods, fields, and inheritance."""
        return self.backend.get_class_detail(class_name)

    def fields(self, class_name: str) -> list[str]:
        """List fields declared in a class."""
        return self.backend.get_fields(class_name)

    def disassemble_method(
        self, class_name: str, method_name: str | None = None, cfg: bool = False
    ) -> DisasmResult:
        """Disassemble Dalvik bytecode with optional Control Flow Graph."""
        return self.backend.disassemble_method(class_name, method_name, cfg=cfg)

    def decompile_source(
        self,
        class_name: str,
        method_name: str | None = None,
        lang: str = "java",
        cfg: bool = False,
    ) -> CodeResult:
        """Decompile Dalvik bytecode to Java or Dalvik source with optional CFG."""
        return self.backend.decompile_source(class_name, method_name, lang=lang, cfg=cfg)

    def files(self) -> list[str]:
        """List all entries in the APK archive."""
        return self.backend.get_files()

    def file_entries(
        self, so_only: bool = False, assets_only: bool = False
    ) -> list[ApkFileEntry]:
        """List file entries with metadata and category filters."""
        return self.backend.get_file_entries(so_only=so_only, assets_only=assets_only)

    def resources(
        self, res_type: str | None = None, grep: str | None = None
    ) -> list[ResourceEntry]:
        """Extract and filter Android resources."""
        return self.backend.get_resources(res_type=res_type, grep=grep)

    def certs(self) -> SignatureReport:
        """Extract APK signature schemes (v1, v2, v3) and certificate details."""
        return self.backend.get_signature_report()

    def strings(self, min_len: int = 4, entropy: bool = False) -> list[str]:
        """Extract strings from target."""
        return self.backend.get_strings(min_len=min_len, entropy=entropy)

    def string_items(self, min_len: int = 4, entropy: bool = False) -> list[StringItem]:
        """Extract string items with length, source, and Shannon entropy."""
        return self.backend.get_string_items(min_len=min_len, calculate_entropy=entropy)

    def certificates(self) -> list[dict[str, Any]]:
        """Extract signing certificate information."""
        return self.backend.get_certificates()

    def xrefs(self, target: str, direction: str = "both") -> XrefResult:
        """Extract cross-references (callers/callees) for a class, method, or string."""
        return self.backend.get_xrefs(target, direction=direction)

    def secrets(self, min_entropy: float = 3.8) -> list[SecretFinding]:
        """Scan target strings and resources for credentials, tokens, and secrets."""
        items = self.string_items(min_len=4, entropy=True)
        return scan_strings_for_secrets(items, min_entropy=min_entropy)

    def vulns(self) -> VulnerabilityReport:
        """Audit target against OWASP MASVS/MASTG security guidelines."""
        m = self.manifest.data()
        strs = self.strings(min_len=3)
        target_name = str(self.target_info.package_name or self.target_info.target_path)
        return audit_target_vulnerabilities(target_name, manifest=m, strings=strs)

    def native(self, lib_name: str | None = None) -> list[ElfInfo]:
        """Inspect native ELF shared libraries (.so) inside APK."""
        import zipfile

        results: list[ElfInfo] = []
        path = Path(self.target_info.target_path)
        if not path.exists():
            return results

        if path.is_file() and path.suffix == ".so":
            with open(path, "rb") as f:
                so_data = f.read()
            results.append(parse_elf_bytes(so_data, file_name=path.name))
        elif path.is_file() and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                for entry in zf.namelist():
                    if entry.endswith(".so"):
                        if lib_name and lib_name.lower() not in entry.lower():
                            continue
                        try:
                            so_data = zf.read(entry)
                            results.append(parse_elf_bytes(so_data, file_name=entry))
                        except Exception:
                            pass
        return results

    def diff(self, other: "AndoGuard | str | Path") -> ApkDiffResult:
        """Compare current target against another APK or AndoGuard session."""
        import uuid

        if isinstance(other, (str, Path)):
            other_ag = AndoGuard.open(
                other, session_name=f"diff-{uuid.uuid4().hex[:6]}"
            )
            try:
                return diff_andoguard_instances(self, other_ag)
            finally:
                other_ag.close()
        return diff_andoguard_instances(self, other)

    def build_search_index(self) -> int:
        """Build full-text search index for target symbols, strings, and components."""
        items: list[tuple[str, str, str]] = []
        for c in self.classes():
            items.append(("class", c, c))
            for m in self.methods(c):
                items.append(("method", f"{c}->{m}", f"{c}->{m}"))

        for s in self.strings(min_len=4):
            items.append(("string", s[:60], s))

        for comp in self.manifest.components():
            items.append(
                ("component", comp.name, f"{comp.component_type.upper()}: {comp.name}")
            )

        for r in self.resources():
            items.append(
                ("resource", r.name, f"{r.res_type}: {r.name} = {r.value or ''}")
            )

        self.session_store.index_search_items(self.session_record.session_id, items)
        return len(items)

    def search(self, query: str) -> list[SearchResultItem]:
        """Search target bytecode symbols, strings, components, and resources."""
        results = self.session_store.search(
            query, session_id=self.session_record.session_id
        )
        if not results:
            self.build_search_index()
            results = self.session_store.search(
                query, session_id=self.session_record.session_id
            )
        return results

    def devices(self, simulation_mode: bool = False) -> list[DeviceInfo]:
        """List connected Android devices and emulators."""
        from andoguard.adapters.frida_bridge import FridaBridge

        bridge = FridaBridge(simulation_mode=simulation_mode)
        return bridge.get_devices()

    def processes(
        self, device_id: str | None = None, simulation_mode: bool = False
    ) -> list[ProcessInfo]:
        """List running processes on connected device."""
        from andoguard.adapters.frida_bridge import FridaBridge

        bridge = FridaBridge(simulation_mode=simulation_mode)
        return bridge.list_processes(device_id=device_id)

    def spawn(
        self,
        package_name: str | None = None,
        device_id: str | None = None,
        auto_resume: bool = False,
        simulation_mode: bool = False,
    ) -> int:
        """Spawn target package on connected device."""
        from andoguard.adapters.frida_bridge import FridaBridge

        pkg = package_name or self.target_info.package_name or "com.example.target"
        bridge = FridaBridge(simulation_mode=simulation_mode)
        return bridge.spawn(pkg, device_id=device_id, auto_resume=auto_resume)

    def attach(
        self,
        target: int | str | None = None,
        device_id: str | None = None,
        simulation_mode: bool = False,
    ) -> Any:
        """Attach to running target process on connected device."""
        from andoguard.adapters.frida_bridge import FridaBridge

        tgt = target or self.target_info.package_name or "com.example.target"
        bridge = FridaBridge(simulation_mode=simulation_mode)
        return bridge.attach(tgt, device_id=device_id)

    def resume_process(
        self, pid: int, device_id: str | None = None, simulation_mode: bool = False
    ) -> None:
        """Resume execution of a spawned target process."""
        from andoguard.adapters.frida_bridge import FridaBridge

        bridge = FridaBridge(simulation_mode=simulation_mode)
        bridge.resume(pid, device_id=device_id)

    def kill_process(
        self, pid: int, device_id: str | None = None, simulation_mode: bool = False
    ) -> None:
        """Kill a running process on target device."""
        from andoguard.adapters.frida_bridge import FridaBridge

        bridge = FridaBridge(simulation_mode=simulation_mode)
        bridge.kill(pid, device_id=device_id)

    def generate_hook(
        self,
        target: str,
        custom_return: str | None = None,
        dump_backtrace: bool = True,
        native: bool = False,
        library: str | None = None,
    ) -> str:
        """Generate Frida hook script for a Java method or native C/C++ function."""
        if native:
            return generate_native_hook(target, library_name=library)
        if "#" in target:
            cls_name, meth_name = target.split("#", 1)
            return generate_java_method_hook(
                cls_name,
                meth_name,
                dump_backtrace=dump_backtrace,
                custom_return=custom_return,
            )
        if "->" in target:
            cls_name, meth_name = target.split("->", 1)
            return generate_java_method_hook(
                cls_name,
                meth_name,
                dump_backtrace=dump_backtrace,
                custom_return=custom_return,
            )
        return generate_java_class_hook(target)

    def generate_tracer(self, pattern: str) -> str:
        """Generate Frida tracing script matching class or method pattern."""
        return generate_pattern_tracer_script(pattern)

    def bypass(self, module: str = "all") -> str:
        """Generate security bypass script (ssl, root, debug, emulator, or all)."""
        if module == "all":
            return generate_combined_bypass()
        return generate_combined_bypass([module])

    def search_memory(self, pattern: str, is_hex: bool = False) -> str:
        """Generate Frida script to search readable memory ranges for pattern."""
        return generate_memory_search_script(pattern, is_hex=is_hex)

    @property
    def session(self) -> SessionRecord:
        """Active session record."""
        return self.session_record

    @property
    def store(self) -> SessionStore:
        """Active session store."""
        return self.session_store

    def dump_memory(self, address: str, length: int) -> str:
        """Generate Frida script to dump memory range at address."""
        return generate_memory_dump_script(address, length)

    def trace_events(self, session_id: str | None = None) -> list[TraceEvent]:
        """Retrieve recorded dynamic trace events."""
        sid = session_id or self.session_record.session_id
        return self.session_store.get_trace_events(sid)

    def save_trace_event(
        self, event: TraceEvent, session_id: str | None = None
    ) -> None:
        """Persist dynamic trace event."""
        sid = session_id or self.session_record.session_id
        self.session_store.save_trace_event(sid, event)

    def hooks(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve recorded dynamic hooks for session."""
        sid = session_id or self.session_record.session_id
        return self.session_store.get_hooks(sid)

    def save_hook(
        self,
        class_name: str,
        method_name: str,
        script: str,
        status: str = "active",
        session_id: str | None = None,
    ) -> str:
        """Persist hook script for session."""
        sid = session_id or self.session_record.session_id
        return self.session_store.save_hook(
            sid, class_name, method_name, script, status=status
        )

    def ai_ask(
        self,
        question: str,
        context: str | None = None,
        provider: str | None = None,
    ) -> str:
        """Query AI reasoning provider with context."""
        cache = AiCacheManager(self.session_store.config)
        p = get_ai_provider(provider, config=self.session_store.config)
        system, prompt = build_ask_prompt(question, context=context)
        cache_key = cache.compute_hash(p.name, p.model, prompt, system=system)
        hit = cache.get(cache_key)
        if hit is not None:
            return hit
        resp = p.generate(prompt, system=system)
        cache.put(cache_key, p.name, p.model, resp)
        return resp

    def ai_explain(
        self,
        class_or_method: str,
        provider: str | None = None,
    ) -> str:
        """Explain and de-obfuscate class or method using AI."""
        code = ""
        try:
            res = self.decompile_source(class_or_method)
            code = res.source
        except Exception:
            try:
                dis = self.disassemble_method(class_or_method)
                code = "\n".join(dis.instructions)
            except Exception:
                code = f"// Target: {class_or_method}"

        cache = AiCacheManager(self.session_store.config)
        p = get_ai_provider(provider, config=self.session_store.config)
        system, prompt = build_explain_prompt(code, identifier=class_or_method)
        cache_key = cache.compute_hash(p.name, p.model, prompt, system=system)
        hit = cache.get(cache_key)
        if hit is not None:
            return hit
        resp = p.generate(prompt, system=system)
        cache.put(cache_key, p.name, p.model, resp)
        return resp

    def ai_triage(
        self,
        provider: str | None = None,
    ) -> str:
        """Perform automated AI security triage across all static vulnerabilities."""
        report = self.vulns()
        findings_data = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "masvs_id": f.masvs_id,
                "evidence": f.evidence,
            }
            for f in report.findings
        ]
        sec_flags = self.manifest.security_flags()
        manifest_summary = (
            f"Package: {self.target_info.package_name}, "
            f"Debuggable: {sec_flags.debuggable}, "
            f"AllowBackup: {sec_flags.allow_backup}, "
            f"Exported: {len(self.manifest.exported_components())} components"
        )
        cache = AiCacheManager(self.session_store.config)
        p = get_ai_provider(provider, config=self.session_store.config)
        system, prompt = build_triage_prompt(findings_data, manifest_summary)
        cache_key = cache.compute_hash(p.name, p.model, prompt, system=system)
        hit = cache.get(cache_key)
        if hit is not None:
            return hit
        resp = p.generate(prompt, system=system)
        cache.put(cache_key, p.name, p.model, resp)
        return resp

    def adaptive_run(
        self,
        goal: str = "Perform full security audit",
        autonomy: str = "full",
        max_steps: int = 10,
        provider: str | None = None,
    ) -> AdaptiveRunResult:
        """Run autonomous agent loop to achieve reverse engineering or audit goal."""
        from andoguard.adaptive.agent import AdaptiveAgent

        agent = AdaptiveAgent(autonomy_level=autonomy, max_steps=max_steps)
        return agent.run(self, goal, provider=provider)

    def adaptive_plan(
        self,
        goal: str = "Perform full security audit",
        provider: str | None = None,
    ) -> list[str]:
        """Generate high-level step plan for goal without executing tools."""
        from andoguard.adaptive.agent import AdaptiveAgent

        agent = AdaptiveAgent()
        return agent.plan(self, goal, provider=provider)

    def generate_report(self, format: str = "markdown") -> str:
        """Generate comprehensive assessment report ('markdown', 'html', or 'json')."""
        from andoguard.report.generator import generate_report

        return generate_report(self, format=format)

    def export_bundle(self, out_path: str | Path | None = None) -> Path:
        """Export session into an integrity-verified .agguard zip archive."""
        from andoguard.session.bundle import export_session_bundle

        return export_session_bundle(self, out_path=out_path)

    @classmethod
    def import_bundle(
        cls,
        bundle_path: str | Path,
        work_dir: str | Path | None = None,
    ) -> SessionRecord:
        """Import an .agguard session archive into local database."""
        from andoguard.session.bundle import import_session_bundle

        cfg = AndoGuardConfig.load()
        if work_dir:
            cfg.work_dir = Path(work_dir)
            cfg.ensure_directories()
        return import_session_bundle(bundle_path, config=cfg)

    def close(self) -> None:
        """Release open file handles and shutdown backend workers."""
        self.backend.close()

    def __enter__(self) -> "AndoGuard":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
