"""Public library API for AndoGuard."""

from pathlib import Path
from typing import Any

from andoguard.adapters.backend import BackendAdapter
from andoguard.adapters.detect import create_backend
from andoguard.config import AndoGuardConfig
from andoguard.errors import (
    SessionNotFoundError,
    TargetNotFoundError,
)
from andoguard.models import AnalysisMode, SessionRecord, TargetInfo
from andoguard.session.store import SessionStore


class ManifestFacade:
    """Helper facade for manifest queries."""

    def __init__(self, backend: BackendAdapter) -> None:
        self._backend = backend

    def xml(self) -> str | None:
        """Return the decoded XML manifest string."""
        return self._backend.get_manifest_xml()

    def permissions(self) -> list[str]:
        """Return all declared and requested permissions."""
        return self._backend.get_permissions()

    def components(self) -> dict[str, list[str]]:
        """Return all declared components by category."""
        return self._backend.get_components()

    def exported_components(self) -> list[str]:
        """Return list of exported Android components."""
        # For M1, returns basic list from components
        comps = self.components()
        exported: list[str] = []
        for cat, names in comps.items():
            for name in names:
                exported.append(f"{cat[:-1]}:{name}")
        return exported


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

    def files(self) -> list[str]:
        """List all entries in the APK archive."""
        return self.backend.get_files()

    def strings(self, min_len: int = 4, entropy: bool = False) -> list[str]:
        """Extract strings from target."""
        return self.backend.get_strings(min_len=min_len, entropy=entropy)

    def certificates(self) -> list[dict[str, Any]]:
        """Extract signing certificate information."""
        return self.backend.get_certificates()

    def close(self) -> None:
        """Release open file handles and shutdown backend workers."""
        self.backend.close()

    def __enter__(self) -> "AndoGuard":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
