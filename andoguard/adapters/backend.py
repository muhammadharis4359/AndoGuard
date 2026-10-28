"""Abstract backend adapter protocol and thread-affine BackendExecutor."""

import concurrent.futures
import queue
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from andoguard.errors import BackendError, ConcurrencyError
from andoguard.models import (
    ApkFileEntry,
    BackendCapabilities,
    ManifestData,
    ResourceEntry,
    SignatureReport,
    StringItem,
    TargetInfo,
)

T = TypeVar("T")


class BackendExecutor:
    """Serializes backend calls on a dedicated single owner worker thread.

    Androguard and other low-level Android parsing objects are often thread-affine
    and maintain internal mutable structures that fail when accessed concurrently.
    BackendExecutor guarantees all calls route through a single owner thread.
    """

    def __init__(self, thread_name: str = "AndoGuard-BackendWorker") -> None:
        self.thread_name = thread_name
        self._queue: queue.Queue[
            tuple[
                Callable[..., Any],
                tuple[Any, ...],
                dict[str, Any],
                concurrent.futures.Future[Any],
            ]
            | None
        ] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._shutdown = False
        self._lock = threading.Lock()
        self._owner_thread_ident: int | None = None

    def _start_worker(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._shutdown = False
                self._thread = threading.Thread(
                    target=self._worker_loop,
                    name=self.thread_name,
                    daemon=True,
                )
                self._thread.start()

    def _worker_loop(self) -> None:
        self._owner_thread_ident = threading.get_ident()
        while not self._shutdown:
            try:
                task = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if task is None:
                self._queue.task_done()
                break

            func, args, kwargs, future = task
            try:
                result = func(*args, **kwargs)
                future.set_result(result)
            except BaseException as exc:
                future.set_exception(exc)
            finally:
                self._queue.task_done()

    def is_owner_thread(self) -> bool:
        """Check if caller is currently executing on the backend worker thread."""
        return threading.get_ident() == self._owner_thread_ident

    def submit(
        self,
        func: Callable[..., T],
        *args: Any,
        timeout: float | None = 60.0,
        **kwargs: Any,
    ) -> T:
        """Submit a callable to the single owner worker thread and wait for result.

        If caller is already on the owner thread, executes immediately to prevent deadlocks.
        """
        if self._shutdown:
            raise ConcurrencyError("BackendExecutor has been shut down.")

        if self.is_owner_thread():
            return func(*args, **kwargs)

        self._start_worker()

        future: concurrent.futures.Future[T] = concurrent.futures.Future()
        self._queue.put((func, args, kwargs, future))

        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as err:
            raise ConcurrencyError(
                f"Backend call '{getattr(func, '__name__', str(func))}' timed out after {timeout} seconds.",
                remediation="Consider increasing timeout or running with lower concurrency.",
            ) from err
        except Exception as exc:
            if isinstance(exc, BackendError):
                raise
            raise BackendError(
                f"Backend execution failure in '{getattr(func, '__name__', str(func))}': {exc}",
                remediation="Check target integrity and parser compatibility.",
            ) from exc

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the backend worker thread."""
        with self._lock:
            self._shutdown = True
            if self._thread and self._thread.is_alive():
                self._queue.put(None)
                if wait and not self.is_owner_thread():
                    self._thread.join(timeout=2.0)
                self._thread = None


class BackendAdapter(ABC):
    """Abstract base class for Android parser backends."""

    def __init__(self, target_path: Path | None = None) -> None:
        self.target_path = target_path
        self._executor = BackendExecutor(thread_name=f"{self.name}-Worker")

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identifier name."""

    @abstractmethod
    def get_capabilities(self) -> BackendCapabilities:
        """Report features supported by this adapter."""

    @abstractmethod
    def open(self, target_path: Path) -> None:
        """Open and parse the target Android binary."""

    @abstractmethod
    def close(self) -> None:
        """Release any open file handles and stop executor."""

    @abstractmethod
    def get_target_info(self) -> TargetInfo:
        """Extract structured target metadata."""

    @abstractmethod
    def get_manifest_xml(self) -> str | None:
        """Return decoded AndroidManifest.xml as UTF-8 string."""

    @abstractmethod
    def get_permissions(self) -> list[str]:
        """Return list of declared and requested permissions."""

    @abstractmethod
    def get_components(self) -> dict[str, list[str]]:
        """Return dictionary mapping component type to component class names."""

    @abstractmethod
    def get_files(self) -> list[str]:
        """List all entries in the APK/container."""

    @abstractmethod
    def get_classes(self, grep: str | None = None, pkg: str | None = None) -> list[str]:
        """List class names, optionally filtered by grep pattern or package."""

    @abstractmethod
    def get_methods(self, class_name: str) -> list[str]:
        """List method signatures for a given class."""

    @abstractmethod
    def disassemble(self, class_name: str, method_name: str | None = None) -> list[str]:
        """Disassemble Dalvik bytecode for a class or specific method."""

    @abstractmethod
    def decompile(self, class_name: str, method_name: str | None = None) -> str | None:
        """Decompile Dalvik bytecode to Java source."""

    @abstractmethod
    def get_strings(self, min_len: int = 4, entropy: bool = False) -> list[str]:
        """Extract string literals from bytecode with optional entropy sorting."""

    @abstractmethod
    def get_certificates(self) -> list[dict[str, Any]]:
        """Extract signing certificate details."""

    @abstractmethod
    def get_manifest_data(self) -> ManifestData:
        """Extract complete structured AndroidManifest.xml metadata."""

    @abstractmethod
    def get_resources(
        self, res_type: str | None = None, grep: str | None = None
    ) -> list[ResourceEntry]:
        """Extract and filter Android resources."""

    @abstractmethod
    def get_file_entries(
        self, so_only: bool = False, assets_only: bool = False
    ) -> list[ApkFileEntry]:
        """List container files with metadata and category flags."""

    @abstractmethod
    def get_signature_report(self) -> SignatureReport:
        """Extract APK signature schemes (v1, v2, v3) and certificate details."""

    @abstractmethod
    def get_string_items(
        self, min_len: int = 4, calculate_entropy: bool = False
    ) -> list[StringItem]:
        """Extract string items with length, source, and Shannon entropy."""
