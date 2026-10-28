"""Frida bridge and device management for dynamic Android instrumentation."""

from collections.abc import Callable
from typing import Any

from andoguard.errors import (
    DeviceNotFoundError,
    FridaUnavailableError,
    HookError,
    ProcessNotFoundError,
)
from andoguard.models import DeviceInfo, ProcessInfo

try:
    import frida
    HAS_FRIDA = True
except ImportError:
    frida = None
    HAS_FRIDA = False


class FridaBridge:
    """Manages connections to Frida devices, process lifecycles, and script injection."""

    def __init__(self, simulation_mode: bool = False) -> None:
        self.simulation_mode = simulation_mode
        self._mock_processes: list[ProcessInfo] = [
            ProcessInfo(pid=1001, name="com.android.systemui"),
            ProcessInfo(pid=2048, name="com.example.testapp"),
            ProcessInfo(pid=3120, name="com.google.android.gms"),
        ]

    def is_available(self) -> bool:
        """Check whether Frida runtime is installed and importable."""
        return HAS_FRIDA or self.simulation_mode

    def get_devices(self) -> list[DeviceInfo]:
        """Enumerate connected Android devices, emulators, and local processes."""
        if self.simulation_mode:
            return [
                DeviceInfo(id="emulator-5554", name="Android Emulator Pixel 7", device_type="usb", is_emulator=True),
                DeviceInfo(id="usb-123456", name="Google Pixel 8 Pro", device_type="usb", is_emulator=False),
            ]

        if not HAS_FRIDA or frida is None:
            raise FridaUnavailableError("Frida library is not installed.")

        try:
            device_list = frida.enumerate_devices()
            results: list[DeviceInfo] = []
            for d in device_list:
                dtype = "usb" if d.type == "usb" else ("remote" if d.type == "remote" else "local")
                is_emu = "emulator" in d.id.lower() or "emulator" in d.name.lower() or "generic" in d.name.lower()
                results.append(
                    DeviceInfo(
                        id=str(d.id),
                        name=str(d.name),
                        device_type=dtype,
                        is_emulator=is_emu,
                    )
                )
            return results
        except Exception as exc:
            raise FridaUnavailableError(str(exc)) from exc

    def get_device(self, device_id: str | None = None) -> Any:
        """Retrieve Frida device object by ID or default to USB device."""
        if self.simulation_mode:
            return "simulated-device"

        if not HAS_FRIDA or frida is None:
            raise FridaUnavailableError("Frida library is not installed.")

        try:
            if device_id:
                return frida.get_device(device_id)
            # Default to first USB or remote device, or local
            try:
                return frida.get_usb_device(timeout=2)
            except Exception:
                return frida.get_remote_device()
        except Exception as exc:
            raise DeviceNotFoundError(device_id) from exc

    def list_processes(self, device_id: str | None = None) -> list[ProcessInfo]:
        """List running processes on target device."""
        if self.simulation_mode:
            return list(self._mock_processes)

        dev = self.get_device(device_id)
        try:
            raw_procs = dev.enumerate_processes()
            return [
                ProcessInfo(
                    pid=p.pid,
                    name=p.name,
                    parameters=getattr(p, "parameters", {}) or {},
                )
                for p in raw_procs
            ]
        except Exception as exc:
            raise FridaUnavailableError(f"Failed to enumerate processes: {exc}") from exc

    def spawn(
        self, package_name: str, device_id: str | None = None, auto_resume: bool = False
    ) -> int:
        """Spawn target Android package and return new process ID."""
        if self.simulation_mode:
            pid = 2048
            return pid

        dev = self.get_device(device_id)
        try:
            pid = dev.spawn([package_name])
            if auto_resume:
                dev.resume(pid)
            return int(pid)
        except Exception as exc:
            raise FridaUnavailableError(f"Failed to spawn '{package_name}': {exc}") from exc

    def attach(self, target: int | str, device_id: str | None = None) -> Any:
        """Attach to target process by PID or package name."""
        if self.simulation_mode:
            class MockFridaSession:
                def create_script(self, code: str) -> Any:
                    class MockFridaScript:
                        def load(self) -> None:
                            pass
                        def unload(self) -> None:
                            pass
                        def on(self, signal: str, callback: Any) -> None:
                            pass
                    return MockFridaScript()
                def detach(self) -> None:
                    pass
            return MockFridaSession()

        dev = self.get_device(device_id)
        try:
            return dev.attach(target)
        except Exception as exc:
            raise ProcessNotFoundError(str(target)) from exc

    def resume(self, pid: int, device_id: str | None = None) -> None:
        """Resume process execution."""
        if self.simulation_mode:
            return

        dev = self.get_device(device_id)
        try:
            dev.resume(pid)
        except Exception as exc:
            raise FridaUnavailableError(f"Failed to resume pid {pid}: {exc}") from exc

    def kill(self, pid: int, device_id: str | None = None) -> None:
        """Kill running process."""
        if self.simulation_mode:
            self._mock_processes = [p for p in self._mock_processes if p.pid != pid]
            return

        dev = self.get_device(device_id)
        try:
            dev.kill(pid)
        except Exception as exc:
            raise FridaUnavailableError(f"Failed to kill pid {pid}: {exc}") from exc

    def inject_script(
        self,
        session: Any,
        script_code: str,
        on_message: Callable[[dict[str, Any], Any], None] | None = None,
    ) -> Any:
        """Compile and inject JavaScript into active Frida session."""
        try:
            script = session.create_script(script_code)
            if on_message:
                script.on("message", on_message)
            script.load()
            return script
        except Exception as exc:
            raise HookError(str(exc), script=script_code) from exc
