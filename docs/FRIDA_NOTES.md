# Frida Bridge & Dynamic Instrumentation Notes

AndoGuard provides an optional dynamic instrumentation mode backed by Frida. Dynamic mode is strictly opt-in and offline-friendly; tests and static analysis operate fully without a connected device.

## Device Setup Guidelines

1. **Prerequisites**:
   - `adb` (Android Debug Bridge) installed and added to `PATH`.
   - Android device or emulator with USB debugging enabled (`adb devices`).
   - Root privileges (recommended for system-wide hooks and bypassing protections).

2. **Frida Server Installation**:
   - Determine target device ABI:
     ```bash
     adb shell getprop ro.product.cpu.abi
     ```
   - Download the corresponding `frida-server` binary matching your local `frida` Python package version:
     ```bash
     python -c "import frida; print(frida.__version__)"
     ```
   - Push and start `frida-server`:
     ```bash
     adb push frida-server-*-android-<abi> /data/local/tmp/frida-server
     adb shell "chmod 755 /data/local/tmp/frida-server"
     adb shell "/data/local/tmp/frida-server &"
     ```

3. **Version Matching**:
   Ensure the local Frida client version matches the remote `frida-server` version. Mismatched major versions can cause protocol errors or silent hook failures.

4. **Safety & Non-Destructive Operation**:
   - AndoGuard dynamic commands provide `--dry-run` to preview scripts before attaching.
   - Spawned processes offer resume-on-exit cleanup to prevent leaving target devices in an unstable frozen state.
