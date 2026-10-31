# AndoGuard

> **Production-Grade Android Reverse Engineering & Security Testing Toolkit**

AndoGuard is an offline-first, library-first Python 3.11+ toolkit designed for authorized Android security assessments, binary analysis, and security auditing.

```
+-----------------------------------------------------------------------+
|  NOTICE: FOR AUTHORIZED SECURITY TESTING AND REVERSE ENGINEERING ONLY |
|  Unauthorized testing of systems or devices is strictly prohibited.   |
+-----------------------------------------------------------------------+
```

## Features

- **Offline-First Static Analysis**: Inspect APK containers, DEX bytecode, manifests, components, certificates, native libraries, strings, and secrets without external cloud dependencies.
- **Resumable SQLite Sessions**: Deduplicate targets by SHA-256 and resume past analyses with full audit trails.
- **Thread-Safe Architecture**: Uses a dedicated `BackendExecutor` single-worker queue to guarantee safe multi-threaded queries over thread-affine Android parsing data structures.
- **Adapter Layer**: Seamless support for Androguard v4 and v5 with automatic capability detection and built-in pure-Python fallback parsers.
- **Library & CLI**: Every CLI command is a thin wrapper around a typed, importable Python API.

## Installation

```bash
# Editable development install
pip install -e ".[dev]"

# With Frida and YARA extras
pip install -e ".[all]"
```

## Quick Start (CLI)

```bash
# View version and authorized use notice
andoguard --version

# Open an APK target (initializes a persistent session and displays summary card)
andoguard open sample.apk

# View target info in human-readable or machine-readable JSON format
andoguard info
andoguard info --json

# Launch modern interactive web dashboard for security audit & presentation
andoguard dashboard
andoguard dashboard samples/insecure_bank.apk --port 8080

# List active and past sessions
andoguard sessions

# Resume an existing session by ID or name
andoguard resume <session-id>
```

## Python Library Usage

```python
from andoguard import AndoGuard

# Open target and create/resume a session
ag = AndoGuard.open("sample.apk", session_name="audit-sample")

# Inspect general metadata
info = ag.info()
print(f"Package: {info.package_name} (v{info.version_name})")
print(f"Target SDK: {info.target_sdk_version}")
print(f"SHA-256: {info.sha256}")

# Always clean up when finished
ag.close()
```

## License

Apache-2.0
