# AndoGuard — Design and Architectural Decisions

This document records architectural, technical, and implementation decisions made in AndoGuard, including reasons for non-obvious choices and any necessary deviations.

## Decisions Log

- **ADR-001: Hatchling build backend**: Selected Hatchling as standard PEP 621 build backend for modern, lightweight, reproducible packaging without legacy setup.py overhead.
- **ADR-002: Typer & Rich for CLI**: Typer provides declarative, fully type-hinted command definitions while Rich provides formatted summary cards, status spinners, and syntax highlighting.
- **ADR-003: SQLite with WAL mode & explicit foreign keys**: Used for all session persistence to ensure atomic transactions, robust concurrent reads, crash resilience, and zero external database dependencies.
- **ADR-004: Dedicated single-thread BackendExecutor**: Third-party Android analysis tools (including Androguard) are thread-affine with non-thread-safe internal structures; a dedicated single worker thread with thread-safe task submission guarantees safe concurrent callers.
- **ADR-005: Adapter abstraction for Androguard v4 and v5**: Third-party parser imports are strictly restricted to `andoguard/adapters/` with capability detection via `detect.py`, supporting Androguard 4.x and future 5.x while providing a pure-Python fallback parser for clean offline environments without external C/graph dependencies.
- **ADR-006: Target deduplication by SHA-256**: Input files (APK, DEX, etc.) are hashed via SHA-256 upon intake to detect existing sessions and prevent redundant duplicate analysis.
- **ADR-007: Safe offline-by-default execution**: No remote calls are made unless explicit AI providers or device bridges are commanded; telemetry or phone-home requests are strictly excluded.
- **ADR-008: Clear structured errors with remediation**: Replaced unhandled tracebacks for operational failures with typed `AndoGuardError` subclasses providing actionable remediation guidance.
- **ADR-009: Separation of package source and session data**: Session files, caches, and indexes are saved strictly in `~/.andoguard/sessions/<session_id>` or an explicit `--work-dir`, never modifying input artifacts.
