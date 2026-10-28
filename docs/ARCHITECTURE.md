# AndoGuard Architecture

AndoGuard is an offline-first, library-first Android reverse engineering and security testing framework.

```
                          ┌───────────────────────────┐
                          │   CLI (Typer + Rich)      │
                          │   andoguard open/info/... │
                          └─────────────┬─────────────┘
                                        │ (thin wrapper)
                                        ▼
                          ┌───────────────────────────┐
                          │     Public Library API    │
                          │   AndoGuard (Facade)      │
                          └──────┬─────────────┬──────┘
                                 │             │
                    ┌────────────▼──┐       ┌──▼────────────────────────┐
                    │ Session Store │       │ BackendExecutor           │
                    │ SQLite + WAL  │       │ Single-worker task queue  │
                    │ Migrations    │       │ Thread-safe execution     │
                    └───────────────┘       └──┬────────────────────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │ Adapter Detection   │
                                    │ (detect.py)         │
                                    └────┬──────────┬─────┘
                                         │          │
                     ┌───────────────────▼──┐    ┌──▼───────────────────┐
                     │ Androguard v4 / v5   │    │ Pure-Python Fallback │
                     │ Adapter Layer        │    │ Format Parsers       │
                     └──────────────────────┘    └──────────────────────┘
```

## Layering Principles

1. **CLI Layer (`andoguard.cli`)**:
   Thin command-line interface implemented with Typer and Rich. CLI commands invoke the public library API directly and format outputs as human-readable cards or machine-readable JSON.

2. **Public API (`andoguard.api` / `AndoGuard`)**:
   Clean, typed facade object exposing operations (`open`, `info`, `manifest`, `classes`, `disassemble`, etc.). Maintains explicit session contexts and lifecycle management (`close()`).

3. **Session & Persistence Layer (`andoguard.session`)**:
   SQLite-backed repository using WAL mode and strictly versioned migrations. Stores session metadata, analyzed targets, extracted artifacts, findings, traces, and an immutable audit event trail. No sensitive tokens or device serials are persisted.

4. **Concurrency & Execution (`andoguard.adapters.backend.BackendExecutor`)**:
   Android parser data structures (like DEX analysis and CFG graphs) have thread affinity and mutable internal state. The `BackendExecutor` encapsulates a dedicated worker thread with a task queue to ensure all parser interactions are serialized and isolated from concurrent caller threads.

5. **Adapter Layer (`andoguard.adapters`)**:
   All third-party library dependencies (such as Androguard v4/v5) are strictly confined to this layer. The rest of AndoGuard communicates solely through the abstract `BackendAdapter` protocol. If external libraries are missing or incompatible, the framework falls back cleanly without crashes.

6. **Format Parsers (`andoguard.formats`)**:
   Pure-Python format readers for APK, DEX, AXML, ARSC, and ELF containers, guaranteeing offline capability and resilient parsing even in minimal environments.
