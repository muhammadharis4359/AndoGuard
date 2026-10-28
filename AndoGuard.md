# AndoGuard — Antigravity Build Instructions

> Project brief adapted from the supplied `task.txt` specification. The original specification calls the toolkit **DroidLens**; this version uses **AndoGuard** as the requested project/product name.

## Mission

Build a production-grade Python 3.11+ toolkit named **AndoGuard** for authorized Android reverse engineering and security testing. Deliver both a CLI and an importable Python library. It should be offline-first and provide static APK/DEX/ODEX/OAT/VDEX analysis, optional live instrumentation through Frida, resumable sessions, and optional AI-assisted analysis.

**Important:** implement this in milestones. Do not pretend that a feature is complete until it works and has tests. If a dependency or format is unavailable, report the limitation clearly and offer a useful fallback.

## Core constraints

- Python 3.11 or newer; full type hints.
- Library-first design: CLI commands must be thin wrappers over public Python APIs.
- Offline by default. Network use is limited to configured AI providers and the Frida device bridge.
- Deterministic outputs for identical inputs and flags, except timestamps/path metadata.
- Third-party Android parser imports must exist only in the adapter layer.
- No global mutable state; use explicit session objects.
- Never modify the input APK/DEX/ODEX/OAT/VDEX. Write generated output only to the session work directory or an explicit output path.
- Use clear, actionable errors instead of tracebacks for expected failures.
- Authorized use only. Do not use the tool against apps or devices without permission.

## Product identity and naming

Use **AndoGuard** as the product name in documentation, CLI help, README, and user-facing messages. Use Python package/import name `andoguard` and CLI command `andoguard`, unless a technical packaging constraint requires a documented alternative. Keep internal names consistent; do not leave accidental user-facing `droidlens` labels.

## Project structure

Create a maintainable project with the following structure (adjust only when necessary and document deviations):

```text
andoguard/
├── pyproject.toml
├── README.md
├── docs/
│   ├── DECISIONS.md
│   ├── ARCHITECTURE.md
│   └── FRIDA_NOTES.md
├── andoguard/
│   ├── __init__.py
│   ├── errors.py
│   ├── config.py
│   ├── models.py
│   ├── adapters/
│   │   ├── backend.py
│   │   ├── ag_v5.py
│   │   ├── ag_v4.py
│   │   ├── detect.py
│   │   ├── frida_bridge.py
│   │   └── llm/
│   ├── formats/
│   │   ├── apk.py
│   │   ├── dex.py
│   │   ├── odex.py
│   │   ├── axml.py
│   │   ├── arsc.py
│   │   └── elf.py
│   ├── static/
│   ├── dynamic/
│   │   └── templates/
│   ├── adaptive/
│   ├── ai/
│   │   └── prompts/
│   ├── session/
│   │   ├── db.py
│   │   ├── schema.sql
│   │   └── store.py
│   ├── report/
│   │   └── templates/
│   ├── cli/
│   │   ├── main.py
│   │   ├── render.py
│   │   └── commands/
│   ├── tests/
│   └── examples/
```

## Modes

### 1. Static mode (default; offline)

Support:
- APK structure, DEX discovery, signatures/certificates, embedded `.so`, `.jar`, and assets.
- Android manifest decoding: package/version/SDK, permissions, activities, services, receivers, providers, exported components, intent filters, `debuggable`, `allowBackup`, cleartext/network security settings.
- AXML and ARSC resource decoding with filtering.
- Dalvik disassembly and best-effort Java decompilation, with explicit fallback messages when decompilation is unavailable.
- Browsing files, classes, methods, fields, strings, and cross-references.
- Secret scanning for high-entropy strings and common key/token patterns, with file/offset provenance.
- OWASP MASVS/MASTG-aligned security checks. Each finding must include severity, evidence, remediation, confidence, and provenance.
- Native `.so` triage: sections, symbols, imports, exports, JNI entry points.
- Structural APK-to-APK diffs.
- Persistent global search over strings, classes, methods, and file paths.

### 2. Dynamic mode (requires ADB and Frida)

Wrap the Frida Python API rather than reimplementing it. Support:
- Device listing and process listing, spawn, attach, resume, and kill.
- Class/method tracing with optional argument and return capture.
- Declarative, inspectable hooks rendered from versioned templates.
- Separately toggleable SSL-pinning, root-detection, debugger-detection, and emulator-detection test modules.
- Memory pattern scan, region dump, and read-at-address where supported.
- Hook generation from a selected class/method and inferred argument descriptors.
- Frida client/server compatibility checks and clear setup guidance.
- Safe cleanup: offer resume-on-exit behavior for spawned processes.
- A dry-run option for commands that touch devices or networks. Require confirmation for device mutations unless explicitly configured otherwise.

### 3. Adaptive mode

Provide an optional LLM-driven observe/plan/act/evidence/update loop that can pivot between static and dynamic evidence.

Requirements:
- Every AI claim must cite a stored tool result; findings must carry evidence references.
- Enforce hard limits for steps, tokens, elapsed time, and estimated cost.
- Support interruption, resumable transcripts, and deterministic replay of recorded tool calls.
- Autonomy levels: `off`, `device`, and `full`; mutations require confirmation except in explicitly selected full-autonomy mode.
- Without a Frida device, continue in static-only mode and mark dynamic steps as skipped.
- Without an AI provider, use a deterministic rule-based walker over the same tool registry.

Expose a typed tool registry for operations such as manifest/component/permission inspection, file/class/method browsing, code/disassembly/decompilation, xrefs, string/secret/vulnerability scans, native triage, APK diffs, Frida devices/traces/hooks, trace reading, and finding storage.

## ODEX/OAT/VDEX handling

- Detect supported container formats and extract embedded DEX files to the work directory.
- Validate DEX magic and checksums before parsing.
- Record container type, inferred Android/OAT version where possible, and extracted DEX files.
- Clearly disclose when quickened instructions cannot be fully de-optimized.
- Support an optional boot-image/framework directory for resolution attempts.
- Never claim unsupported formats are fully parsed.

## AI layer

Implement a provider protocol and optional adapters for:
- Gemini (default provider)
- OpenAI-compatible endpoints (including OpenAI, OpenRouter, LM Studio, and vLLM)
- Anthropic
- Ollama

Configuration should support a user config file and environment variables. API keys must never be logged or persisted in session databases. Local models must use context limits and chunk code at method boundaries rather than truncating arbitrarily. Route planner work to a strong model where configured, explanations to a lower-cost model, and summarization to a local model when available. Cache responses using a content hash and record provider/model, token counts, estimated cost, and latency without recording secrets.

The provider health-check command must handle unavailable endpoints gracefully and report actionable diagnostics.

## Session persistence

Use SQLite with WAL mode, foreign keys, and versioned migrations. Persist sessions, targets, artifacts, findings, cross-references, search index entries, hooks, traces, AI runs/cache, and an audit event trail.

- Deduplicate targets by SHA-256 and offer to resume an existing session.
- Support exporting/importing a session bundle.
- Never store API keys.
- Avoid persisting device serials beyond the session record.
- Keep all writes within the session work directory or explicit output paths.

## CLI requirements

Use Typer and Rich. Every command must support machine-readable `--json` output where applicable. Provide global options for session, work directory, quiet mode, and color control. Use documented exit codes and concise errors with suggested fixes.

Target command surface (implement incrementally):

```text
andoguard open <apk|dex|odex|oat|vdex|dir> [--name NAME] [--mode static|dynamic|adaptive]
andoguard sessions
andoguard resume <id-or-name>
andoguard note "<text>"
andoguard findings [--severity SEVERITY]
andoguard export <id> -o session.agguard
andoguard import <file>

andoguard info
andoguard manifest
andoguard resources [--type TYPE] [--grep PATTERN]
andoguard files [--so|--assets]
andoguard certs
andoguard classes [--grep PATTERN] [--pkg PACKAGE]
andoguard methods --class CLASS
andoguard code <CLASS-or-CLASS#METHOD> [--lang java|dalvik] [--cfg]
andoguard disasm <CLASS#METHOD> [--cfg]
andoguard xrefs --to SYMBOL
andoguard xrefs --from SYMBOL
andoguard strings [--min-len N] [--entropy]
andoguard secrets
andoguard vulns [--masvs]
andoguard native [--list|--symbols|--imports|--disasm SYMBOL]
andoguard diff <other.apk>
andoguard search <query>

andoguard dynamic devices
andoguard dynamic ps
andoguard dynamic spawn <package>
andoguard dynamic attach <package>
andoguard dynamic resume
andoguard dynamic trace --class REGEX [--method REGEX] [--args] [--ret]
andoguard dynamic hook --class CLASS --method METHOD [--script FILE]
andoguard dynamic bypass [--ssl|--root|--debug|--emulator]
andoguard dynamic gen --class CLASS --method METHOD [-o hook.js]
andoguard dynamic mem --scan PATTERN
andoguard dynamic traces [--tail N]

andoguard ai doctor
andoguard ai ask "<question>"
andoguard ai explain <CLASS#METHOD>
andoguard ai triage
andoguard adaptive run --goal "<goal>" [--max-steps N] [--auto off|device|full]
andoguard adaptive plan
andoguard adaptive replay <run-id>

andoguard report [--format md|json|html] [-o OUTPUT_DIR] [--session ID]
```

CLI usability:
- `open` should show a concise summary card as soon as possible.
- Long lists must paginate and show counts.
- Code output should be syntax-highlighted; JSON output should include offsets for pagination.
- Each command's help must include a real example.
- Commands that write files must say where.
- Show progress for long-running operations and never appear to hang.
- Print an “authorized use only” notice once in `andoguard --version`.

## Adapter layer and concurrency

Third-party parser imports belong only in `andoguard/adapters/`. Implement an abstract backend covering APK/DEX opening, classes/methods/fields/strings, bytecode, disassembly, decompilation, xrefs, vulnerability checks, AXML/ARSC, certificates, and native triage.

Support Androguard v5 and v4 through separate adapters. Detect capabilities at runtime and prefer v5 when available; missing optional capabilities should produce an actionable message instead of a traceback.

Androguard objects may be thread-affine. Implement a `BackendExecutor` with one owner worker thread and a task queue; route every backend call through it. Add a stress test that submits work concurrently from eight threads.

## Safety and performance

- Add `--dry-run` to device/network-touching commands.
- Keep hook scripts inspectable and versioned; never silently evaluate untrusted scripts.
- Every finding must have provenance and a confidence value, defaulting to medium.
- Lazy-load decompilation and avoid building full xref indexes unless requested.
- Persist and invalidate indexes based on target hash.
- Support parallel decompilation jobs where safe.
- Warn and stream when memory use becomes excessive.
- Aim to stay responsive on large APKs.

## Testing and quality gates

- Use pytest; target at least 80% coverage for formats, session, and static analysis.
- Include small local fixtures for APK, multidex APK, DEX, ODEX/OAT, and planted suspicious patterns. CI must not download fixtures.
- Add golden tests for manifest/resource decoding and JSON output.
- Run adapter contract tests for available backends and skip cleanly when dependencies are absent.
- Mark device tests so they skip without a connected device.
- Use recorded/mock AI responses in tests; never require live API calls in CI.
- Test `BackendExecutor` concurrency.
- Execute the public-library example in tests.
- Run Ruff, formatting, and strict mypy checks for core, session, and AI modules.
- CI should cover Python 3.11, 3.12, and 3.13.

## Packaging

- Build with Hatchling.
- Provide the `andoguard` console entry point.
- Declare runtime dependencies and optional extras for Frida, YARA, and development tools.
- Keep line length at 88 and add pre-commit configuration.
- Document dependency/API deviations in `docs/DECISIONS.md`.

## Public API target

Aim for an importable API with a stable surface similar to:

```python
from andoguard import AndoGuard

ag = AndoGuard.open("app.apk", session="my-app")
print(ag.info())
print(ag.manifest.permissions())
print(ag.manifest.exported_components())

for cls in ag.classes(grep="Auth"):
    print(cls.name, cls.methods)

source = ag.decompile("com.example.Auth", "login")
for line in ag.disassemble("com.example.Auth", "login"):
    print(line)

ag.xrefs.to("Ljavax/crypto/Cipher;")
ag.secrets.scan()
for finding in ag.vulns.scan():
    print(finding.masvs_id, finding.severity, finding.title)

run = ag.adaptive.run(goal="find where the API key is used", max_steps=15)
print(run.summary(), run.cost)
ag.report.to_markdown("out/report.md")
ag.close()
```

Use clear, typed interfaces and document any deliberate differences. The public API must be tested so it cannot silently break.

## Milestones — follow this order

1. **M1:** Skeleton, packaging, config, errors, models, session database/migrations, `BackendExecutor`, adapter protocol and v4/v5 detection, working `open`/`info`/`sessions`/`resume`.
2. **M2:** Manifest, resources/AXML/ARSC, file tree, certificates, strings.
3. **M3:** Classes, methods, disassembly/decompilation, navigation, JSON output.
4. **M4:** Xrefs, FTS5 search, secrets, vulnerability checks, native triage, diff.
5. **M5:** Frida bridge, devices, tracer, hook model/templates, hook generation.
6. **M6:** Bypasses, memory, trace persistence and replay.
7. **M7:** AI providers, diagnostics, context packing, cache, explain/ask/triage.
8. **M8:** Tool registry, adaptive planner/loop, budgets, replay, correlation.
9. **M9:** Reports, export/import, examples, documentation, CI, packaging polish.

Each milestone must be independently useful and tested before proceeding. Keep the main branch working and make a commit per milestone when using version control.

## Documentation deliverables

- `README.md`: five-minute quickstart and genuine sample output.
- `docs/DECISIONS.md`: one-line explanation for every non-obvious choice or deviation.
- `docs/ARCHITECTURE.md`: module boundaries, data flow, adapter model, concurrency model.
- `docs/FRIDA_NOTES.md`: device setup and Frida server/client version matching.
- `examples/library_usage.py`: demonstrates the public library API.

## Definition of done

- `pip install -e '.[dev]'` succeeds on a clean supported Python environment.
- `andoguard open sample.apk` works offline without a device.
- Supported ODEX/OAT inputs expose embedded DEX/class information, with limitations stated honestly.
- Secret scanning finds a planted test pattern with file/offset provenance.
- Hook generation emits a correctly typed script for a supported method descriptor.
- Adaptive mode works deterministically without AI and produces replayable evidence.
- JSON output validates against its documented schema.
- Expected errors never produce raw tracebacks.
- Strict mypy passes for the required modules.
- Tests and CI cover the supported Python versions.

## Instructions for Antigravity

1. Read this entire file before editing or generating code.
2. Start with **Milestone 1 only**. Do not attempt to implement all milestones in one pass.
3. Inspect the current workspace before creating files; preserve unrelated user work.
4. Create the initial project skeleton and implement M1 end-to-end, including tests and docs.
5. Record assumptions or unavoidable deviations in `docs/DECISIONS.md`.
6. Run the available tests, type checks, and lint checks. Fix failures where feasible and report anything blocked by the environment.
7. Do not claim later milestones are implemented. At the end, provide a concise report listing files created, commands run, test results, known limitations, and the next milestone.
