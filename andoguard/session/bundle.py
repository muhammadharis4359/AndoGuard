"""Session bundle export and import with SHA-256 integrity verification (.agguard archives)."""

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from andoguard.config import AndoGuardConfig
from andoguard.errors import InvalidTargetError
from andoguard.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    SessionRecord,
    TargetInfo,
    TargetType,
    TraceEvent,
)
from andoguard.report.generator import generate_markdown_report
from andoguard.session.db import apply_migrations, db_session
from andoguard.session.store import SessionStore

if TYPE_CHECKING:
    from andoguard.api import AndoGuard


def export_session_bundle(ag: "AndoGuard", out_path: str | Path | None = None) -> Path:
    """Export complete AndoGuard session into a verified .agguard zip archive."""
    session_id = ag.session_record.session_id
    bundle_file = Path(out_path) if out_path else ag.session_store.config.work_dir / f"{ag.session_record.name}.agguard"
    bundle_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. Gather components
    session_dict = ag.session_record.model_dump()
    target_dict = ag.target_info.model_dump()
    findings = [f.model_dump() for f in ag.session_store.get_findings(session_id)]
    artifacts = [a.model_dump() if hasattr(a, "model_dump") else a for a in ag.session_store.get_artifacts(session_id)]
    traces = [t.model_dump() for t in ag.trace_events()]
    hooks = ag.hooks()
    report_md = generate_markdown_report(ag)

    archive_files: dict[str, str] = {
        "session.json": json.dumps(session_dict, indent=2),
        "target.json": json.dumps(target_dict, indent=2),
        "findings.json": json.dumps(findings, indent=2),
        "artifacts.json": json.dumps(artifacts, indent=2),
        "traces.json": json.dumps(traces, indent=2),
        "hooks.json": json.dumps(hooks, indent=2),
        "report.md": report_md,
    }

    # 2. Compute integrity manifest
    manifest: dict[str, str] = {}
    for fname, content in archive_files.items():
        manifest[fname] = hashlib.sha256(content.encode("utf-8")).hexdigest()

    archive_files["manifest.json"] = json.dumps(
        {
            "version": "1.0",
            "created_at": datetime.now(UTC).isoformat(),
            "session_id": session_id,
            "files": manifest,
        },
        indent=2,
    )

    # 3. Create zip archive
    with zipfile.ZipFile(bundle_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, content in archive_files.items():
            zf.writestr(fname, content.encode("utf-8"))

    return bundle_file


def import_session_bundle(
    bundle_path: str | Path,
    config: AndoGuardConfig | None = None,
) -> SessionRecord:
    """Import and verify an .agguard session archive into local database."""
    path = Path(bundle_path)
    if not path.is_file():
        raise FileNotFoundError(f"Session bundle archive not found: '{path}'")

    if not zipfile.is_zipfile(path):
        raise InvalidTargetError(str(path), reason="Not a valid zip or .agguard bundle")

    cfg = config or AndoGuardConfig.load()
    apply_migrations(cfg.database_path)
    store = SessionStore(cfg)

    with zipfile.ZipFile(path, "r") as zf:
        # Check manifest
        if "manifest.json" not in zf.namelist():
            raise InvalidTargetError(str(path), reason="Missing manifest.json in session bundle")

        manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
        files_manifest: dict[str, str] = manifest_data.get("files", {})

        # Verify integrity
        for fname, expected_hash in files_manifest.items():
            if fname not in zf.namelist():
                raise InvalidTargetError(str(path), reason=f"Corrupt bundle: missing '{fname}'")
            actual_hash = hashlib.sha256(zf.read(fname)).hexdigest()
            if actual_hash != expected_hash:
                raise InvalidTargetError(str(path), reason=f"Integrity check failed for '{fname}'")

        # Read session & target
        session_data = json.loads(zf.read("session.json").decode("utf-8"))
        target_data = json.loads(zf.read("target.json").decode("utf-8"))
        findings_data: list[dict[str, Any]] = json.loads(zf.read("findings.json").decode("utf-8"))
        traces_data: list[dict[str, Any]] = json.loads(zf.read("traces.json").decode("utf-8"))
        hooks_data: list[dict[str, Any]] = json.loads(zf.read("hooks.json").decode("utf-8"))

    # Restore target record
    t_info = TargetInfo(
        target_path=target_data["target_path"],
        target_type=TargetType(target_data["target_type"]),
        file_size=target_data["file_size"],
        md5=target_data["md5"],
        sha1=target_data["sha1"],
        sha256=target_data["sha256"],
        package_name=target_data.get("package_name"),
        version_code=target_data.get("version_code"),
        version_name=target_data.get("version_name"),
        min_sdk_version=target_data.get("min_sdk_version"),
        target_sdk_version=target_data.get("target_sdk_version"),
    )
    store.register_target(t_info)

    # Restore session record
    session_rec = SessionRecord(**session_data)
    with db_session(cfg.database_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO sessions (
                id, name, target_sha256, mode, work_dir, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                session_rec.session_id,
                session_rec.name,
                session_rec.target_sha256,
                session_rec.mode.value,
                str(cfg.get_session_dir(session_rec.session_id)),
                session_rec.notes,
                session_rec.created_at,
                session_rec.updated_at,
            ),
        )

    # Restore findings
    for f in findings_data:
        finding = Finding(
            id=f["id"],
            session_id=session_rec.session_id,
            title=f["title"],
            severity=FindingSeverity(f["severity"]),
            confidence=FindingConfidence(f["confidence"]),
            masvs_id=f.get("masvs_id"),
            evidence=f["evidence"],
            remediation=f["remediation"],
            provenance=f.get("provenance", "imported_bundle"),
            created_at=f["created_at"],
        )
        store.add_finding(finding)

    # Restore traces
    for t in traces_data:
        event = TraceEvent(
            timestamp=t["timestamp"],
            event_type=t["event_type"],
            class_name=t.get("class_name", ""),
            method_name=t.get("method_name", ""),
            args=t.get("args", []),
            return_val=t.get("return_val"),
        )
        store.save_trace_event(session_rec.session_id, event)

    # Restore hooks
    for h in hooks_data:
        store.save_hook(
            session_id=session_rec.session_id,
            class_name=h.get("class_name", ""),
            method_name=h.get("method_name", ""),
            script=h.get("script", ""),
            status=h.get("status", "active"),
        )

    store.set_active_session(session_rec.session_id)
    return session_rec
