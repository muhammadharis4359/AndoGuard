"""Session repository and target deduplication store."""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from andoguard.config import AndoGuardConfig
from andoguard.errors import SessionNotFoundError, TargetNotFoundError
from andoguard.models import (
    AnalysisMode,
    AuditRecord,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SearchResultItem,
    SessionRecord,
    TargetInfo,
    TraceEvent,
)
from andoguard.session.db import apply_migrations, db_session


def compute_file_hashes(path: Path) -> tuple[int, str, str, str]:
    """Compute size, MD5, SHA1, and SHA256 of a file efficiently."""
    if not path.is_file():
        raise TargetNotFoundError(str(path))

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0

    with open(path, "rb") as f:
        while chunk := f.read(65536):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


class SessionStore:
    """Manages persistence for targets, sessions, findings, and audit trails."""

    def __init__(self, config: AndoGuardConfig | None = None) -> None:
        self.config = config or AndoGuardConfig.load()
        self.db_path = self.config.database_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database tables and run migrations."""
        apply_migrations(self.db_path)

    def find_target_by_sha256(self, sha256: str) -> dict[str, object] | None:
        """Find stored target by SHA256 checksum."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM targets WHERE sha256 = ?;", (sha256,))
            row = cur.fetchone()
            if row:
                return dict(row)
        return None

    def save_target(self, target: TargetInfo) -> None:
        """Persist or update target record."""
        now = datetime.now(UTC).isoformat()
        metadata = {
            "package_name": target.package_name,
            "version_code": target.version_code,
            "version_name": target.version_name,
            "min_sdk_version": target.min_sdk_version,
            "target_sdk_version": target.target_sdk_version,
            "app_name": target.app_name,
            "main_activity": target.main_activity,
            "dex_count": target.dex_count,
            "permissions_count": target.permissions_count,
            "activities_count": target.activities_count,
            "services_count": target.services_count,
            "receivers_count": target.receivers_count,
            "providers_count": target.providers_count,
            "extra": target.extra_metadata,
        }
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO targets (sha256, path, type, size, md5, sha1, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    path = excluded.path,
                    metadata_json = excluded.metadata_json;
                """,
                (
                    target.sha256,
                    target.target_path,
                    target.target_type.value,
                    target.file_size,
                    target.md5,
                    target.sha1,
                    json.dumps(metadata),
                    now,
                ),
            )

    def find_sessions_by_target(self, sha256: str) -> list[SessionRecord]:
        """Find existing sessions for the given target SHA256 hash."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM sessions WHERE target_sha256 = ? ORDER BY updated_at DESC;",
                (sha256,),
            )
            rows = cur.fetchall()
            return [
                SessionRecord(
                    session_id=row["id"],
                    name=row["name"],
                    target_sha256=row["target_sha256"],
                    target_path=row["work_dir"],
                    target_type=row["mode"],
                    mode=AnalysisMode(row["mode"]),
                    work_dir=row["work_dir"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    notes=row["notes"],
                )
                for row in rows
            ]

    def create_session(
        self,
        target: TargetInfo,
        name: str | None = None,
        mode: AnalysisMode = AnalysisMode.STATIC,
        notes: str | None = None,
    ) -> SessionRecord:
        """Create a new session, persisting target and initial audit record."""
        self.save_target(target)

        session_id = str(uuid.uuid4())[:8]
        if not name:
            sanitized = Path(target.target_path).stem.replace(" ", "_")
            name = f"{sanitized}-{session_id}"
        else:
            with db_session(self.db_path) as conn:
                existing = conn.execute(
                    "SELECT id FROM sessions WHERE name = ?;", (name,)
                ).fetchone()
                if existing:
                    name = f"{name}-{session_id}"

        session_dir = self.config.get_session_dir(session_id)
        now = datetime.now(UTC).isoformat()

        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sessions (id, name, target_sha256, mode, work_dir, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    session_id,
                    name,
                    target.sha256,
                    mode.value,
                    str(session_dir),
                    notes,
                    now,
                    now,
                ),
            )

        self.add_audit_event(
            session_id=session_id,
            event_type="SESSION_CREATED",
            details=f"Created session '{name}' ({session_id}) for target {target.target_path} (SHA-256: {target.sha256})",
        )

        # Set as active session
        self.config.active_session_id = session_id
        self.config.save()

        return SessionRecord(
            session_id=session_id,
            name=name,
            target_sha256=target.sha256,
            target_path=target.target_path,
            target_type=target.target_type.value,
            mode=mode,
            work_dir=str(session_dir),
            created_at=now,
            updated_at=now,
            notes=notes,
        )

    def get_session(self, identifier: str) -> SessionRecord | None:
        """Lookup session by ID or exact name."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT s.*, t.path as orig_target_path, t.type as orig_target_type
                FROM sessions s
                JOIN targets t ON s.target_sha256 = t.sha256
                WHERE s.id = ? OR s.name = ?;
                """,
                (identifier, identifier),
            )
            row = cur.fetchone()
            if not row:
                return None

            return SessionRecord(
                session_id=row["id"],
                name=row["name"],
                target_sha256=row["target_sha256"],
                target_path=row["orig_target_path"],
                target_type=row["orig_target_type"],
                mode=AnalysisMode(row["mode"]),
                work_dir=row["work_dir"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                notes=row["notes"],
            )

    def list_sessions(self) -> list[SessionRecord]:
        """Return all persisted sessions ordered by updated timestamp."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT s.*, t.path as orig_target_path, t.type as orig_target_type
                FROM sessions s
                JOIN targets t ON s.target_sha256 = t.sha256
                ORDER BY s.updated_at DESC;
                """
            )
            rows = cur.fetchall()
            return [
                SessionRecord(
                    session_id=row["id"],
                    name=row["name"],
                    target_sha256=row["target_sha256"],
                    target_path=row["orig_target_path"],
                    target_type=row["orig_target_type"],
                    mode=AnalysisMode(row["mode"]),
                    work_dir=row["work_dir"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    notes=row["notes"],
                )
                for row in rows
            ]

    def set_active_session(self, identifier: str) -> SessionRecord:
        """Mark a session as active in configuration."""
        record = self.get_session(identifier)
        if not record:
            raise SessionNotFoundError(identifier)

        self.config.active_session_id = record.session_id
        self.config.save()

        now = datetime.now(UTC).isoformat()
        with db_session(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE id = ?;",
                (now, record.session_id),
            )

        self.add_audit_event(
            session_id=record.session_id,
            event_type="SESSION_RESUMED",
            details=f"Session resumed as active session: {record.session_id}",
        )
        return record

    def get_active_session(self) -> SessionRecord | None:
        """Retrieve current active session if set, or most recent."""
        if self.config.active_session_id:
            found = self.get_session(self.config.active_session_id)
            if found:
                return found

        # Fallback to most recent session
        sessions = self.list_sessions()
        if sessions:
            self.config.active_session_id = sessions[0].session_id
            self.config.save()
            return sessions[0]

        return None

    def add_audit_event(self, session_id: str, event_type: str, details: str) -> None:
        """Append an event to the session audit trail."""
        now = datetime.now(UTC).isoformat()
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_events (session_id, event_type, details, timestamp)
                VALUES (?, ?, ?, ?);
                """,
                (session_id, event_type, details, now),
            )

    def get_audit_events(self, session_id: str) -> list[AuditRecord]:
        """Fetch chronological audit records for a session."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM audit_events WHERE session_id = ? ORDER BY id ASC;",
                (session_id,),
            )
            rows = cur.fetchall()
            return [
                AuditRecord(
                    id=row["id"],
                    session_id=row["session_id"],
                    event_type=row["event_type"],
                    details=row["details"],
                    timestamp=row["timestamp"],
                )
                for row in rows
            ]

    def add_finding(self, finding: Finding) -> None:
        """Persist a security finding."""
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO findings (id, session_id, title, severity, confidence, masvs_id, evidence, remediation, provenance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    evidence = excluded.evidence,
                    remediation = excluded.remediation;
                """,
                (
                    finding.id,
                    finding.session_id,
                    finding.title,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.masvs_id,
                    finding.evidence,
                    finding.remediation,
                    finding.provenance,
                    finding.created_at,
                ),
            )

    def record_finding(
        self,
        session_id: str,
        title: str,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        evidence: str,
        remediation: str,
        masvs_id: str | None = None,
        provenance: str = "manual",
    ) -> str:
        """Create and persist a new Finding record."""
        fid = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        finding = Finding(
            id=fid,
            session_id=session_id,
            title=title,
            severity=severity,
            confidence=confidence,
            masvs_id=masvs_id,
            evidence=evidence,
            remediation=remediation,
            provenance=provenance,
            created_at=now,
        )
        self.add_finding(finding)
        return fid

    def get_findings(
        self, session_id: str, severity: FindingSeverity | None = None
    ) -> list[Finding]:
        """Retrieve findings for a session with optional severity filter."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            if severity:
                cur.execute(
                    "SELECT * FROM findings WHERE session_id = ? AND severity = ? ORDER BY created_at ASC;",
                    (session_id, severity.value),
                )
            else:
                cur.execute(
                    "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at ASC;",
                    (session_id,),
                )
            rows = cur.fetchall()
            return [
                Finding(
                    id=row["id"],
                    session_id=row["session_id"],
                    title=row["title"],
                    severity=FindingSeverity(row["severity"]),
                    confidence=FindingConfidence(row["confidence"]),
                    masvs_id=row["masvs_id"],
                    evidence=row["evidence"],
                    remediation=row["remediation"],
                    provenance=row["provenance"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def index_search_items(
        self, session_id: str, items: list[tuple[str, str, str]]
    ) -> None:
        """Bulk index items (item_type, identifier, snippet) for full-text search."""
        if not items:
            return
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.executemany(
                "INSERT INTO search_index (id, session_id, item_type, identifier, snippet) VALUES (?, ?, ?, ?, ?);",
                [
                    (str(uuid.uuid4()), session_id, itype, ident, snip)
                    for itype, ident, snip in items
                ],
            )

    def search(
        self, query: str, session_id: str | None = None
    ) -> list[SearchResultItem]:
        """Search indexed symbols, strings, and components."""
        pattern = f"%{query}%"
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            if session_id:
                cur.execute(
                    """
                    SELECT item_type, identifier, snippet, session_id
                    FROM search_index
                    WHERE session_id = ? AND (identifier LIKE ? OR snippet LIKE ?)
                    LIMIT 200;
                    """,
                    (session_id, pattern, pattern),
                )
            else:
                cur.execute(
                    """
                    SELECT item_type, identifier, snippet, session_id
                    FROM search_index
                    WHERE identifier LIKE ? OR snippet LIKE ?
                    LIMIT 200;
                    """,
                    (pattern, pattern),
                )
            rows = cur.fetchall()
            return [
                SearchResultItem(
                    item_type=row["item_type"],
                    identifier=row["identifier"],
                    snippet=row["snippet"],
                    session_id=row["session_id"],
                )
                for row in rows
            ]

    def save_trace_event(self, session_id: str, event: TraceEvent) -> None:
        """Persist dynamic trace event into session traces table."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO traces (id, session_id, timestamp, event_type, class_name, method_name, args_json, ret_val)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(uuid.uuid4()),
                    session_id,
                    event.timestamp,
                    event.event_type,
                    event.class_name,
                    event.method_name,
                    json.dumps(event.args),
                    event.return_val,
                ),
            )

    def get_trace_events(self, session_id: str) -> list[TraceEvent]:
        """Retrieve stored trace events for session."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM traces WHERE session_id = ? ORDER BY timestamp ASC;",
                (session_id,),
            )
            rows = cur.fetchall()
            results: list[TraceEvent] = []
            for r in rows:
                args_list = []
                if r["args_json"]:
                    try:
                        args_list = json.loads(r["args_json"])
                    except Exception:
                        args_list = []
                results.append(
                    TraceEvent(
                        timestamp=r["timestamp"],
                        event_type=r["event_type"],
                        class_name=r["class_name"] or "",
                        method_name=r["method_name"] or "",
                        args=[str(a) for a in args_list],
                        return_val=r["ret_val"],
                    )
                )
            return results

    def save_hook(
        self,
        session_id: str,
        class_name: str,
        method_name: str,
        script: str,
        status: str = "active",
    ) -> str:
        """Record installed hook script in database."""
        hook_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO hooks (id, session_id, class_name, method_name, script, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (hook_id, session_id, class_name, method_name, script, status, now),
            )
        return hook_id

    def get_hooks(self, session_id: str) -> list[dict[str, Any]]:
        """Retrieve recorded hooks for session."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM hooks WHERE session_id = ? ORDER BY created_at ASC;",
                (session_id,),
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]


