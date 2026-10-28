"""Tests for SQLite session store, migrations, and target deduplication."""

from pathlib import Path

from andoguard.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    TargetInfo,
    TargetType,
)
from andoguard.session.db import get_db_connection
from andoguard.session.store import SessionStore, compute_file_hashes


def test_sqlite_wal_mode_and_foreign_keys(test_store: SessionStore) -> None:
    conn = get_db_connection(test_store.db_path)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode;")
        mode = cur.fetchone()[0]
        assert mode.lower() == "wal"

        cur.execute("PRAGMA foreign_keys;")
        fk = cur.fetchone()[0]
        assert fk == 1
    finally:
        conn.close()


def test_target_deduplication(test_store: SessionStore, sample_apk_path: Path) -> None:
    size, md5, sha1, sha256 = compute_file_hashes(sample_apk_path)

    target_info = TargetInfo(
        target_path=str(sample_apk_path),
        target_type=TargetType.APK,
        file_size=size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        package_name="com.example.testapp",
        dex_count=1,
    )

    # 1. Create first session
    session1 = test_store.create_session(target_info, name="session-1")
    assert session1.name == "session-1"
    assert session1.target_sha256 == sha256

    # 2. Check target was saved and can be found by SHA-256
    found = test_store.find_target_by_sha256(sha256)
    assert found is not None
    assert found["sha256"] == sha256

    # 3. Find existing sessions by target SHA-256
    existing = test_store.find_sessions_by_target(sha256)
    assert len(existing) == 1
    assert existing[0].session_id == session1.session_id

    # 4. Create second session on same target (deduplication check)
    session2 = test_store.create_session(target_info, name="session-2")
    assert session2.name == "session-2"
    existing_after = test_store.find_sessions_by_target(sha256)
    assert len(existing_after) == 2


def test_session_lifecycle_and_audit(
    test_store: SessionStore, sample_apk_path: Path
) -> None:
    size, md5, sha1, sha256 = compute_file_hashes(sample_apk_path)
    target_info = TargetInfo(
        target_path=str(sample_apk_path),
        target_type=TargetType.APK,
        file_size=size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )

    session = test_store.create_session(target_info, name="audit-test-session")

    # List sessions
    sessions = test_store.list_sessions()
    assert any(s.session_id == session.session_id for s in sessions)

    # Lookup by ID
    s_by_id = test_store.get_session(session.session_id)
    assert s_by_id is not None
    assert s_by_id.name == "audit-test-session"

    # Lookup by name
    s_by_name = test_store.get_session("audit-test-session")
    assert s_by_name is not None
    assert s_by_name.session_id == session.session_id

    # Audit events
    events = test_store.get_audit_events(session.session_id)
    assert len(events) >= 1
    assert events[0].event_type == "SESSION_CREATED"

    # Resume session
    resumed = test_store.set_active_session(session.session_id)
    assert resumed.session_id == session.session_id
    updated_events = test_store.get_audit_events(session.session_id)
    assert any(e.event_type == "SESSION_RESUMED" for e in updated_events)


def test_session_findings_storage(
    test_store: SessionStore, sample_apk_path: Path
) -> None:
    size, md5, sha1, sha256 = compute_file_hashes(sample_apk_path)
    target_info = TargetInfo(
        target_path=str(sample_apk_path),
        target_type=TargetType.APK,
        file_size=size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )
    session = test_store.create_session(target_info)

    finding = Finding(
        id="f-101",
        session_id=session.session_id,
        title="Insecure Cleartext Traffic Allowed",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        masvs_id="MASVS-NETWORK-1",
        evidence="android:usesCleartextTraffic='true'",
        remediation="Set usesCleartextTraffic to false",
        provenance="AndroidManifest.xml:L12",
        created_at="2026-10-28T12:00:00Z",
    )
    test_store.add_finding(finding)

    findings = test_store.get_findings(session.session_id)
    assert len(findings) == 1
    assert findings[0].id == "f-101"
    assert findings[0].severity == FindingSeverity.HIGH
