"""Database connection and migration manager for AndoGuard sessions."""

import contextlib
import sqlite3
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

CURRENT_SCHEMA_VERSION = 1


def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Create and configure a SQLite connection with WAL mode and foreign keys."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    return conn


@contextlib.contextmanager
def db_session(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite transactions."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def apply_migrations(db_path: Path) -> int:
    """Apply schema migrations up to the current schema version."""
    schema_sql_path = Path(__file__).parent / "schema.sql"
    if not schema_sql_path.exists():
        raise FileNotFoundError(f"Schema file not found at {schema_sql_path}")

    with db_session(db_path) as conn:
        # Check current version
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';"
        )
        has_migrations_table = cur.fetchone() is not None

        current_v = 0
        if has_migrations_table:
            cur.execute("SELECT MAX(version) FROM schema_migrations;")
            row = cur.fetchone()
            if row and row[0] is not None:
                current_v = int(row[0])

        if current_v < 1:
            with open(schema_sql_path, encoding="utf-8") as f:
                schema_sql = f.read()
            conn.executescript(schema_sql)
            now = datetime.now(UTC).isoformat()
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                (1, now),
            )
            current_v = 1

    return current_v
