"""Content-hashed AI response caching in SQLite."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from andoguard.config import AndoGuardConfig
from andoguard.session.db import apply_migrations, db_session


class AiCacheManager:
    """Persistent cache for LLM reasoning and code analysis responses."""

    def __init__(self, config: AndoGuardConfig | None = None) -> None:
        self.config = config or AndoGuardConfig.load()
        self.db_path: Path = self.config.database_path
        apply_migrations(self.db_path)

    @staticmethod
    def compute_hash(
        provider: str,
        model: str,
        prompt: str,
        system: str | None = None,
    ) -> str:
        """Compute deterministic SHA-256 hash for provider, model, and prompt."""
        hasher = hashlib.sha256()
        hasher.update(provider.lower().strip().encode("utf-8"))
        hasher.update(b":")
        hasher.update(model.lower().strip().encode("utf-8"))
        hasher.update(b":")
        if system:
            hasher.update(system.encode("utf-8"))
        hasher.update(b":")
        hasher.update(prompt.encode("utf-8"))
        return hasher.hexdigest()

    def get(self, prompt_hash: str) -> str | None:
        """Retrieve cached AI response if present."""
        if not self.config.ai_cache_enabled:
            return None
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT response_text FROM ai_cache WHERE prompt_hash = ?;",
                (prompt_hash,),
            )
            row = cur.fetchone()
            if row:
                return str(row["response_text"])
        return None

    def put(
        self,
        prompt_hash: str,
        provider: str,
        model: str,
        response_text: str,
        token_count: int = 0,
        latency_ms: float = 0.0,
        cost_estimate: float = 0.0,
    ) -> None:
        """Persist AI response to SQLite cache."""
        if not self.config.ai_cache_enabled:
            return
        now = datetime.now(UTC).isoformat()
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO ai_cache (
                    prompt_hash, provider, model, response_text, token_count, latency_ms, cost_estimate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    prompt_hash,
                    provider,
                    model,
                    response_text,
                    token_count,
                    latency_ms,
                    cost_estimate,
                    now,
                ),
            )

    def clear(self) -> int:
        """Clear all entries in the AI response cache."""
        with db_session(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM ai_cache;")
            return cur.rowcount
