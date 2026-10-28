"""Configuration management for AndoGuard."""

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from andoguard.models import AnalysisMode


class AndoGuardConfig(BaseModel):
    """Runtime configuration for AndoGuard operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    work_dir: Path = Field(default_factory=lambda: Path.home() / ".andoguard")
    default_mode: AnalysisMode = AnalysisMode.STATIC
    quiet: bool = False
    no_color: bool = False
    json_output: bool = False
    active_session_id: str | None = None

    @classmethod
    def load(cls, config_path: Path | None = None) -> "AndoGuardConfig":
        """Load configuration from file and environment variables."""
        work_dir_env = os.environ.get("ANDOGUARD_WORK_DIR")
        default_dir = Path(work_dir_env) if work_dir_env else Path.home() / ".andoguard"

        cfg_file = config_path or (default_dir / "config.json")
        data: dict[str, Any] = {}

        if cfg_file.exists():
            try:
                with open(cfg_file, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                # If config file is corrupted, fall back gracefully
                pass

        if work_dir_env:
            data["work_dir"] = default_dir

        mode_env = os.environ.get("ANDOGUARD_MODE")
        if mode_env and mode_env in {m.value for m in AnalysisMode}:
            data["default_mode"] = AnalysisMode(mode_env)

        config = cls(**data)
        config.ensure_directories()
        return config

    def save(self, config_path: Path | None = None) -> None:
        """Persist current configuration to disk without sensitive keys."""
        self.ensure_directories()
        cfg_file = config_path or (self.work_dir / "config.json")
        payload = {
            "work_dir": str(self.work_dir),
            "default_mode": self.default_mode.value,
            "quiet": self.quiet,
            "no_color": self.no_color,
            "json_output": self.json_output,
            "active_session_id": self.active_session_id,
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def ensure_directories(self) -> None:
        """Create necessary working directory and sessions store."""
        self.work_dir.mkdir(parents=True, exist_ok=True)
        (self.work_dir / "sessions").mkdir(parents=True, exist_ok=True)

    def get_session_dir(self, session_id: str) -> Path:
        """Get dedicated directory path for a specific session."""
        session_path = self.work_dir / "sessions" / session_id
        session_path.mkdir(parents=True, exist_ok=True)
        return session_path

    @property
    def database_path(self) -> Path:
        """Path to SQLite session database."""
        return self.work_dir / "sessions.db"
