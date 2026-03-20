from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


@dataclass(slots=True)
class Settings:
    database_url: str = os.getenv("EVONHI_DATABASE_URL", "sqlite:///./evonhi_saas.db")
    default_max_paths: int = _env_int("EVONHI_DEFAULT_MAX_PATHS", 50)
    max_paths_limit: int = _env_int("EVONHI_MAX_PATHS_LIMIT", 250)
    max_path_depth: int = _env_int("EVONHI_MAX_PATH_DEPTH", 8)
    manifest_root: Path = field(
        default_factory=lambda: Path(os.getenv("EVONHI_MANIFEST_ROOT", str(Path.cwd()))).resolve()
    )
    api_key: str | None = os.getenv("EVONHI_API_KEY") or None

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_key)


settings = Settings()
