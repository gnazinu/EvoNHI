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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    app_env: str = os.getenv("EVONHI_ENV", "development")
    database_url: str = os.getenv(
        "EVONHI_DATABASE_URL",
        "postgresql+psycopg://evonhi:evonhi@localhost:5432/evonhi",
    )
    manifest_root: Path = field(
        default_factory=lambda: Path(os.getenv("EVONHI_MANIFEST_ROOT", str(Path.cwd()))).resolve()
    )
    default_max_paths: int = _env_int("EVONHI_DEFAULT_MAX_PATHS", 50)
    max_paths_limit: int = _env_int("EVONHI_MAX_PATHS_LIMIT", 250)
    max_path_depth: int = _env_int("EVONHI_MAX_PATH_DEPTH", 8)
    max_graph_nodes: int = _env_int("EVONHI_MAX_GRAPH_NODES", 25000)
    max_graph_edges: int = _env_int("EVONHI_MAX_GRAPH_EDGES", 120000)
    max_analysis_attempts: int = _env_int("EVONHI_MAX_ANALYSIS_ATTEMPTS", 3)
    analysis_job_poll_seconds: int = _env_int("EVONHI_ANALYSIS_JOB_POLL_SECONDS", 2)
    analysis_job_timeout_seconds: int = _env_int("EVONHI_ANALYSIS_JOB_TIMEOUT_SECONDS", 300)
    analysis_worker_id: str = os.getenv("EVONHI_ANALYSIS_WORKER_ID", "worker-local")
    run_embedded_worker: bool = _env_bool("EVONHI_RUN_EMBEDDED_WORKER", False)
    token_ttl_hours: int = _env_int("EVONHI_TOKEN_TTL_HOURS", 12)
    session_cookie_name: str = os.getenv("EVONHI_SESSION_COOKIE_NAME", "evonhi_session")
    session_cookie_secure: bool = _env_bool("EVONHI_SESSION_COOKIE_SECURE", False)
    session_cookie_samesite: str = os.getenv("EVONHI_SESSION_COOKIE_SAMESITE", "lax").lower()
    connector_token_ttl_hours: int = _env_int("EVONHI_CONNECTOR_TOKEN_TTL_HOURS", 24 * 90)
    default_tenant_max_environments: int = _env_int("EVONHI_DEFAULT_TENANT_MAX_ENVIRONMENTS", 15)
    default_tenant_max_connectors: int = _env_int("EVONHI_DEFAULT_TENANT_MAX_CONNECTORS", 30)
    default_tenant_max_daily_runs: int = _env_int("EVONHI_DEFAULT_TENANT_MAX_DAILY_RUNS", 200)
    metrics_history_size: int = _env_int("EVONHI_METRICS_HISTORY_SIZE", 1000)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


settings = Settings()
