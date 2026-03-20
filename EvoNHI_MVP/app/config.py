import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    database_url: str = os.getenv("EVONHI_DATABASE_URL", "sqlite:///./evonhi_saas.db")
    default_max_paths: int = int(os.getenv("EVONHI_DEFAULT_MAX_PATHS", "50"))


settings = Settings()
