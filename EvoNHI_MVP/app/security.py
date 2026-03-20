from __future__ import annotations

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader, APIKeyQuery

from app.config import settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_api_key_query = APIKeyQuery(name="api_key", auto_error=False)


def require_api_key(
    api_key_header: str | None = Security(_api_key_header),
    api_key_query: str | None = Security(_api_key_query),
) -> str | None:
    if not settings.auth_enabled:
        return None

    provided_key = api_key_header or api_key_query
    if not provided_key or provided_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return provided_key
