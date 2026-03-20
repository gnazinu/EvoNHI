from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from fastapi import Depends, HTTPException, Request, Response, Security
from fastapi.security import APIKeyCookie, APIKeyHeader, APIKeyQuery, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import models
from app.auth_utils import ensure_utc, utc_now
from app.config import settings
from app.db import get_db

_bearer = HTTPBearer(auto_error=False)
_access_token_query = APIKeyQuery(name="access_token", auto_error=False)
_access_token_cookie = APIKeyCookie(name=settings.session_cookie_name, auto_error=False)
_connector_token_header = APIKeyHeader(name="X-Connector-Token", auto_error=False)
_connector_token_query = APIKeyQuery(name="connector_token", auto_error=False)

ROLE_ORDER = {
    "viewer": 10,
    "analyst": 20,
    "editor": 30,
    "admin": 40,
    "owner": 50,
}


@dataclass(slots=True)
class AuthContext:
    user: models.User
    token: models.AccessToken
    memberships: list[models.Membership]

    def role_for_tenant(self, tenant_id: int) -> str | None:
        for membership in self.memberships:
            if membership.tenant_id == tenant_id and membership.status == "active":
                return membership.role
        return None

    def can_access_tenant(self, tenant_id: int, minimum_role: str = "viewer") -> bool:
        if self.user.is_platform_admin:
            return True
        current_role = self.role_for_tenant(tenant_id)
        if current_role is None:
            return False
        return ROLE_ORDER.get(current_role, 0) >= ROLE_ORDER.get(minimum_role, 0)


def _resolve_access_token(
    db: Session,
    raw_token: str,
) -> tuple[models.AccessToken, models.User, list[models.Membership]] | None:
    import hashlib

    hashed = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token = db.query(models.AccessToken).filter(models.AccessToken.token_hash == hashed).first()
    if not token:
        return None
    if token.revoked_at is not None:
        return None
    expires_at = ensure_utc(token.expires_at)
    if expires_at and expires_at < utc_now():
        return None
    user = token.user
    if not user or not user.is_active:
        return None
    memberships = [membership for membership in user.memberships if membership.status == "active"]
    token.last_used_at = utc_now()
    db.add(token)
    db.commit()
    db.refresh(token)
    return token, user, memberships


def _token_from_request(
    credentials: HTTPAuthorizationCredentials | None,
    access_token_query: str | None,
    access_token_cookie: str | None,
) -> str | None:
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    if access_token_query:
        return access_token_query
    if access_token_cookie:
        return access_token_cookie
    return None


def get_current_user(
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    access_token_query: str | None = Security(_access_token_query),
    access_token_cookie: str | None = Security(_access_token_cookie),
) -> AuthContext:
    raw_token = _token_from_request(credentials, access_token_query, access_token_cookie)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    resolved = _resolve_access_token(db, raw_token)
    if not resolved:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    token, user, memberships = resolved
    return AuthContext(user=user, token=token, memberships=memberships)


def get_optional_user(
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    access_token_query: str | None = Security(_access_token_query),
    access_token_cookie: str | None = Security(_access_token_cookie),
) -> AuthContext | None:
    raw_token = _token_from_request(credentials, access_token_query, access_token_cookie)
    if not raw_token:
        return None
    resolved = _resolve_access_token(db, raw_token)
    if not resolved:
        return None
    token, user, memberships = resolved
    return AuthContext(user=user, token=token, memberships=memberships)


def require_platform_admin(current_user: AuthContext = Depends(get_current_user)) -> AuthContext:
    if not current_user.user.is_platform_admin:
        raise HTTPException(status_code=403, detail="Platform admin privileges required")
    return current_user


def set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        max_age=settings.token_ttl_hours * 3600,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def require_connector_token(
    db: Session = Depends(get_db),
    connector_token_header: str | None = Security(_connector_token_header),
    connector_token_query: str | None = Security(_connector_token_query),
) -> models.ClusterConnector:
    import hashlib

    raw_token = connector_token_header or connector_token_query
    if not raw_token:
        raise HTTPException(status_code=401, detail="Connector token required")
    hashed = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    connector = db.query(models.ClusterConnector).filter(models.ClusterConnector.token_hash == hashed).first()
    if not connector:
        raise HTTPException(status_code=401, detail="Invalid connector token")
    connector.last_seen_at = utc_now()
    db.add(connector)
    db.commit()
    db.refresh(connector)
    return connector


def request_meta(request: Request) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", None),
        "ip_address": request.client.host if request.client else None,
    }
