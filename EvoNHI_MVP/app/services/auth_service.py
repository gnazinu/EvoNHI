from __future__ import annotations

from sqlalchemy.orm import Session

from app import models, schemas
from app.auth_utils import generate_token, hash_password, token_expiry, token_prefix, utc_now, verify_password
from app.config import settings
from app.services.audit_service import record_audit_event


def _create_access_token(db: Session, user: models.User, label: str = "interactive-session") -> tuple[models.AccessToken, str]:
    raw_token, hashed = generate_token()
    token = models.AccessToken(
        user_id=user.id,
        label=label,
        token_prefix=token_prefix(raw_token),
        token_hash=hashed,
        expires_at=token_expiry(hours=settings.token_ttl_hours),
    )
    db.add(token)
    db.flush()
    return token, raw_token


def _token_payload(user: models.User, memberships: list[models.Membership], raw_token: str, token: models.AccessToken) -> dict:
    return {
        "access_token": raw_token,
        "expires_at": token.expires_at,
        "user": user,
        "memberships": memberships,
    }


def register_bootstrap_user(
    db: Session,
    payload: schemas.BootstrapRegister,
    request_meta: dict[str, str | None] | None = None,
) -> dict:
    existing_user = db.query(models.User).filter(models.User.email == payload.email.lower()).first()
    if existing_user:
        raise ValueError("User already exists")
    existing_tenant = db.query(models.Tenant).filter(models.Tenant.slug == payload.tenant_slug).first()
    if existing_tenant:
        raise ValueError("Tenant slug already exists")

    tenant = models.Tenant(name=payload.tenant_name, slug=payload.tenant_slug, plan_tier="enterprise")
    existing_users = db.query(models.User).count()
    user = models.User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        is_platform_admin=existing_users == 0,
    )
    db.add(tenant)
    db.add(user)
    db.flush()

    membership = models.Membership(user_id=user.id, tenant_id=tenant.id, role="owner", status="active")
    db.add(membership)
    token, raw_token = _create_access_token(db, user)

    record_audit_event(
        db,
        action="auth.bootstrap_register",
        resource_type="tenant",
        resource_id=str(tenant.id),
        tenant_id=tenant.id,
        user_id=user.id,
        details={"email": user.email, "role": "owner"},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(user)
    db.refresh(tenant)
    memberships = [membership]
    return _token_payload(user, memberships, raw_token, token)


def authenticate_user(
    db: Session,
    payload: schemas.LoginRequest,
    request_meta: dict[str, str | None] | None = None,
) -> dict:
    user = db.query(models.User).filter(models.User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise ValueError("Invalid email or password")
    if not user.is_active:
        raise ValueError("User is inactive")
    user.last_login_at = utc_now()
    token, raw_token = _create_access_token(db, user)
    memberships = [membership for membership in user.memberships if membership.status == "active"]
    record_audit_event(
        db,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
        tenant_id=memberships[0].tenant_id if memberships else None,
        user_id=user.id,
        details={"membership_count": len(memberships)},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(user)
    return _token_payload(user, memberships, raw_token, token)


def create_tenant_for_user(
    db: Session,
    user: models.User,
    payload: schemas.TenantCreate,
    request_meta: dict[str, str | None] | None = None,
) -> models.Tenant:
    existing_tenant = db.query(models.Tenant).filter(models.Tenant.slug == payload.slug).first()
    if existing_tenant:
        raise ValueError("Tenant slug already exists")
    tenant = models.Tenant(name=payload.name, slug=payload.slug, plan_tier=payload.plan_tier)
    db.add(tenant)
    db.flush()
    membership = models.Membership(user_id=user.id, tenant_id=tenant.id, role="owner", status="active")
    db.add(membership)
    record_audit_event(
        db,
        action="tenant.create",
        resource_type="tenant",
        resource_id=str(tenant.id),
        tenant_id=tenant.id,
        user_id=user.id,
        details={"plan_tier": tenant.plan_tier},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(tenant)
    return tenant
