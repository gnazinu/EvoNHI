from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app import models, schemas
from app.paths import normalize_manifest_path
from app.services.audit_service import record_audit_event


def _get_required(db: Session, model, record_id: int, message: str):
    record = db.get(model, record_id)
    if not record:
        raise LookupError(message)
    return record


def _tenant_limits(tenant: models.Tenant) -> dict:
    settings = tenant.settings
    return {
        "max_environments": int(settings.get("max_environments", 0) or 0),
        "max_connectors": int(settings.get("max_connectors", 0) or 0),
        "max_daily_analysis_runs": int(settings.get("max_daily_analysis_runs", 0) or 0),
        "retention_days": int(settings.get("retention_days", 90) or 90),
    }


def update_tenant_settings(
    db: Session,
    tenant: models.Tenant,
    payload: schemas.TenantSettingsUpdate,
    *,
    user_id: int,
    request_meta: dict[str, str | None] | None = None,
) -> models.Tenant:
    settings = tenant.settings
    if payload.max_environments is not None:
        settings["max_environments"] = payload.max_environments
    if payload.max_connectors is not None:
        settings["max_connectors"] = payload.max_connectors
    if payload.max_daily_analysis_runs is not None:
        settings["max_daily_analysis_runs"] = payload.max_daily_analysis_runs
    if payload.retention_days is not None:
        settings["retention_days"] = payload.retention_days
    if payload.enabled_features is not None:
        tenant.feature_flags_json = json.dumps(payload.enabled_features)
    tenant.settings_json = json.dumps(settings)
    db.add(tenant)
    record_audit_event(
        db,
        action="tenant.settings.update",
        resource_type="tenant",
        resource_id=str(tenant.id),
        tenant_id=tenant.id,
        user_id=user_id,
        details=settings,
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(tenant)
    return tenant


def create_workspace(
    db: Session,
    tenant: models.Tenant,
    payload: schemas.WorkspaceCreate,
    *,
    user_id: int,
    request_meta: dict[str, str | None] | None = None,
) -> models.Workspace:
    workspace = models.Workspace(tenant_id=tenant.id, name=payload.name, description=payload.description)
    db.add(workspace)
    db.flush()
    record_audit_event(
        db,
        action="workspace.create",
        resource_type="workspace",
        resource_id=str(workspace.id),
        tenant_id=tenant.id,
        user_id=user_id,
        details={"name": workspace.name},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(workspace)
    return workspace


def create_environment(
    db: Session,
    workspace: models.Workspace,
    payload: schemas.EnvironmentCreate,
    *,
    user_id: int,
    request_meta: dict[str, str | None] | None = None,
) -> models.Environment:
    tenant = workspace.tenant
    current_count = db.query(models.Environment).filter(models.Environment.tenant_id == workspace.tenant_id).count()
    limits = _tenant_limits(tenant)
    if limits["max_environments"] and current_count >= limits["max_environments"]:
        raise ValueError("Tenant environment quota reached")

    manifests_path = normalize_manifest_path(payload.manifests_path)
    environment = models.Environment(
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
        name=payload.name,
        platform=payload.platform,
        manifests_path=manifests_path,
        entry_workloads_json=json.dumps(payload.entry_workloads),
        budget_limit=payload.budget_limit,
        notes=payload.notes,
    )
    db.add(environment)
    db.flush()
    record_audit_event(
        db,
        action="environment.create",
        resource_type="environment",
        resource_id=str(environment.id),
        tenant_id=workspace.tenant_id,
        user_id=user_id,
        details={"workspace_id": workspace.id, "platform": environment.platform},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(environment)
    return environment


def add_crown_jewel(
    db: Session,
    environment: models.Environment,
    payload: schemas.CrownJewelCreate,
    *,
    user_id: int,
    request_meta: dict[str, str | None] | None = None,
) -> models.CrownJewel:
    existing = (
        db.query(models.CrownJewel)
        .filter(models.CrownJewel.environment_id == environment.id)
        .filter(models.CrownJewel.kind == payload.kind)
        .filter(models.CrownJewel.name == payload.name)
        .filter(models.CrownJewel.namespace == payload.namespace)
        .first()
    )
    if existing:
        raise ValueError("Crown jewel already registered for this environment")
    jewel = models.CrownJewel(
        tenant_id=environment.tenant_id,
        environment_id=environment.id,
        kind=payload.kind,
        name=payload.name,
        namespace=payload.namespace,
        criticality=payload.criticality,
        rationale=payload.rationale,
    )
    db.add(jewel)
    db.flush()
    record_audit_event(
        db,
        action="crown_jewel.create",
        resource_type="crown_jewel",
        resource_id=str(jewel.id),
        tenant_id=environment.tenant_id,
        user_id=user_id,
        details={"environment_id": environment.id, "kind": jewel.kind},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(jewel)
    return jewel
