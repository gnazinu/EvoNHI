from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app import models, schemas
from app.paths import normalize_manifest_path


def _get_required(db: Session, model, record_id: int, message: str):
    record = db.get(model, record_id)
    if not record:
        raise LookupError(message)
    return record


def create_tenant(db: Session, payload: schemas.TenantCreate) -> models.Tenant:
    existing = db.query(models.Tenant).filter(models.Tenant.slug == payload.slug).first()
    if existing:
        raise ValueError(f"Tenant slug already exists: {payload.slug}")
    tenant = models.Tenant(name=payload.name, slug=payload.slug, plan_tier=payload.plan_tier)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def create_workspace(db: Session, tenant_id: int, payload: schemas.WorkspaceCreate) -> models.Workspace:
    _get_required(db, models.Tenant, tenant_id, "Tenant not found")
    workspace = models.Workspace(tenant_id=tenant_id, name=payload.name, description=payload.description)
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    return workspace


def create_environment(db: Session, workspace_id: int, payload: schemas.EnvironmentCreate) -> models.Environment:
    _get_required(db, models.Workspace, workspace_id, "Workspace not found")
    manifests_path = normalize_manifest_path(payload.manifests_path)
    environment = models.Environment(
        workspace_id=workspace_id,
        name=payload.name,
        platform=payload.platform,
        manifests_path=manifests_path,
        entry_workloads_json=json.dumps(payload.entry_workloads),
        budget_limit=payload.budget_limit,
        notes=payload.notes,
    )
    db.add(environment)
    db.commit()
    db.refresh(environment)
    return environment


def add_crown_jewel(db: Session, environment_id: int, payload: schemas.CrownJewelCreate) -> models.CrownJewel:
    _get_required(db, models.Environment, environment_id, "Environment not found")
    existing = (
        db.query(models.CrownJewel)
        .filter(models.CrownJewel.environment_id == environment_id)
        .filter(models.CrownJewel.kind == payload.kind)
        .filter(models.CrownJewel.name == payload.name)
        .filter(models.CrownJewel.namespace == payload.namespace)
        .first()
    )
    if existing:
        raise ValueError("Crown jewel already registered for this environment")
    jewel = models.CrownJewel(
        environment_id=environment_id,
        kind=payload.kind,
        name=payload.name,
        namespace=payload.namespace,
        criticality=payload.criticality,
        rationale=payload.rationale,
    )
    db.add(jewel)
    db.commit()
    db.refresh(jewel)
    return jewel
