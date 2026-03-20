from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app import models, schemas


def create_tenant(db: Session, payload: schemas.TenantCreate) -> models.Tenant:
    tenant = models.Tenant(name=payload.name, slug=payload.slug, plan_tier=payload.plan_tier)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def create_workspace(db: Session, tenant_id: int, payload: schemas.WorkspaceCreate) -> models.Workspace:
    workspace = models.Workspace(tenant_id=tenant_id, name=payload.name, description=payload.description)
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    return workspace


def create_environment(db: Session, workspace_id: int, payload: schemas.EnvironmentCreate) -> models.Environment:
    environment = models.Environment(
        workspace_id=workspace_id,
        name=payload.name,
        platform=payload.platform,
        manifests_path=payload.manifests_path,
        entry_workloads_json=json.dumps(payload.entry_workloads),
        budget_limit=payload.budget_limit,
        notes=payload.notes,
    )
    db.add(environment)
    db.commit()
    db.refresh(environment)
    return environment


def add_crown_jewel(db: Session, environment_id: int, payload: schemas.CrownJewelCreate) -> models.CrownJewel:
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
