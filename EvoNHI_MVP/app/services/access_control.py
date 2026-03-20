from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import models
from app.security import AuthContext


def ensure_tenant_access(current_user: AuthContext, tenant_id: int, minimum_role: str = "viewer") -> None:
    if not current_user.can_access_tenant(tenant_id, minimum_role=minimum_role):
        raise HTTPException(status_code=403, detail="Insufficient access for this tenant")


def get_workspace_for_user(db: Session, workspace_id: int, current_user: AuthContext, minimum_role: str = "viewer") -> models.Workspace:
    workspace = db.get(models.Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_tenant_access(current_user, workspace.tenant_id, minimum_role=minimum_role)
    return workspace


def get_environment_for_user(db: Session, environment_id: int, current_user: AuthContext, minimum_role: str = "viewer") -> models.Environment:
    environment = db.get(models.Environment, environment_id)
    if not environment:
        raise HTTPException(status_code=404, detail="Environment not found")
    ensure_tenant_access(current_user, environment.tenant_id, minimum_role=minimum_role)
    return environment


def get_analysis_run_for_user(db: Session, run_id: int, current_user: AuthContext, minimum_role: str = "viewer") -> models.AnalysisRun:
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    ensure_tenant_access(current_user, run.tenant_id, minimum_role=minimum_role)
    return run


def get_remediation_plan_for_user(db: Session, plan_id: int, current_user: AuthContext, minimum_role: str = "viewer") -> models.RemediationPlan:
    plan = db.get(models.RemediationPlan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    ensure_tenant_access(current_user, plan.tenant_id, minimum_role=minimum_role)
    return plan


def get_connector_for_user(db: Session, connector_id: int, current_user: AuthContext, minimum_role: str = "viewer") -> models.ClusterConnector:
    connector = db.get(models.ClusterConnector, connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    ensure_tenant_access(current_user, connector.tenant_id, minimum_role=minimum_role)
    return connector
