from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import get_db
from app.services.analysis_service import analysis_run_to_dict, build_dashboard, run_analysis
from app.services.onboarding import add_crown_jewel, create_environment, create_tenant, create_workspace
from app.security import require_api_key

router = APIRouter(prefix="/api/v1", tags=["evonhi-saas"], dependencies=[Depends(require_api_key)])


def _raise_http(exc: Exception) -> None:
    detail = str(exc)
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=404, detail=detail) from exc
    if "already exists" in detail or "already registered" in detail:
        raise HTTPException(status_code=409, detail=detail) from exc
    raise HTTPException(status_code=400, detail=detail) from exc


@router.get("/tenants", response_model=list[schemas.TenantRead])
def list_tenants(db: Session = Depends(get_db)):
    return db.query(models.Tenant).order_by(models.Tenant.created_at.desc()).all()


@router.post("/tenants", response_model=schemas.TenantRead)
def create_tenant_route(payload: schemas.TenantCreate, db: Session = Depends(get_db)):
    try:
        return create_tenant(db, payload)
    except (LookupError, ValueError) as exc:
        _raise_http(exc)


@router.get("/tenants/{tenant_id}/workspaces", response_model=list[schemas.WorkspaceRead])
def list_workspaces(tenant_id: int, db: Session = Depends(get_db)):
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return db.query(models.Workspace).filter(models.Workspace.tenant_id == tenant_id).order_by(models.Workspace.created_at.desc()).all()


@router.post("/tenants/{tenant_id}/workspaces", response_model=schemas.WorkspaceRead)
def create_workspace_route(tenant_id: int, payload: schemas.WorkspaceCreate, db: Session = Depends(get_db)):
    try:
        return create_workspace(db, tenant_id, payload)
    except (LookupError, ValueError) as exc:
        _raise_http(exc)


@router.get("/workspaces/{workspace_id}/environments", response_model=list[schemas.EnvironmentRead])
def list_environments(workspace_id: int, db: Session = Depends(get_db)):
    workspace = db.get(models.Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return db.query(models.Environment).filter(models.Environment.workspace_id == workspace_id).order_by(models.Environment.created_at.desc()).all()


@router.post("/workspaces/{workspace_id}/environments", response_model=schemas.EnvironmentRead)
def create_environment_route(workspace_id: int, payload: schemas.EnvironmentCreate, db: Session = Depends(get_db)):
    try:
        return create_environment(db, workspace_id, payload)
    except (LookupError, ValueError) as exc:
        _raise_http(exc)


@router.post("/environments/{environment_id}/crown-jewels", response_model=schemas.CrownJewelRead)
def add_crown_jewel_route(environment_id: int, payload: schemas.CrownJewelCreate, db: Session = Depends(get_db)):
    try:
        return add_crown_jewel(db, environment_id, payload)
    except (LookupError, ValueError) as exc:
        _raise_http(exc)


@router.get("/environments/{environment_id}/analysis-runs", response_model=list[schemas.AnalysisRunRead])
def list_analysis_runs(environment_id: int, db: Session = Depends(get_db)):
    environment = db.get(models.Environment, environment_id)
    if not environment:
        raise HTTPException(status_code=404, detail="Environment not found")
    runs = (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.environment_id == environment_id)
        .order_by(models.AnalysisRun.created_at.desc())
        .all()
    )
    return [analysis_run_to_dict(run) for run in runs]


@router.post("/environments/{environment_id}/analysis-runs", response_model=schemas.AnalysisRunRead)
def run_analysis_route(environment_id: int, payload: schemas.AnalysisRunCreate, db: Session = Depends(get_db)):
    try:
        run = run_analysis(db, environment_id, payload.max_paths)
    except (LookupError, ValueError) as exc:
        _raise_http(exc)
    return analysis_run_to_dict(run)


@router.get("/analysis-runs/{run_id}", response_model=schemas.AnalysisRunRead)
def get_analysis_run(run_id: int, db: Session = Depends(get_db)):
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return analysis_run_to_dict(run)


@router.get("/analysis-runs/{run_id}/remediation-plans")
def get_analysis_plans(run_id: int, db: Session = Depends(get_db)):
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    payload = analysis_run_to_dict(run)
    return {"analysis_run_id": run_id, "plans": payload["remediation_plans"]}


@router.get("/analysis-runs/{run_id}/executive-summary")
def get_executive_summary(run_id: int, db: Session = Depends(get_db)):
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    payload = analysis_run_to_dict(run)
    return {
        "analysis_run_id": run_id,
        "executive_summary": payload["summary"].get("executive_summary", {}),
        "path_details": payload["summary"].get("path_details", []),
        "plans": payload["remediation_plans"],
    }


@router.get("/tenants/{tenant_id}/dashboard", response_model=schemas.DashboardRead)
def tenant_dashboard(tenant_id: int, db: Session = Depends(get_db)):
    try:
        return build_dashboard(db, tenant_id)
    except (LookupError, ValueError) as exc:
        _raise_http(exc)
