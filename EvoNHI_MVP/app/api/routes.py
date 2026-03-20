from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import get_db
from app.services.analysis_service import analysis_run_to_dict, build_dashboard, run_analysis
from app.services.onboarding import add_crown_jewel, create_environment, create_tenant, create_workspace

router = APIRouter(prefix="/api/v1", tags=["evonhi-saas"])


@router.post("/tenants", response_model=schemas.TenantRead)
def create_tenant_route(payload: schemas.TenantCreate, db: Session = Depends(get_db)):
    return create_tenant(db, payload)


@router.post("/tenants/{tenant_id}/workspaces", response_model=schemas.WorkspaceRead)
def create_workspace_route(tenant_id: int, payload: schemas.WorkspaceCreate, db: Session = Depends(get_db)):
    return create_workspace(db, tenant_id, payload)


@router.post("/workspaces/{workspace_id}/environments", response_model=schemas.EnvironmentRead)
def create_environment_route(workspace_id: int, payload: schemas.EnvironmentCreate, db: Session = Depends(get_db)):
    return create_environment(db, workspace_id, payload)


@router.post("/environments/{environment_id}/crown-jewels", response_model=schemas.CrownJewelRead)
def add_crown_jewel_route(environment_id: int, payload: schemas.CrownJewelCreate, db: Session = Depends(get_db)):
    return add_crown_jewel(db, environment_id, payload)


@router.post("/environments/{environment_id}/analysis-runs", response_model=schemas.AnalysisRunRead)
def run_analysis_route(environment_id: int, payload: schemas.AnalysisRunCreate, db: Session = Depends(get_db)):
    try:
        run = run_analysis(db, environment_id, payload.max_paths)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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


@router.get("/tenants/{tenant_id}/dashboard", response_model=schemas.DashboardRead)
def tenant_dashboard(tenant_id: int, db: Session = Depends(get_db)):
    return build_dashboard(db, tenant_id)
