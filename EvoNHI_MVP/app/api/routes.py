from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth_utils import utc_now
from app.db import get_db
from app.observability import metrics_snapshot
from app.security import (
    AuthContext,
    get_current_user,
    require_connector_token,
    require_platform_admin,
    request_meta,
)
from app.services.access_control import (
    ensure_tenant_access,
    get_analysis_run_for_user,
    get_connector_for_user,
    get_environment_for_user,
    get_remediation_plan_for_user,
    get_workspace_for_user,
)
from app.services.analysis_service import (
    analysis_run_to_dict,
    build_dashboard,
    enqueue_analysis_run,
    process_analysis_run,
    run_analysis,
)
from app.services.audit_service import record_audit_event
from app.services.auth_service import authenticate_user, create_tenant_for_user, register_bootstrap_user
from app.services.onboarding import add_crown_jewel, create_environment, create_workspace, update_tenant_settings
from app.services.telemetry_service import create_connector, latest_telemetry_snapshot, store_telemetry_snapshot

router = APIRouter(prefix="/api/v1", tags=["evonhi-enterprise"])


def _as_token_read(payload: dict) -> schemas.AccessTokenRead:
    return schemas.AccessTokenRead(
        access_token=payload["access_token"],
        expires_at=payload["expires_at"],
        user=schemas.UserRead.model_validate(payload["user"]),
        memberships=[schemas.MembershipRead.model_validate(item) for item in payload["memberships"]],
    )


@router.post("/auth/bootstrap", response_model=schemas.AccessTokenRead)
def bootstrap_register_route(payload: schemas.BootstrapRegister, request: Request, db: Session = Depends(get_db)):
    try:
        result = register_bootstrap_user(db, payload, request_meta=request_meta(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _as_token_read(result)


@router.post("/auth/login", response_model=schemas.AccessTokenRead)
def login_route(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    try:
        result = authenticate_user(db, payload, request_meta=request_meta(request))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return _as_token_read(result)


@router.get("/me")
def current_user_route(current_user: AuthContext = Depends(get_current_user)):
    return {
        "user": schemas.UserRead.model_validate(current_user.user),
        "memberships": [schemas.MembershipRead.model_validate(item) for item in current_user.memberships],
    }


@router.get("/tenants", response_model=list[schemas.TenantRead])
def list_tenants(current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.user.is_platform_admin:
        tenants = db.query(models.Tenant).order_by(models.Tenant.created_at.desc()).all()
    else:
        tenant_ids = [membership.tenant_id for membership in current_user.memberships if membership.status == "active"]
        tenants = db.query(models.Tenant).filter(models.Tenant.id.in_(tenant_ids)).order_by(models.Tenant.created_at.desc()).all() if tenant_ids else []
    return tenants


@router.post("/tenants", response_model=schemas.TenantRead)
def create_tenant_route(
    payload: schemas.TenantCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return create_tenant_for_user(db, current_user.user, payload, request_meta=request_meta(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.patch("/tenants/{tenant_id}/settings", response_model=schemas.TenantRead)
def update_tenant_settings_route(
    tenant_id: int,
    payload: schemas.TenantSettingsUpdate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_tenant_access(current_user, tenant_id, minimum_role="owner")
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return update_tenant_settings(db, tenant, payload, user_id=current_user.user.id, request_meta=request_meta(request))


@router.get("/tenants/{tenant_id}/workspaces", response_model=list[schemas.WorkspaceRead])
def list_workspaces(tenant_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    ensure_tenant_access(current_user, tenant_id, minimum_role="viewer")
    return db.query(models.Workspace).filter(models.Workspace.tenant_id == tenant_id).order_by(models.Workspace.created_at.desc()).all()


@router.post("/tenants/{tenant_id}/workspaces", response_model=schemas.WorkspaceRead)
def create_workspace_route(
    tenant_id: int,
    payload: schemas.WorkspaceCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_tenant_access(current_user, tenant_id, minimum_role="editor")
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return create_workspace(db, tenant, payload, user_id=current_user.user.id, request_meta=request_meta(request))


@router.get("/tenants/{tenant_id}/audit-events", response_model=list[schemas.AuditEventRead])
def list_audit_events(tenant_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    ensure_tenant_access(current_user, tenant_id, minimum_role="admin")
    return (
        db.query(models.AuditEvent)
        .filter(models.AuditEvent.tenant_id == tenant_id)
        .order_by(models.AuditEvent.created_at.desc())
        .limit(200)
        .all()
    )


@router.get("/workspaces/{workspace_id}/environments", response_model=list[schemas.EnvironmentRead])
def list_environments(workspace_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    workspace = get_workspace_for_user(db, workspace_id, current_user, minimum_role="viewer")
    return (
        db.query(models.Environment)
        .filter(models.Environment.workspace_id == workspace.id)
        .order_by(models.Environment.created_at.desc())
        .all()
    )


@router.post("/workspaces/{workspace_id}/environments", response_model=schemas.EnvironmentRead)
def create_environment_route(
    workspace_id: int,
    payload: schemas.EnvironmentCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    workspace = get_workspace_for_user(db, workspace_id, current_user, minimum_role="editor")
    return create_environment(db, workspace, payload, user_id=current_user.user.id, request_meta=request_meta(request))


@router.post("/environments/{environment_id}/crown-jewels", response_model=schemas.CrownJewelRead)
def add_crown_jewel_route(
    environment_id: int,
    payload: schemas.CrownJewelCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="editor")
    try:
        return add_crown_jewel(db, environment, payload, user_id=current_user.user.id, request_meta=request_meta(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/environments/{environment_id}/connectors", response_model=list[schemas.ClusterConnectorRead])
def list_connectors(environment_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="viewer")
    return (
        db.query(models.ClusterConnector)
        .filter(models.ClusterConnector.environment_id == environment.id)
        .order_by(models.ClusterConnector.created_at.desc())
        .all()
    )


@router.post("/environments/{environment_id}/connectors", response_model=schemas.ClusterConnectorSecretRead)
def create_connector_route(
    environment_id: int,
    payload: schemas.ClusterConnectorCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="admin")
    connector, raw_token = create_connector(
        db,
        environment.tenant_id,
        environment,
        payload,
        user_id=current_user.user.id,
        request_meta=request_meta(request),
    )
    return {"connector_id": connector.id, "connector_token": raw_token}


@router.get("/environments/{environment_id}/telemetry-snapshots", response_model=list[schemas.TelemetrySnapshotRead])
def list_telemetry_snapshots(environment_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="viewer")
    return (
        db.query(models.TelemetrySnapshot)
        .filter(models.TelemetrySnapshot.environment_id == environment.id)
        .order_by(models.TelemetrySnapshot.collected_at.desc())
        .limit(50)
        .all()
    )


@router.post("/environments/{environment_id}/telemetry-snapshots", response_model=schemas.TelemetrySnapshotRead)
def create_telemetry_snapshot_route(
    environment_id: int,
    payload: schemas.TelemetrySnapshotCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="editor")
    return store_telemetry_snapshot(
        db,
        tenant_id=environment.tenant_id,
        environment=environment,
        payload=payload,
        user_id=current_user.user.id,
        actor_type="user",
        request_meta=request_meta(request),
    )


@router.post("/connector-ingest/telemetry", response_model=schemas.TelemetrySnapshotRead)
def connector_ingest_telemetry_route(
    payload: schemas.TelemetrySnapshotCreate,
    request: Request,
    connector: models.ClusterConnector = Depends(require_connector_token),
    db: Session = Depends(get_db),
):
    environment = db.get(models.Environment, connector.environment_id)
    if not environment:
        raise HTTPException(status_code=404, detail="Connector environment not found")
    return store_telemetry_snapshot(
        db,
        tenant_id=connector.tenant_id,
        environment=environment,
        payload=payload,
        connector=connector,
        actor_type="connector",
        request_meta=request_meta(request),
    )


@router.get("/environments/{environment_id}/analysis-runs", response_model=list[schemas.AnalysisRunRead])
def list_analysis_runs(environment_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="viewer")
    runs = (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.environment_id == environment.id)
        .order_by(models.AnalysisRun.created_at.desc())
        .all()
    )
    return [analysis_run_to_dict(run) for run in runs]


@router.post("/environments/{environment_id}/analysis-runs", response_model=schemas.AnalysisRunRead)
def enqueue_analysis_run_route(
    environment_id: int,
    payload: schemas.AnalysisRunCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="analyst")
    try:
        run = enqueue_analysis_run(
            db,
            environment,
            requested_by_user_id=current_user.user.id,
            max_paths=payload.max_paths,
            request_meta=request_meta(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return analysis_run_to_dict(run)


@router.post("/analysis-runs/{run_id}/execute-now", response_model=schemas.AnalysisRunRead)
def execute_analysis_now_route(
    run_id: int,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    run = get_analysis_run_for_user(db, run_id, current_user, minimum_role="analyst")
    if run.status not in {"queued", "failed"}:
        raise HTTPException(status_code=409, detail="Analysis run is not eligible for immediate execution")
    processed = process_analysis_run(db, run.id, worker_id="api-manual", request_meta=request_meta(request))
    return analysis_run_to_dict(processed)


@router.post("/environments/{environment_id}/analysis-runs/execute-inline", response_model=schemas.AnalysisRunRead)
def run_analysis_inline_route(
    environment_id: int,
    payload: schemas.AnalysisRunCreate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    environment = get_environment_for_user(db, environment_id, current_user, minimum_role="analyst")
    processed = run_analysis(
        db,
        environment.id,
        payload.max_paths,
        requested_by_user_id=current_user.user.id,
        request_meta=request_meta(request),
    )
    return analysis_run_to_dict(processed)


@router.get("/analysis-runs/{run_id}", response_model=schemas.AnalysisRunRead)
def get_analysis_run_route(run_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    run = get_analysis_run_for_user(db, run_id, current_user, minimum_role="viewer")
    return analysis_run_to_dict(run)


@router.get("/analysis-runs/{run_id}/remediation-plans", response_model=list[schemas.RemediationPlanRead])
def get_analysis_plans(run_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    run = get_analysis_run_for_user(db, run_id, current_user, minimum_role="viewer")
    payload = analysis_run_to_dict(run)
    return payload["remediation_plans"]


@router.patch("/remediation-plans/{plan_id}", response_model=schemas.RemediationPlanRead)
def update_remediation_plan_route(
    plan_id: int,
    payload: schemas.RemediationPlanUpdate,
    request: Request,
    current_user: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plan = get_remediation_plan_for_user(db, plan_id, current_user, minimum_role="editor")
    if payload.status is not None:
        plan.status = payload.status
    if payload.owner_user_id is not None:
        plan.owner_user_id = payload.owner_user_id
    if payload.ticket_url is not None:
        plan.ticket_url = payload.ticket_url
    if payload.notes is not None:
        plan.notes = payload.notes
    if payload.status == "approved":
        plan.approved_by_user_id = current_user.user.id
        plan.approved_at = plan.approved_at or utc_now()
    if payload.status == "applied":
        plan.applied_at = plan.applied_at or utc_now()
    db.add(plan)
    record_audit_event(
        db,
        action="remediation_plan.update",
        resource_type="remediation_plan",
        resource_id=str(plan.id),
        tenant_id=plan.tenant_id,
        user_id=current_user.user.id,
        details={"status": plan.status, "owner_user_id": plan.owner_user_id, "ticket_url": plan.ticket_url},
        **request_meta(request),
    )
    db.commit()
    db.refresh(plan)
    return schemas.RemediationPlanRead.model_validate(
        {
            "id": plan.id,
            "tenant_id": plan.tenant_id,
            "analysis_run_id": plan.analysis_run_id,
            "title": plan.title,
            "coverage_ratio": plan.coverage_ratio,
            "reduced_paths": plan.reduced_paths,
            "remaining_paths": plan.remaining_paths,
            "cost": plan.cost,
            "operational_impact": plan.operational_impact,
            "selected_actions": plan.selected_actions,
            "reasoning": plan.reasoning,
            "status": plan.status,
            "owner_user_id": plan.owner_user_id,
            "approved_by_user_id": plan.approved_by_user_id,
            "ticket_url": plan.ticket_url,
            "notes": plan.notes,
            "approved_at": plan.approved_at,
            "applied_at": plan.applied_at,
            "expires_at": plan.expires_at,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
        }
    )


@router.get("/analysis-runs/{run_id}/executive-summary")
def get_executive_summary(run_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    run = get_analysis_run_for_user(db, run_id, current_user, minimum_role="viewer")
    payload = analysis_run_to_dict(run)
    return {
        "analysis_run_id": run_id,
        "executive_summary": payload["summary"].get("executive_summary", {}),
        "path_details": payload["summary"].get("path_details", []),
        "plans": payload["remediation_plans"],
        "latest_telemetry_snapshot": latest_telemetry_snapshot(db, run.environment_id).id if latest_telemetry_snapshot(db, run.environment_id) else None,
    }


@router.get("/tenants/{tenant_id}/dashboard", response_model=schemas.DashboardRead)
def tenant_dashboard(tenant_id: int, current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    ensure_tenant_access(current_user, tenant_id, minimum_role="viewer")
    return build_dashboard(db, tenant_id)


@router.get("/platform/metrics", response_model=schemas.MetricsRead)
def platform_metrics(_current_user: AuthContext = Depends(require_platform_admin)):
    return metrics_snapshot()
