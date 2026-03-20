import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import models
from app.db import SessionLocal, init_db
from app.schemas import BootstrapRegister, CrownJewelCreate, EnvironmentCreate, TelemetrySnapshotCreate, WorkspaceCreate
from app.services.analysis_service import run_analysis
from app.services.auth_service import register_bootstrap_user
from app.services.onboarding import add_crown_jewel, create_environment, create_workspace
from app.services.telemetry_service import store_telemetry_snapshot

init_db()

db = SessionLocal()
try:
    tenant = db.query(models.Tenant).filter(models.Tenant.slug == "acme-fincloud").first()
    user = db.query(models.User).filter(models.User.email == "owner@acme.test").first()
    if tenant is None or user is None:
        register_bootstrap_user(
            db,
            BootstrapRegister(
                email="owner@acme.test",
                full_name="Acme Owner",
                password="super-secure-pass",
                tenant_name="Acme Financial Cloud",
                tenant_slug="acme-fincloud",
            ),
        )
        tenant = db.query(models.Tenant).filter(models.Tenant.slug == "acme-fincloud").first()
        user = db.query(models.User).filter(models.User.email == "owner@acme.test").first()

    workspace = db.query(models.Workspace).filter(models.Workspace.tenant_id == tenant.id, models.Workspace.name == "Production Security").first()
    if workspace is None:
        workspace = create_workspace(
            db,
            tenant,
            WorkspaceCreate(name="Production Security", description="Primary customer environment"),
            user_id=user.id,
        )

    environment = db.query(models.Environment).filter(models.Environment.workspace_id == workspace.id, models.Environment.name == "k8s-prod-demo").first()
    if environment is None:
        environment = create_environment(
            db,
            workspace,
            EnvironmentCreate(
                name="k8s-prod-demo",
                manifests_path="data/demo/manifests",
                entry_workloads=["public-gateway"],
                budget_limit=8,
            ),
            user_id=user.id,
        )

    jewel = (
        db.query(models.CrownJewel)
        .filter(models.CrownJewel.environment_id == environment.id, models.CrownJewel.kind == "Secret", models.CrownJewel.name == "payments-db-secret")
        .first()
    )
    if jewel is None:
        add_crown_jewel(
            db,
            environment,
            CrownJewelCreate(
                kind="Secret",
                name="payments-db-secret",
                namespace="payments",
                criticality=10,
                rationale="Database credential for sensitive payment data",
            ),
            user_id=user.id,
        )

    store_telemetry_snapshot(
        db,
        tenant_id=tenant.id,
        environment=environment,
        payload=TelemetrySnapshotCreate(
            source_kind="seed-demo",
            payload={
                "workloads": [
                    {
                        "namespace": "edge",
                        "name": "public-gateway",
                        "traffic_rps": 125,
                        "criticality": "high",
                        "replicas": 2,
                    }
                ],
                "permissions": [
                    {
                        "namespace": "edge",
                        "service_account": "gateway-sa",
                        "resource": "secrets",
                        "verb": "get",
                        "recent_requests": 60,
                    }
                ],
            },
        ),
        user_id=user.id,
    )

    run = run_analysis(db, environment.id, max_paths=50, requested_by_user_id=user.id)
    print(f"Seeded tenant {tenant.slug}; analysis run id: {run.id}")
    print("Login first via /api/v1/auth/login using owner@acme.test / super-secure-pass")
    print(f"Executive dashboard: /dashboard/runs/{run.id}")
finally:
    db.close()
