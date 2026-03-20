import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db import Base, SessionLocal, engine
from app.models import CrownJewel, Environment, Tenant, Workspace
from app.schemas import CrownJewelCreate, EnvironmentCreate, TenantCreate, WorkspaceCreate
from app.services.analysis_service import run_analysis
from app.services.onboarding import add_crown_jewel, create_environment, create_tenant, create_workspace

Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    tenant = db.query(Tenant).filter(Tenant.slug == "acme-fincloud").first()
    if tenant is None:
        tenant = create_tenant(db, TenantCreate(name="Acme Financial Cloud", slug="acme-fincloud", plan_tier="pro"))

    workspace = db.query(Workspace).filter(Workspace.tenant_id == tenant.id, Workspace.name == "Production Security").first()
    if workspace is None:
        workspace = create_workspace(
            db,
            tenant.id,
            WorkspaceCreate(name="Production Security", description="Primary customer environment"),
        )

    environment = db.query(Environment).filter(Environment.workspace_id == workspace.id, Environment.name == "k8s-prod-demo").first()
    if environment is None:
        environment = create_environment(
            db,
            workspace.id,
            EnvironmentCreate(
                name="k8s-prod-demo",
                manifests_path="data/demo/manifests",
                entry_workloads=["public-gateway"],
                budget_limit=8,
            ),
        )

    jewel = (
        db.query(CrownJewel)
        .filter(CrownJewel.environment_id == environment.id, CrownJewel.kind == "Secret", CrownJewel.name == "payments-db-secret")
        .first()
    )
    if jewel is None:
        add_crown_jewel(
            db,
            environment.id,
            CrownJewelCreate(
                kind="Secret",
                name="payments-db-secret",
                namespace="payments",
                criticality=10,
                rationale="Database credential for sensitive payment data",
            ),
        )

    run = run_analysis(db, environment.id, max_paths=50)
    print(f"Seeded tenant {tenant.slug}; analysis run id: {run.id}")
    print(f"Executive dashboard: /dashboard/runs/{run.id}")
finally:
    db.close()
