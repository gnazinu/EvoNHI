from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.config import settings
from app.schemas import CrownJewelCreate, EnvironmentCreate, TenantCreate, WorkspaceCreate
from app.services.analysis_service import analysis_run_to_dict, run_analysis
from app.services.onboarding import add_crown_jewel, create_environment, create_tenant, create_workspace


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_create_environment_normalizes_manifest_path(db_session, monkeypatch, tmp_path):
    manifests_dir = tmp_path / "bundles" / "demo"
    manifests_dir.mkdir(parents=True)
    (manifests_dir / "00-secret.yaml").write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-secret\n  namespace: default\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "manifest_root", tmp_path.resolve())

    tenant = create_tenant(db_session, TenantCreate(name="Acme", slug="acme"))
    workspace = create_workspace(db_session, tenant.id, WorkspaceCreate(name="Platform"))
    environment = create_environment(
        db_session,
        workspace.id,
        EnvironmentCreate(
            name="Prod",
            manifests_path="bundles/demo",
            entry_workloads=["public-gateway", "public-gateway"],
            budget_limit=8,
        ),
    )

    assert environment.manifests_path == "bundles/demo"
    assert environment.entry_workloads == ["public-gateway"]


def test_run_analysis_persists_executive_summary(db_session, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(settings, "manifest_root", repo_root.resolve())

    tenant = create_tenant(db_session, TenantCreate(name="Acme Financial Cloud", slug="acme-fincloud"))
    workspace = create_workspace(db_session, tenant.id, WorkspaceCreate(name="Production Security"))
    environment = create_environment(
        db_session,
        workspace.id,
        EnvironmentCreate(
            name="k8s-prod-demo",
            manifests_path="data/demo/manifests",
            entry_workloads=["public-gateway"],
            budget_limit=8,
        ),
    )
    add_crown_jewel(
        db_session,
        environment.id,
        CrownJewelCreate(kind="Secret", name="payments-db-secret", namespace="payments"),
    )

    run = run_analysis(db_session, environment.id, max_paths=20)
    payload = analysis_run_to_dict(run)

    assert payload["summary"]["executive_summary"]["risk_level"] in {"guarded", "elevated", "high", "critical"}
    assert payload["summary"]["path_details"]
    assert payload["remediation_plans"][0]["selected_actions"][0]["title"]
