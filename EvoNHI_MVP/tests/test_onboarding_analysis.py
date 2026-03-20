from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models
from app.config import settings
from app.db import Base
from app.schemas import BootstrapRegister, CrownJewelCreate, EnvironmentCreate, TelemetrySnapshotCreate, WorkspaceCreate
from app.services.analysis_service import analysis_run_to_dict, enqueue_analysis_run, process_analysis_run, run_analysis
from app.services.auth_service import register_bootstrap_user
from app.services.onboarding import add_crown_jewel, create_environment, create_workspace
from app.services.telemetry_service import latest_telemetry_snapshot, store_telemetry_snapshot


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _bootstrap_tenant(db_session):
    token_payload = register_bootstrap_user(
        db_session,
        BootstrapRegister(
            email="owner@acme.test",
            full_name="Owner User",
            password="super-secure-pass",
            tenant_name="Acme",
            tenant_slug="acme",
        ),
    )
    tenant = db_session.query(models.Tenant).filter(models.Tenant.slug == "acme").first()
    user = db_session.query(models.User).filter(models.User.email == "owner@acme.test").first()
    assert token_payload["access_token"].startswith("evn_")
    return tenant, user


def test_create_environment_normalizes_manifest_path(db_session, monkeypatch, tmp_path):
    manifests_dir = tmp_path / "bundles" / "demo"
    manifests_dir.mkdir(parents=True)
    (manifests_dir / "00-secret.yaml").write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-secret\n  namespace: default\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "manifest_root", tmp_path.resolve())

    tenant, user = _bootstrap_tenant(db_session)
    workspace = create_workspace(db_session, tenant, WorkspaceCreate(name="Platform"), user_id=user.id)
    environment = create_environment(
        db_session,
        workspace,
        EnvironmentCreate(
            name="Prod",
            manifests_path="bundles/demo",
            entry_workloads=["public-gateway", "public-gateway"],
            budget_limit=8,
        ),
        user_id=user.id,
    )

    assert environment.manifests_path == "bundles/demo"
    assert environment.entry_workloads == ["public-gateway"]
    assert environment.tenant_id == tenant.id


def test_analysis_queue_and_processing_persist_summary_and_telemetry(db_session, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(settings, "manifest_root", repo_root.resolve())

    tenant, user = _bootstrap_tenant(db_session)
    workspace = create_workspace(db_session, tenant, WorkspaceCreate(name="Production Security"), user_id=user.id)
    environment = create_environment(
        db_session,
        workspace,
        EnvironmentCreate(
            name="k8s-prod-demo",
            manifests_path="data/demo/manifests",
            entry_workloads=["public-gateway"],
            budget_limit=8,
        ),
        user_id=user.id,
    )
    add_crown_jewel(
        db_session,
        environment,
        CrownJewelCreate(kind="Secret", name="payments-db-secret", namespace="payments"),
        user_id=user.id,
    )
    telemetry = store_telemetry_snapshot(
        db_session,
        tenant_id=tenant.id,
        environment=environment,
        payload=TelemetrySnapshotCreate(
            source_kind="manual",
            payload={
                "workloads": [
                    {
                        "namespace": "edge",
                        "name": "public-gateway",
                        "traffic_rps": 140,
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
                        "recent_requests": 55,
                    }
                ],
            },
        ),
        user_id=user.id,
        actor_type="user",
    )

    queued = enqueue_analysis_run(db_session, environment, requested_by_user_id=user.id, max_paths=20)
    assert queued.status == "queued"
    assert queued.telemetry_snapshot_id == telemetry.id

    processed = process_analysis_run(db_session, queued.id, worker_id="pytest-worker")
    payload = analysis_run_to_dict(processed)

    assert payload["status"] == "completed"
    assert payload["summary"]["executive_summary"]["risk_level"] in {"guarded", "elevated", "high", "critical"}
    assert payload["summary"]["runtime_context"]["snapshot_available"] is True
    assert payload["summary"]["path_details"]
    assert payload["remediation_plans"][0]["selected_actions"][0]["title"]
    assert latest_telemetry_snapshot(db_session, environment.id).id == telemetry.id


def test_run_analysis_sync_wrapper_still_works(db_session, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(settings, "manifest_root", repo_root.resolve())

    tenant, user = _bootstrap_tenant(db_session)
    workspace = create_workspace(db_session, tenant, WorkspaceCreate(name="Ops"), user_id=user.id)
    environment = create_environment(
        db_session,
        workspace,
        EnvironmentCreate(
            name="sync-demo",
            manifests_path="data/demo/manifests",
            entry_workloads=["public-gateway"],
            budget_limit=8,
        ),
        user_id=user.id,
    )
    add_crown_jewel(
        db_session,
        environment,
        CrownJewelCreate(kind="Secret", name="payments-db-secret", namespace="payments"),
        user_id=user.id,
    )

    run = run_analysis(db_session, environment.id, max_paths=10, requested_by_user_id=user.id)
    assert run.status == "completed"
