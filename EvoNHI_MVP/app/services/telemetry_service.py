from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app import models, schemas
from app.auth_utils import generate_token, token_prefix
from app.engine.manifest_loader import load_yaml_documents
from app.paths import resolve_manifest_path
from app.services.audit_service import record_audit_event


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def summarize_telemetry_payload(payload: dict[str, Any]) -> dict[str, Any]:
    workloads = payload.get("workloads", []) or []
    permissions = payload.get("permissions", []) or []
    secrets = payload.get("secrets", []) or []
    traffic = sum(float(item.get("traffic_rps", 0) or 0) for item in workloads)
    critical_workloads = sum(1 for item in workloads if str(item.get("criticality", "")).lower() in {"critical", "high"})
    return {
        "workloads": len(workloads),
        "permissions": len(permissions),
        "secrets": len(secrets),
        "aggregate_traffic_rps": round(traffic, 2),
        "critical_workloads": critical_workloads,
    }


def build_runtime_context(snapshot: models.TelemetrySnapshot | None) -> dict[str, Any]:
    if snapshot is None:
        return {"confidence": 0.0, "workloads": {}, "service_accounts": {}, "permissions": {}, "secrets": {}}

    payload = snapshot.payload
    workload_index = {}
    service_account_index = {}
    permission_index = {}
    secret_index = {}

    for item in payload.get("workloads", []) or []:
        key = (item.get("namespace", "default"), item.get("name"))
        workload_index[key] = item
    for item in payload.get("service_accounts", []) or []:
        key = (item.get("namespace", "default"), item.get("name"))
        service_account_index[key] = item
    for item in payload.get("permissions", []) or []:
        key = (
            item.get("namespace", "default"),
            item.get("service_account"),
            item.get("resource"),
            item.get("verb"),
        )
        permission_index[key] = item
    for item in payload.get("secrets", []) or []:
        key = (item.get("namespace", "default"), item.get("name"))
        secret_index[key] = item

    return {
        "confidence": 0.85,
        "snapshot_id": snapshot.id,
        "summary": snapshot.summary,
        "workloads": workload_index,
        "service_accounts": service_account_index,
        "permissions": permission_index,
        "secrets": secret_index,
    }


def create_connector(
    db: Session,
    tenant_id: int,
    environment: models.Environment,
    payload: schemas.ClusterConnectorCreate,
    *,
    user_id: int,
    request_meta: dict[str, str | None] | None = None,
) -> tuple[models.ClusterConnector, str]:
    raw_token, token_hash = generate_token()
    connector = models.ClusterConnector(
        tenant_id=tenant_id,
        environment_id=environment.id,
        name=payload.name,
        kind=payload.kind,
        status="active",
        scopes_json=json.dumps(payload.scopes),
        config_json=json.dumps(payload.config),
        token_prefix=token_prefix(raw_token),
        token_hash=token_hash,
    )
    db.add(connector)
    db.flush()
    record_audit_event(
        db,
        action="connector.create",
        resource_type="cluster_connector",
        resource_id=str(connector.id),
        tenant_id=tenant_id,
        user_id=user_id,
        details={"environment_id": environment.id, "kind": connector.kind},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(connector)
    return connector, raw_token


def store_telemetry_snapshot(
    db: Session,
    *,
    tenant_id: int,
    environment: models.Environment,
    payload: schemas.TelemetrySnapshotCreate,
    connector: models.ClusterConnector | None = None,
    request_meta: dict[str, str | None] | None = None,
    user_id: int | None = None,
    actor_type: str = "user",
) -> models.TelemetrySnapshot:
    summary = payload.summary or summarize_telemetry_payload(payload.payload)
    snapshot = models.TelemetrySnapshot(
        tenant_id=tenant_id,
        environment_id=environment.id,
        connector_id=connector.id if connector else None,
        source_kind=payload.source_kind,
        payload_json=json.dumps(payload.payload),
        summary_json=json.dumps(summary),
        collected_at=payload.collected_at or utc_now(),
    )
    db.add(snapshot)
    db.flush()

    runtime_profile = environment.runtime_profile
    runtime_profile["last_runtime_sync"] = snapshot.collected_at.isoformat()
    runtime_profile["last_telemetry_snapshot_id"] = snapshot.id
    environment.runtime_profile_json = json.dumps(runtime_profile)
    if connector:
        connector.last_seen_at = utc_now()
        connector.last_error = None
        db.add(connector)
    db.add(environment)

    record_audit_event(
        db,
        action="telemetry.ingest",
        resource_type="telemetry_snapshot",
        resource_id=str(snapshot.id),
        tenant_id=tenant_id,
        user_id=user_id,
        actor_type=actor_type,
        details={"environment_id": environment.id, "connector_id": connector.id if connector else None},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(snapshot)
    return snapshot


def latest_telemetry_snapshot(db: Session, environment_id: int) -> models.TelemetrySnapshot | None:
    return (
        db.query(models.TelemetrySnapshot)
        .filter(models.TelemetrySnapshot.environment_id == environment_id)
        .order_by(models.TelemetrySnapshot.collected_at.desc(), models.TelemetrySnapshot.created_at.desc())
        .first()
    )


def create_environment_snapshot(
    db: Session,
    environment: models.Environment,
    *,
    request_meta: dict[str, str | None] | None = None,
    user_id: int | None = None,
) -> models.EnvironmentSnapshot:
    manifest_dir = resolve_manifest_path(environment.manifests_path)
    bundle = _manifest_bundle(manifest_dir)
    serialized = json.dumps(bundle, sort_keys=True)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    telemetry = latest_telemetry_snapshot(db, environment.id)
    snapshot = models.EnvironmentSnapshot(
        tenant_id=environment.tenant_id,
        environment_id=environment.id,
        manifests_digest=digest,
        manifest_bundle_json=serialized,
        manifest_source_json=json.dumps(
            {
                "path": environment.manifests_path,
                "file_count": len({doc.get("_evonhi_source") for doc in bundle}),
            }
        ),
        telemetry_snapshot_id=telemetry.id if telemetry else None,
        summary_json=json.dumps(
            {
                "objects": len(bundle),
                "path": environment.manifests_path,
                "telemetry_snapshot_id": telemetry.id if telemetry else None,
            }
        ),
    )
    db.add(snapshot)
    db.flush()
    runtime_profile = environment.runtime_profile
    runtime_profile["last_snapshot_id"] = snapshot.id
    environment.runtime_profile_json = json.dumps(runtime_profile)
    db.add(environment)
    record_audit_event(
        db,
        action="snapshot.create",
        resource_type="environment_snapshot",
        resource_id=str(snapshot.id),
        tenant_id=environment.tenant_id,
        user_id=user_id,
        details={"environment_id": environment.id, "digest": digest},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(snapshot)
    return snapshot


def _manifest_bundle(manifest_dir: Path) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for file_path in sorted(manifest_dir.rglob("*.y*ml")):
        for doc in load_yaml_documents(file_path):
            normalized = dict(doc)
            normalized["_evonhi_source"] = file_path.relative_to(manifest_dir).as_posix()
            documents.append(normalized)
    return documents
