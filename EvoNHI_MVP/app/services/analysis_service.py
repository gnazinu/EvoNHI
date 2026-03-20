from __future__ import annotations

import json
from datetime import timedelta
from statistics import mean

from sqlalchemy.orm import Session

from app import models
from app.auth_utils import utc_now
from app.config import settings
from app.domain.analysis_models import CrownJewelSpec, ScenarioConfig
from app.engine.graph_builder import build_attack_graph
from app.engine.manifest_loader import load_cluster_model_from_documents
from app.engine.optimizer import optimize_actions
from app.engine.path_analysis import find_attack_paths, path_summary
from app.engine.remediation import propose_remediation_actions
from app.observability import record_analysis_run
from app.services.audit_service import record_audit_event
from app.services.reporting import build_dashboard_payload, build_executive_summary, serialize_action, serialize_path
from app.services.telemetry_service import build_runtime_context, create_environment_snapshot, latest_telemetry_snapshot


def _normalized_max_paths(max_paths: int | None) -> int:
    value = max_paths or settings.default_max_paths
    return max(1, min(value, settings.max_paths_limit))


def _daily_run_limit_exceeded(db: Session, tenant: models.Tenant) -> bool:
    limit = int(tenant.settings.get("max_daily_analysis_runs", 0) or 0)
    if limit <= 0:
        return False
    since = utc_now() - timedelta(days=1)
    count = (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.tenant_id == tenant.id)
        .filter(models.AnalysisRun.created_at >= since)
        .count()
    )
    return count >= limit


def _plan_title(index: int, reduced_paths: int, coverage_ratio: float) -> str:
    coverage_pct = round(coverage_ratio * 100)
    if reduced_paths <= 0:
        return f"Stabilization plan #{index}"
    if coverage_pct >= 75:
        return f"High-impact containment plan #{index}"
    if coverage_pct >= 40:
        return f"Balanced reduction plan #{index}"
    return f"Low-disruption hardening plan #{index}"


def _plan_reasoning(plan, selected_actions: list[dict], budget_limit: int, telemetry_confidence: float) -> str:
    action_titles = ", ".join(action["title"] for action in selected_actions[:2])
    if len(selected_actions) > 2:
        action_titles += f" and {len(selected_actions) - 2} more changes"
    confidence_pct = round(telemetry_confidence * 100)
    return (
        f"This plan removes {plan.reduced_paths} reachable paths while staying within the "
        f"budget score {budget_limit}. Telemetry confidence for operational impact is {confidence_pct}%. "
        f"Priority changes include {action_titles or 'the least disruptive controls'}."
    )


def _enforce_graph_limits(graph) -> None:
    if graph.number_of_nodes() > settings.max_graph_nodes:
        raise ValueError(f"Graph node limit exceeded ({graph.number_of_nodes()} > {settings.max_graph_nodes})")
    if graph.number_of_edges() > settings.max_graph_edges:
        raise ValueError(f"Graph edge limit exceeded ({graph.number_of_edges()} > {settings.max_graph_edges})")


def enqueue_analysis_run(
    db: Session,
    environment: models.Environment,
    *,
    requested_by_user_id: int | None,
    max_paths: int,
    request_meta: dict[str, str | None] | None = None,
) -> models.AnalysisRun:
    if not environment.crown_jewels:
        raise ValueError("At least one crown jewel is required before running analysis")
    if _daily_run_limit_exceeded(db, environment.tenant):
        raise ValueError("Tenant daily analysis run quota reached")

    snapshot = create_environment_snapshot(
        db,
        environment,
        user_id=requested_by_user_id,
        request_meta=request_meta,
    )
    telemetry = latest_telemetry_snapshot(db, environment.id)
    run = models.AnalysisRun(
        tenant_id=environment.tenant_id,
        environment_id=environment.id,
        requested_by_user_id=requested_by_user_id,
        snapshot_id=snapshot.id,
        telemetry_snapshot_id=telemetry.id if telemetry else None,
        status="queued",
        max_paths_requested=_normalized_max_paths(max_paths),
        progress=0,
    )
    db.add(run)
    db.flush()
    record_audit_event(
        db,
        action="analysis.enqueue",
        resource_type="analysis_run",
        resource_id=str(run.id),
        tenant_id=environment.tenant_id,
        user_id=requested_by_user_id,
        details={"environment_id": environment.id, "snapshot_id": snapshot.id},
        **(request_meta or {}),
    )
    db.commit()
    db.refresh(run)
    return run


def _mark_run_running(db: Session, run: models.AnalysisRun, worker_id: str) -> None:
    if run.status != "running":
        run.status = "running"
        run.started_at = utc_now()
        run.worker_id = worker_id
        run.progress = max(run.progress, 5)
        run.attempts += 1
        db.add(run)
        db.commit()
        db.refresh(run)


def _serialize_plans(environment: models.Environment, plans, action_index: dict[str, object]) -> list[dict]:
    serialized_plans = []
    for idx, plan in enumerate(plans, start=1):
        selected_actions = [serialize_action(action_index[action_id]) for action_id in plan.selected_actions if action_id in action_index]
        confidences = [action.get("telemetry_confidence") for action in selected_actions if action.get("telemetry_confidence") is not None]
        telemetry_confidence = mean(confidences) if confidences else 0.0
        serialized_plans.append(
            {
                "title": _plan_title(idx, plan.reduced_paths, plan.coverage_ratio),
                "coverage_ratio": plan.coverage_ratio,
                "reduced_paths": plan.reduced_paths,
                "remaining_paths": plan.remaining_paths,
                "cost": plan.cost,
                "operational_impact": round(plan.operational_impact, 2),
                "selected_actions": selected_actions,
                "reasoning": _plan_reasoning(plan, selected_actions, environment.budget_limit, telemetry_confidence),
                "telemetry_confidence": telemetry_confidence,
            }
        )
    return serialized_plans


def _compute_analysis_result(
    environment: models.Environment,
    snapshot: models.EnvironmentSnapshot,
    telemetry_snapshot: models.TelemetrySnapshot | None,
    *,
    max_paths: int,
) -> tuple[dict, list[dict]]:
    jewels = [
        CrownJewelSpec(
            kind=jewel.kind,
            name=jewel.name,
            namespace=jewel.namespace,
            criticality=jewel.criticality,
            rationale=jewel.rationale,
        )
        for jewel in environment.crown_jewels
    ]
    scenario = ScenarioConfig(
        crown_jewels=jewels,
        entry_workloads=environment.entry_workloads,
        max_paths=max_paths,
        metadata={"environment": environment.name, "mode": "enterprise-saas"},
    )

    cluster_model = load_cluster_model_from_documents(snapshot.manifest_bundle)
    graph = build_attack_graph(cluster_model, scenario)
    _enforce_graph_limits(graph)

    runtime_context = build_runtime_context(telemetry_snapshot)
    baseline_paths = find_attack_paths(graph, max_paths=max_paths)
    actions = propose_remediation_actions(graph, telemetry_context=runtime_context)
    best_plans = optimize_actions(graph, actions, max_paths=max_paths, budget=environment.budget_limit)
    action_index = {action.action_id: action for action in actions}
    path_cards = [serialize_path(graph, path) for path in baseline_paths[:8]]
    serialized_plans = _serialize_plans(environment, best_plans, action_index)

    summary = {
        "environment": environment.name,
        "platform": environment.platform,
        "manifests_path": environment.manifests_path,
        "snapshot_id": snapshot.id,
        "snapshot_digest": snapshot.manifests_digest,
        "telemetry_snapshot_id": telemetry_snapshot.id if telemetry_snapshot else None,
        "telemetry_summary": telemetry_snapshot.summary if telemetry_snapshot else {"confidence": 0.0},
        "workloads": len(cluster_model.workloads),
        "service_accounts": len(cluster_model.service_accounts),
        "secrets": len(cluster_model.secrets),
        "permissions": sum(1 for _, attrs in graph.nodes(data=True) if attrs.get("kind") == "permission"),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "baseline_paths": len(baseline_paths),
        "sample_paths": path_summary(baseline_paths[:5]),
        "path_details": path_cards,
        "candidate_actions": len(actions),
        "crown_jewels": [f"{j.kind}:{j.namespace}:{j.name}" for j in jewels],
        "analysis_scope": {
            "modeled_vectors": [
                "public workload entry points",
                "service account token inheritance",
                "RBAC secret reads",
                "mounted secret exposure",
                "workload-mutation pivots",
            ],
            "max_paths": max_paths,
            "max_depth": settings.max_path_depth,
        },
        "runtime_context": {
            "telemetry_confidence": runtime_context.get("confidence", 0.0),
            "snapshot_available": telemetry_snapshot is not None,
        },
    }
    summary["executive_summary"] = build_executive_summary(
        environment_name=environment.name,
        crown_jewels=summary["crown_jewels"],
        baseline_paths=summary["baseline_paths"],
        path_cards=path_cards,
        remediation_plans=serialized_plans,
        actions_count=summary["candidate_actions"],
        workloads=summary["workloads"],
        service_accounts=summary["service_accounts"],
    )
    return summary, serialized_plans


def process_analysis_run(
    db: Session,
    run_id: int,
    *,
    worker_id: str | None = None,
    request_meta: dict[str, str | None] | None = None,
) -> models.AnalysisRun:
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise LookupError("Analysis run not found")

    worker_id = worker_id or settings.analysis_worker_id
    _mark_run_running(db, run, worker_id)

    try:
        environment = db.get(models.Environment, run.environment_id)
        snapshot = db.get(models.EnvironmentSnapshot, run.snapshot_id)
        telemetry_snapshot = db.get(models.TelemetrySnapshot, run.telemetry_snapshot_id) if run.telemetry_snapshot_id else None
        if not environment or not snapshot:
            raise ValueError("Analysis input snapshot is missing")

        summary, serialized_plans = _compute_analysis_result(
            environment,
            snapshot,
            telemetry_snapshot,
            max_paths=run.max_paths_requested,
        )

        for existing in list(run.remediation_plans):
            db.delete(existing)
        db.flush()

        for plan in serialized_plans:
            record = models.RemediationPlan(
                tenant_id=run.tenant_id,
                analysis_run_id=run.id,
                title=plan["title"],
                coverage_ratio=plan["coverage_ratio"],
                reduced_paths=plan["reduced_paths"],
                remaining_paths=plan["remaining_paths"],
                cost=plan["cost"],
                operational_impact=plan["operational_impact"],
                selected_actions_json=json.dumps(plan["selected_actions"]),
                reasoning=plan["reasoning"],
                status="proposed",
            )
            db.add(record)

        run.status = "completed"
        run.baseline_paths = summary["baseline_paths"]
        run.summary_json = json.dumps(summary)
        run.error_message = None
        run.progress = 100
        run.completed_at = utc_now()
        db.add(run)
        record_audit_event(
            db,
            action="analysis.complete",
            resource_type="analysis_run",
            resource_id=str(run.id),
            tenant_id=run.tenant_id,
            user_id=run.requested_by_user_id,
            details={"baseline_paths": summary["baseline_paths"]},
            **(request_meta or {}),
        )
        db.commit()
        db.refresh(run)
        record_analysis_run(True)
        return run
    except Exception as exc:
        run.status = "failed"
        run.error_message = str(exc)
        run.progress = 100
        run.completed_at = utc_now()
        db.add(run)
        record_audit_event(
            db,
            action="analysis.failed",
            resource_type="analysis_run",
            resource_id=str(run.id),
            tenant_id=run.tenant_id,
            user_id=run.requested_by_user_id,
            status="failure",
            details={"error": str(exc)},
            **(request_meta or {}),
        )
        db.commit()
        db.refresh(run)
        record_analysis_run(False)
        raise


def claim_next_analysis_run(db: Session, *, worker_id: str) -> models.AnalysisRun | None:
    run = (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.status == "queued")
        .order_by(models.AnalysisRun.created_at.asc())
        .first()
    )
    if not run:
        return None
    run.status = "running"
    run.worker_id = worker_id
    run.started_at = utc_now()
    run.progress = 1
    run.attempts += 1
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def run_analysis(
    db: Session,
    environment_id: int,
    max_paths: int,
    *,
    requested_by_user_id: int | None = None,
    request_meta: dict[str, str | None] | None = None,
) -> models.AnalysisRun:
    environment = db.get(models.Environment, environment_id)
    if not environment:
        raise LookupError("Environment not found")
    run = enqueue_analysis_run(
        db,
        environment,
        requested_by_user_id=requested_by_user_id,
        max_paths=max_paths,
        request_meta=request_meta,
    )
    return process_analysis_run(db, run.id, worker_id="inline-sync", request_meta=request_meta)


def analysis_run_to_dict(run: models.AnalysisRun) -> dict:
    plans = sorted(
        run.remediation_plans,
        key=lambda plan: (plan.remaining_paths, plan.cost, plan.operational_impact, -plan.coverage_ratio, plan.id or 0),
    )
    return {
        "id": run.id,
        "tenant_id": run.tenant_id,
        "environment_id": run.environment_id,
        "requested_by_user_id": run.requested_by_user_id,
        "snapshot_id": run.snapshot_id,
        "telemetry_snapshot_id": run.telemetry_snapshot_id,
        "status": run.status,
        "baseline_paths": run.baseline_paths,
        "progress": run.progress,
        "attempts": run.attempts,
        "max_paths_requested": run.max_paths_requested,
        "worker_id": run.worker_id,
        "queue_name": run.queue_name,
        "error_message": run.error_message,
        "summary": run.summary,
        "remediation_plans": [
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
            for plan in plans
        ],
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "created_at": run.created_at,
        "updated_at": run.updated_at,
    }


def build_dashboard(db: Session, tenant_id: int) -> dict:
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise LookupError("Tenant not found")

    workspaces = db.query(models.Workspace).filter(models.Workspace.tenant_id == tenant_id).all()
    environments = db.query(models.Environment).filter(models.Environment.tenant_id == tenant_id).all()
    runs = (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.tenant_id == tenant_id)
        .order_by(models.AnalysisRun.created_at.desc())
        .all()
    )
    connectors = db.query(models.ClusterConnector).filter(models.ClusterConnector.tenant_id == tenant_id).all()
    latest_summary = runs[0].summary if runs else {}
    latest_runs = [analysis_run_to_dict(run) for run in runs[:5]]
    return {
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "workspaces": len(workspaces),
        "environments": len(environments),
        "connectors": len(connectors),
        "analysis_runs": len(runs),
        "latest_risk_summary": latest_summary,
        "latest_runs": [build_dashboard_payload(run_payload) for run_payload in latest_runs],
        "environment_overview": [
            {
                "environment_id": env.id,
                "name": env.name,
                "platform": env.platform,
                "budget_limit": env.budget_limit,
                "latest_status": next((run.status for run in runs if run.environment_id == env.id), "never-analyzed"),
            }
            for env in environments
        ],
        "telemetry_overview": [
            {
                "connector_id": connector.id,
                "environment_id": connector.environment_id,
                "name": connector.name,
                "status": connector.status,
                "last_seen_at": connector.last_seen_at,
            }
            for connector in connectors
        ],
    }
