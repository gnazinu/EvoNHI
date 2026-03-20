from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app import models
from app.config import settings
from app.domain.analysis_models import CrownJewelSpec, ScenarioConfig
from app.engine.graph_builder import build_attack_graph
from app.engine.manifest_loader import load_cluster_model
from app.engine.optimizer import optimize_actions
from app.engine.path_analysis import find_attack_paths, path_summary
from app.engine.remediation import propose_remediation_actions
from app.paths import resolve_manifest_path
from app.services.reporting import build_dashboard_payload, build_executive_summary, serialize_action, serialize_path


def _normalized_max_paths(max_paths: int | None) -> int:
    value = max_paths or settings.default_max_paths
    return max(1, min(value, settings.max_paths_limit))


def _plan_title(index: int, reduced_paths: int, coverage_ratio: float) -> str:
    coverage_pct = round(coverage_ratio * 100)
    if reduced_paths <= 0:
        return f"Stabilization plan #{index}"
    if coverage_pct >= 75:
        return f"High-impact containment plan #{index}"
    if coverage_pct >= 40:
        return f"Balanced reduction plan #{index}"
    return f"Low-disruption hardening plan #{index}"


def _plan_reasoning(plan, selected_actions: list[dict], budget_limit: int) -> str:
    action_titles = ", ".join(action["title"] for action in selected_actions[:2])
    if len(selected_actions) > 2:
        action_titles += f" and {len(selected_actions) - 2} more changes"
    return (
        f"This plan removes {plan.reduced_paths} reachable paths while staying within the "
        f"budget score {budget_limit}. Priority changes include {action_titles or 'the least disruptive controls'}."
    )


def run_analysis(db: Session, environment_id: int, max_paths: int) -> models.AnalysisRun:
    environment = db.get(models.Environment, environment_id)
    if not environment:
        raise LookupError("Environment not found")

    if not environment.crown_jewels:
        raise ValueError("At least one crown jewel is required before running analysis")

    manifest_path = resolve_manifest_path(environment.manifests_path)
    max_paths = _normalized_max_paths(max_paths)

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
        entry_workloads=json.loads(environment.entry_workloads_json or "[]"),
        max_paths=max_paths,
        metadata={"environment": environment.name, "mode": "saas-mvp"},
    )

    cluster_model = load_cluster_model(manifest_path)
    graph = build_attack_graph(cluster_model, scenario)
    baseline_paths = find_attack_paths(graph, max_paths=max_paths)
    actions = propose_remediation_actions(graph)
    best_plans = optimize_actions(graph, actions, max_paths=max_paths, budget=environment.budget_limit)
    action_index = {action.action_id: action for action in actions}

    serialized_path_details = [serialize_path(graph, path) for path in baseline_paths[:8]]
    serialized_plans = []
    for idx, plan in enumerate(best_plans, start=1):
        selected_actions = [serialize_action(action_index[action_id]) for action_id in plan.selected_actions if action_id in action_index]
        serialized_plans.append(
            {
                "title": _plan_title(idx, plan.reduced_paths, plan.coverage_ratio),
                "coverage_ratio": plan.coverage_ratio,
                "reduced_paths": plan.reduced_paths,
                "remaining_paths": plan.remaining_paths,
                "cost": plan.cost,
                "operational_impact": plan.operational_impact,
                "selected_actions": selected_actions,
                "reasoning": _plan_reasoning(plan, selected_actions, environment.budget_limit),
            }
        )

    summary = {
        "environment": environment.name,
        "platform": environment.platform,
        "manifests_path": environment.manifests_path,
        "workloads": len(cluster_model.workloads),
        "service_accounts": len(cluster_model.service_accounts),
        "secrets": len(cluster_model.secrets),
        "permissions": sum(1 for _, attrs in graph.nodes(data=True) if attrs.get("kind") == "permission"),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "baseline_paths": len(baseline_paths),
        "sample_paths": path_summary(baseline_paths[:5]),
        "path_details": serialized_path_details,
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
    }
    summary["executive_summary"] = build_executive_summary(
        environment_name=environment.name,
        crown_jewels=summary["crown_jewels"],
        baseline_paths=summary["baseline_paths"],
        path_cards=serialized_path_details,
        remediation_plans=serialized_plans,
        actions_count=summary["candidate_actions"],
        workloads=summary["workloads"],
        service_accounts=summary["service_accounts"],
    )

    run = models.AnalysisRun(
        environment_id=environment.id,
        status="completed",
        baseline_paths=len(baseline_paths),
        summary_json=json.dumps(summary),
    )
    db.add(run)
    db.flush()

    for idx, plan in enumerate(serialized_plans, start=1):
        record = models.RemediationPlan(
            analysis_run_id=run.id,
            title=plan["title"],
            coverage_ratio=plan["coverage_ratio"],
            reduced_paths=plan["reduced_paths"],
            remaining_paths=plan["remaining_paths"],
            cost=plan["cost"],
            operational_impact=plan["operational_impact"],
            selected_actions_json=json.dumps(plan["selected_actions"]),
            reasoning=plan["reasoning"],
        )
        db.add(record)

    db.commit()
    db.refresh(run)
    return run


def analysis_run_to_dict(run: models.AnalysisRun) -> dict:
    plans = sorted(
        run.remediation_plans,
        key=lambda plan: (plan.remaining_paths, plan.cost, plan.operational_impact, -plan.coverage_ratio, plan.id or 0),
    )
    return {
        "id": run.id,
        "environment_id": run.environment_id,
        "status": run.status,
        "baseline_paths": run.baseline_paths,
        "summary": json.loads(run.summary_json or "{}"),
        "remediation_plans": [
            {
                "id": plan.id,
                "title": plan.title,
                "coverage_ratio": plan.coverage_ratio,
                "reduced_paths": plan.reduced_paths,
                "remaining_paths": plan.remaining_paths,
                "cost": plan.cost,
                "operational_impact": plan.operational_impact,
                "selected_actions": json.loads(plan.selected_actions_json or "[]"),
                "reasoning": plan.reasoning,
            }
            for plan in plans
        ],
        "created_at": run.created_at,
    }


def build_dashboard(db: Session, tenant_id: int) -> dict:
    tenant = db.get(models.Tenant, tenant_id)
    if not tenant:
        raise LookupError("Tenant not found")

    workspaces = db.query(models.Workspace).filter(models.Workspace.tenant_id == tenant_id).all()
    workspace_ids = [w.id for w in workspaces]
    environments = db.query(models.Environment).filter(models.Environment.workspace_id.in_(workspace_ids)).all() if workspace_ids else []
    environment_ids = [env.id for env in environments]
    runs = (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.environment_id.in_(environment_ids))
        .order_by(models.AnalysisRun.created_at.desc())
        .all()
        if environment_ids
        else []
    )
    latest_summary = json.loads(runs[0].summary_json) if runs else {}
    latest_runs = [analysis_run_to_dict(run) for run in runs[:5]]
    return {
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "workspaces": len(workspaces),
        "environments": len(environments),
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
    }
