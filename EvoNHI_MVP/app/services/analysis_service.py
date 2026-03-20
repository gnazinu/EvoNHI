from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.domain.analysis_models import CrownJewelSpec, ScenarioConfig
from app.engine.graph_builder import build_attack_graph
from app.engine.manifest_loader import load_cluster_model
from app.engine.optimizer import optimize_actions
from app.engine.path_analysis import find_attack_paths, path_summary
from app.engine.remediation import propose_remediation_actions


def run_analysis(db: Session, environment_id: int, max_paths: int) -> models.AnalysisRun:
    environment = db.get(models.Environment, environment_id)
    if not environment:
        raise ValueError("Environment not found")

    manifest_path = Path(environment.manifests_path)
    if not manifest_path.exists():
        raise ValueError(f"Manifest path does not exist: {manifest_path}")

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

    summary = {
        "environment": environment.name,
        "workloads": len(cluster_model.workloads),
        "service_accounts": len(cluster_model.service_accounts),
        "secrets": len(cluster_model.secrets),
        "permissions": sum(1 for _, attrs in graph.nodes(data=True) if attrs.get("kind") == "permission"),
        "baseline_paths": len(baseline_paths),
        "sample_paths": path_summary(baseline_paths[:5]),
        "candidate_actions": len(actions),
        "crown_jewels": [f"{j.kind}:{j.namespace}:{j.name}" for j in jewels],
    }

    run = models.AnalysisRun(
        environment_id=environment.id,
        status="completed",
        baseline_paths=len(baseline_paths),
        summary_json=json.dumps(summary),
    )
    db.add(run)
    db.flush()

    for idx, plan in enumerate(best_plans, start=1):
        reasoning = (
            f"Plan {idx} reduces {plan.reduced_paths} paths while keeping cost {plan.cost} "
            f"and operational impact {plan.operational_impact} under the environment budget."
        )
        record = models.RemediationPlan(
            analysis_run_id=run.id,
            title=f"Top remediation plan #{idx}",
            coverage_ratio=plan.coverage_ratio,
            reduced_paths=plan.reduced_paths,
            remaining_paths=plan.remaining_paths,
            cost=plan.cost,
            operational_impact=plan.operational_impact,
            selected_actions_json=json.dumps(plan.selected_actions),
            reasoning=reasoning,
        )
        db.add(record)

    db.commit()
    db.refresh(run)
    return run


def analysis_run_to_dict(run: models.AnalysisRun) -> dict:
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
            for plan in run.remediation_plans
        ],
        "created_at": run.created_at,
    }


def build_dashboard(db: Session, tenant_id: int) -> dict:
    workspaces = db.query(models.Workspace).filter(models.Workspace.tenant_id == tenant_id).all()
    workspace_ids = [w.id for w in workspaces]
    environments = db.query(models.Environment).filter(models.Environment.workspace_id.in_(workspace_ids)).all() if workspace_ids else []
    environment_ids = [env.id for env in environments]
    runs = db.query(models.AnalysisRun).filter(models.AnalysisRun.environment_id.in_(environment_ids)).order_by(models.AnalysisRun.created_at.desc()).all() if environment_ids else []
    latest_summary = json.loads(runs[0].summary_json) if runs else {}
    return {
        "tenant_id": tenant_id,
        "workspaces": len(workspaces),
        "environments": len(environments),
        "analysis_runs": len(runs),
        "latest_risk_summary": latest_summary,
    }
