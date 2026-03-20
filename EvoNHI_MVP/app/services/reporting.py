from __future__ import annotations

from typing import Any

import networkx as nx

from app.domain.analysis_models import AttackPath, RemediationAction
from app.engine.path_analysis import explain_path


def _risk_level(baseline_paths: int) -> str:
    if baseline_paths == 0:
        return "contained"
    if baseline_paths <= 3:
        return "guarded"
    if baseline_paths <= 8:
        return "elevated"
    if baseline_paths <= 15:
        return "high"
    return "critical"


def _risk_color(level: str) -> str:
    return {
        "contained": "#3bb273",
        "guarded": "#69b34c",
        "elevated": "#f0ad4e",
        "high": "#ef7d57",
        "critical": "#d1495b",
    }.get(level, "#ef7d57")


def _coverage_sentence(plan: dict[str, Any] | None) -> str:
    if not plan:
        return "No remediation plan is currently available."

    actions = plan.get("selected_actions", [])
    action_count = len(actions)
    return (
        f"The leading plan removes {plan.get('reduced_paths', 0)} reachable paths "
        f"with {action_count} prioritized changes, cost score {plan.get('cost', 0)} "
        f"and operational impact {plan.get('operational_impact', 0)}."
    )


def serialize_action(action: RemediationAction) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "title": action.title,
        "description": action.description,
        "cost": action.cost,
        "impact": action.impact,
        "action_type": action.action_type,
        "relation": action.relation,
        "rationale": action.rationale,
        "telemetry_confidence": action.telemetry_confidence,
    }


def serialize_path(graph: nx.DiGraph, path: AttackPath) -> dict[str, Any]:
    explained = explain_path(graph, path)
    explained["path_length"] = len(path.nodes) - 1
    explained["crown_jewel"] = graph.nodes[path.nodes[-1]].get("name", path.nodes[-1])
    return explained


def build_executive_summary(
    environment_name: str,
    crown_jewels: list[str],
    baseline_paths: int,
    path_cards: list[dict[str, Any]],
    remediation_plans: list[dict[str, Any]],
    actions_count: int,
    workloads: int,
    service_accounts: int,
) -> dict[str, Any]:
    level = _risk_level(baseline_paths)
    top_plan = remediation_plans[0] if remediation_plans else None
    top_path = path_cards[0] if path_cards else None

    top_findings = [
        {
            "title": "Reachable crown-jewel paths",
            "value": baseline_paths,
            "context": "Distinct attack chains from public entry workloads to crown jewels.",
        },
        {
            "title": "Candidate remediations",
            "value": actions_count,
            "context": "Actionable changes the optimizer can combine into safer plans.",
        },
        {
            "title": "Protected assets in scope",
            "value": len(crown_jewels),
            "context": ", ".join(crown_jewels) if crown_jewels else "No crown jewels registered yet.",
        },
    ]

    if top_path:
        top_findings.append(
            {
                "title": "Most important attack story",
                "value": top_path["headline"],
                "context": top_path["steps"][0]["why"] if top_path.get("steps") else "A public workload has a concrete route to a protected asset.",
            }
        )

    return {
        "headline": f"Environment {environment_name} is currently {level}.",
        "risk_level": level,
        "risk_color": _risk_color(level),
        "non_technical_summary": (
            f"We analyzed {workloads} workloads and {service_accounts} service accounts. "
            f"We found {baseline_paths} reachable paths to high-value assets and generated "
            f"{actions_count} remediation candidates."
        ),
        "why_it_matters": (
            "Every reachable path is a sequence an attacker could follow after compromising "
            "an exposed workload. The fewer of these paths remain, the less room an attacker has to escalate."
        ),
        "top_findings": top_findings,
        "recommended_plan_summary": _coverage_sentence(top_plan),
        "recommended_plan_title": top_plan.get("title") if top_plan else "No plan available",
        "business_impact": (
            "This dashboard is designed for decision-makers: it shows whether the team should "
            "invest in immediate hardening, and which changes buy the most reduction for the least disruption."
        ),
        "confidence_statement": (
            "The current engine models public workload exposure, service-account token usage, "
            "RBAC secret access, mounted secrets and workload-mutation pivots."
        ),
    }


def build_dashboard_payload(run_payload: dict[str, Any]) -> dict[str, Any]:
    summary = run_payload.get("summary", {})
    remediation_plans = run_payload.get("remediation_plans", [])
    executive = summary.get("executive_summary", {})

    return {
        "run": run_payload,
        "summary": summary,
        "plans": remediation_plans,
        "executive": executive,
        "risk_level": executive.get("risk_level", "elevated"),
        "risk_color": executive.get("risk_color", "#ef7d57"),
        "path_cards": summary.get("path_details", []),
        "crown_jewels": summary.get("crown_jewels", []),
        "top_plan": remediation_plans[0] if remediation_plans else None,
    }
