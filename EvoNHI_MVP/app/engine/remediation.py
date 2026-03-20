from __future__ import annotations

import networkx as nx

from app.domain.analysis_models import RemediationAction


def _workload_runtime_modifier(telemetry_context: dict, namespace: str, name: str) -> tuple[float, float]:
    workload = telemetry_context.get("workloads", {}).get((namespace, name), {})
    if not workload:
        return 0.0, telemetry_context.get("confidence", 0.0)
    criticality = str(workload.get("criticality", "medium")).lower()
    traffic = float(workload.get("traffic_rps", 0) or 0)
    replicas = int(workload.get("replicas", 1) or 1)
    modifier = 0.0
    if criticality == "critical":
        modifier += 3.0
    elif criticality == "high":
        modifier += 2.0
    if traffic >= 100:
        modifier += 2.0
    elif traffic >= 20:
        modifier += 1.0
    if replicas <= 1:
        modifier += 1.0
    return modifier, telemetry_context.get("confidence", 0.0)


def _permission_runtime_modifier(telemetry_context: dict, namespace: str, service_account: str, resource: str, verb: str) -> tuple[float, float]:
    permission = telemetry_context.get("permissions", {}).get((namespace, service_account, resource, verb), {})
    if not permission:
        return 0.0, telemetry_context.get("confidence", 0.0)
    recent_requests = float(permission.get("recent_requests", 0) or 0)
    modifier = 0.0
    if recent_requests >= 100:
        modifier += 3.0
    elif recent_requests >= 20:
        modifier += 2.0
    elif recent_requests > 0:
        modifier += 1.0
    return modifier, telemetry_context.get("confidence", 0.0)


def _secret_runtime_modifier(telemetry_context: dict, namespace: str, name: str) -> tuple[float, float]:
    secret = telemetry_context.get("secrets", {}).get((namespace, name), {})
    if not secret:
        return 0.0, telemetry_context.get("confidence", 0.0)
    mounted_by = secret.get("mounted_by", []) or []
    modifier = 2.0 if mounted_by else 0.0
    return modifier, telemetry_context.get("confidence", 0.0)


def propose_remediation_actions(graph: nx.DiGraph, telemetry_context: dict | None = None) -> list[RemediationAction]:
    telemetry_context = telemetry_context or {"confidence": 0.0}
    actions: dict[str, RemediationAction] = {}

    for left, right, attrs in graph.edges(data=True):
        relation = attrs.get("relation")
        left_attrs = graph.nodes[left]
        right_attrs = graph.nodes[right]

        if relation == "granted_permission" and right_attrs.get("kind") == "permission":
            resource = right_attrs.get("resource", "*")
            verb = right_attrs.get("verb", "*")
            binding_name = right_attrs.get("binding_name", "binding")
            action_id = f"remove-permission::{right}"
            base_cost = 2 if verb in {"get", "list", "watch"} else 4
            base_impact = 2.0 if resource in {"secrets", "configmaps"} else 4.0
            modifier, confidence = _permission_runtime_modifier(
                telemetry_context,
                right_attrs.get("subject_namespace", right_attrs.get("namespace", "default")),
                left_attrs.get("name", ""),
                resource,
                verb,
            )
            actions.setdefault(
                action_id,
                RemediationAction(
                    action_id=action_id,
                    title=f"Remove {verb} on {resource} from {left_attrs['name']}",
                    description=f"Break the attack chain by removing permission {verb} on {resource} granted by {binding_name}.",
                    cost=base_cost,
                    impact=base_impact + modifier,
                    action_type="node_removal",
                    relation=relation,
                    target_nodes=[right],
                    rationale="Removing this permission cuts a concrete privilege edge that appears in reachable attack paths.",
                    telemetry_confidence=confidence,
                ),
            )

        if relation == "mounted_secret" and right_attrs.get("kind") == "secret":
            action_id = f"unmount-secret::{left}::{right}"
            modifier, confidence = _workload_runtime_modifier(
                telemetry_context,
                left_attrs.get("namespace", "default"),
                left_attrs.get("name", ""),
            )
            secret_modifier, _ = _secret_runtime_modifier(
                telemetry_context,
                right_attrs.get("namespace", "default"),
                right_attrs.get("name", ""),
            )
            actions.setdefault(
                action_id,
                RemediationAction(
                    action_id=action_id,
                    title=f"Remove mounted secret {right_attrs['name']} from {left_attrs['name']}",
                    description=f"Break the direct secret exposure from workload {left_attrs['name']}.",
                    cost=3,
                    impact=4.0 + modifier + secret_modifier,
                    action_type="edge_removal",
                    relation=relation,
                    target_edges=[(left, right)],
                    rationale="Mounted secrets create a direct exposure path after workload compromise.",
                    telemetry_confidence=confidence,
                ),
            )

        if relation == "uses_token" and left_attrs.get("kind") == "workload" and left_attrs.get("public"):
            action_id = f"disable-token::{left}"
            modifier, confidence = _workload_runtime_modifier(
                telemetry_context,
                left_attrs.get("namespace", "default"),
                left_attrs.get("name", ""),
            )
            actions.setdefault(
                action_id,
                RemediationAction(
                    action_id=action_id,
                    title=f"Disable automounted token for public workload {left_attrs['name']}",
                    description=(
                        f"Reduce blast radius by preventing public workload {left_attrs['name']} "
                        f"from automatically inheriting service account {right_attrs['name']}."
                    ),
                    cost=2,
                    impact=3.0 + modifier,
                    action_type="edge_removal",
                    relation=relation,
                    target_edges=[(left, right)],
                    rationale="Public workloads should not automatically inherit credentials unless strictly required.",
                    telemetry_confidence=confidence,
                ),
            )

    return list(actions.values())


def apply_actions(graph: nx.DiGraph, actions: list[RemediationAction], selected_action_ids: list[str]) -> nx.DiGraph:
    clone = graph.copy()
    action_index = {action.action_id: action for action in actions}
    for action_id in selected_action_ids:
        action = action_index.get(action_id)
        if not action:
            continue
        for node in action.target_nodes:
            if clone.has_node(node):
                clone.remove_node(node)
        for left, right in action.target_edges:
            if clone.has_edge(left, right):
                clone.remove_edge(left, right)
    return clone
