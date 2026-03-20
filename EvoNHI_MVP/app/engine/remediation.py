from __future__ import annotations

import networkx as nx

from app.domain.analysis_models import RemediationAction


def propose_remediation_actions(graph: nx.DiGraph) -> list[RemediationAction]:
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
            base_impact = 2 if resource in {"secrets", "configmaps"} else 4
            actions.setdefault(
                action_id,
                RemediationAction(
                    action_id=action_id,
                    title=f"Remove {verb} on {resource} from {left_attrs['name']}",
                    description=f"Break the attack chain by removing permission {verb} on {resource} granted by {binding_name}.",
                    cost=base_cost,
                    impact=base_impact,
                    action_type="node_removal",
                    relation=relation,
                    target_nodes=[right],
                    rationale="Removing this permission cuts a concrete privilege edge that appears in reachable attack paths.",
                ),
            )

        if relation == "mounted_secret" and right_attrs.get("kind") == "secret":
            action_id = f"unmount-secret::{left}::{right}"
            actions.setdefault(
                action_id,
                RemediationAction(
                    action_id=action_id,
                    title=f"Remove mounted secret {right_attrs['name']} from {left_attrs['name']}",
                    description=f"Break the direct secret exposure from workload {left_attrs['name']}.",
                    cost=3,
                    impact=4,
                    action_type="edge_removal",
                    relation=relation,
                    target_edges=[(left, right)],
                    rationale="Mounted secrets create a direct exposure path after workload compromise.",
                ),
            )

        if relation == "uses_token" and left_attrs.get("kind") == "workload" and left_attrs.get("public"):
            action_id = f"disable-token::{left}"
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
                    impact=3,
                    action_type="edge_removal",
                    relation=relation,
                    target_edges=[(left, right)],
                    rationale="Public workloads should not automatically inherit credentials unless strictly required.",
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
