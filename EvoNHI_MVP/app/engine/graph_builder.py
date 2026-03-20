from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Tuple

import networkx as nx

from app.domain.analysis_models import ClusterModel, CrownJewelSpec, PolicyRule, Role, RoleBinding, ScenarioConfig

SENSITIVE_VERBS = {"get", "list", "watch", "create", "update", "patch", "delete", "*"}
WORKLOAD_CREATION_RESOURCES = {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}


def node_id(kind: str, namespace: str, name: str) -> str:
    return f"{kind.lower()}:{namespace}:{name}"


def permission_id(namespace: str, sa_name: str, binding_name: str, role_name: str, index: int, resource: str, verb: str) -> str:
    return f"permission:{namespace}:{sa_name}:{binding_name}:{role_name}:{index}:{resource}:{verb}"


def _build_role_index(model: ClusterModel) -> Dict[Tuple[str, str, str], Role]:
    index: Dict[Tuple[str, str, str], Role] = {}
    for role in model.roles:
        index[(role.scope, role.metadata.namespace, role.metadata.name)] = role
        if role.scope == "Cluster":
            index[(role.scope, "*", role.metadata.name)] = role
    return index


def _resolve_role(binding: RoleBinding, role_index: Dict[Tuple[str, str, str], Role]) -> Role | None:
    if binding.role_ref_kind == "ClusterRole":
        return role_index.get(("Cluster", "*", binding.role_ref_name))
    return role_index.get(("Namespaced", binding.metadata.namespace, binding.role_ref_name))


def _rule_targets_secret(rule: PolicyRule) -> bool:
    return any(resource in {"secrets", "*"} for resource in rule.resources) and any(verb in SENSITIVE_VERBS for verb in rule.verbs)


def _rule_targets_workload_creation(rule: PolicyRule) -> bool:
    return any(resource in WORKLOAD_CREATION_RESOURCES or resource == "*" for resource in rule.resources) and any(verb in {"create", "patch", "update", "*"} for verb in rule.verbs)


def _mark_crown_jewels(graph: nx.DiGraph, jewels: Iterable[CrownJewelSpec]) -> None:
    for jewel in jewels:
        target = node_id(jewel.kind, jewel.namespace, jewel.name)
        if graph.has_node(target):
            graph.nodes[target]["crown_jewel"] = True
            graph.nodes[target]["criticality"] = jewel.criticality
            graph.nodes[target]["rationale"] = jewel.rationale


def _attach_workload_nodes(graph: nx.DiGraph, model: ClusterModel, scenario: ScenarioConfig) -> None:
    entry_set = set(scenario.entry_workloads)
    for workload in model.workloads:
        wid = node_id("workload", workload.metadata.namespace, workload.metadata.name)
        graph.add_node(
            wid,
            kind="workload",
            name=workload.metadata.name,
            namespace=workload.metadata.namespace,
            public=workload.public or workload.metadata.name in entry_set,
            workload_kind=workload.workload_kind,
        )
        service_account_name = workload.service_account_name or "default"
        sa_id = node_id("serviceaccount", workload.metadata.namespace, service_account_name)
        graph.add_node(sa_id, kind="serviceaccount", name=service_account_name, namespace=workload.metadata.namespace)
        automount = workload.automount_token if workload.automount_token is not None else True
        if automount:
            graph.add_edge(
                wid,
                sa_id,
                relation="uses_token",
                source_object=workload.metadata.name,
                rationale="Compromised workload can use its service account token.",
            )
        for secret_name in workload.mounted_secrets:
            sid = node_id("secret", workload.metadata.namespace, secret_name)
            graph.add_node(sid, kind="secret", name=secret_name, namespace=workload.metadata.namespace)
            graph.add_edge(
                wid,
                sid,
                relation="mounted_secret",
                source_object=workload.metadata.name,
                rationale="Compromised workload can read mounted secret material.",
            )


def build_attack_graph(model: ClusterModel, scenario: ScenarioConfig) -> nx.DiGraph:
    graph = nx.DiGraph()
    role_index = _build_role_index(model)

    for secret in model.secrets:
        sid = node_id("secret", secret.metadata.namespace, secret.metadata.name)
        graph.add_node(sid, kind="secret", name=secret.metadata.name, namespace=secret.metadata.namespace, secret_type=secret.kind)

    for service_account in model.service_accounts:
        sa_id = node_id("serviceaccount", service_account.metadata.namespace, service_account.metadata.name)
        graph.add_node(sa_id, kind="serviceaccount", name=service_account.metadata.name, namespace=service_account.metadata.namespace)

    _attach_workload_nodes(graph, model, scenario)

    service_accounts_by_ns = defaultdict(list)
    for node, attrs in graph.nodes(data=True):
        if attrs.get("kind") == "serviceaccount":
            service_accounts_by_ns[attrs.get("namespace")].append(node)

    for binding in model.role_bindings:
        role = _resolve_role(binding, role_index)
        if not role:
            continue
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount":
                continue
            sa_namespace = subject.namespace or binding.metadata.namespace
            sa_id = node_id("serviceaccount", sa_namespace, subject.name)
            graph.add_node(sa_id, kind="serviceaccount", name=subject.name, namespace=sa_namespace)
            for rule_index, rule in enumerate(role.rules):
                for resource in rule.resources or ["*"]:
                    for verb in rule.verbs or ["*"]:
                        pid = permission_id(sa_namespace, subject.name, binding.metadata.name, role.metadata.name, rule_index, resource, verb)
                        graph.add_node(
                            pid,
                            kind="permission",
                            namespace=sa_namespace,
                            role_name=role.metadata.name,
                            binding_name=binding.metadata.name,
                            resource=resource,
                            verb=verb,
                            scope=role.scope,
                            binding_scope=binding.scope,
                        )
                        graph.add_edge(
                            sa_id,
                            pid,
                            relation="granted_permission",
                            source_object=binding.metadata.name,
                            rationale=f"Role binding {binding.metadata.name} grants {verb} on {resource}.",
                        )

                        if _rule_targets_secret(rule):
                            target_secrets = [
                                node
                                for node, attrs in graph.nodes(data=True)
                                if attrs.get("kind") == "secret" and (attrs.get("namespace") == sa_namespace or role.scope == "Cluster")
                            ]
                            for secret_id in target_secrets:
                                graph.add_edge(
                                    pid,
                                    secret_id,
                                    relation="read_secret",
                                    source_object=role.metadata.name,
                                    rationale="Permission can expose secret material.",
                                )

                        if _rule_targets_workload_creation(rule):
                            pivot_targets = service_accounts_by_ns.get(sa_namespace, [])
                            for target_sa in pivot_targets:
                                if target_sa == sa_id:
                                    continue
                                graph.add_edge(
                                    pid,
                                    target_sa,
                                    relation="spawn_workload_as",
                                    source_object=role.metadata.name,
                                    rationale="Workload creation may allow pivot into another service account in the same namespace.",
                                )

    _mark_crown_jewels(graph, scenario.crown_jewels)
    return graph
