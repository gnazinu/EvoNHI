from __future__ import annotations

from typing import Iterable

import networkx as nx

from app.domain.analysis_models import AttackPath


def entry_nodes(graph: nx.DiGraph) -> list[str]:
    return [node for node, attrs in graph.nodes(data=True) if attrs.get("kind") == "workload" and attrs.get("public")]


def crown_jewel_nodes(graph: nx.DiGraph) -> list[str]:
    return [node for node, attrs in graph.nodes(data=True) if attrs.get("crown_jewel")]


def find_attack_paths(graph: nx.DiGraph, max_paths: int = 50) -> list[AttackPath]:
    paths: list[AttackPath] = []
    count = 0
    for source in entry_nodes(graph):
        for target in crown_jewel_nodes(graph):
            for simple_path in nx.all_simple_paths(graph, source=source, target=target, cutoff=8):
                score = max(1.0, len(simple_path))
                paths.append(AttackPath(nodes=simple_path, score=score))
                count += 1
                if count >= max_paths:
                    return paths
    return paths


def path_summary(paths: Iterable[AttackPath]) -> list[str]:
    return [" -> ".join(path.nodes) for path in paths]
