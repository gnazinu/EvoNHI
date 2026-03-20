from app.domain.analysis_models import CrownJewelSpec, ScenarioConfig
from app.engine.graph_builder import build_attack_graph
from app.engine.manifest_loader import load_cluster_model
from app.engine.optimizer import optimize_actions
from app.engine.path_analysis import find_attack_paths
from app.engine.remediation import propose_remediation_actions


def _demo_graph():
    model = load_cluster_model("data/demo/manifests")
    scenario = ScenarioConfig(
        crown_jewels=[CrownJewelSpec(kind="Secret", name="payments-db-secret", namespace="payments")],
        entry_workloads=["public-gateway"],
        max_paths=50,
    )
    graph = build_attack_graph(model, scenario)
    return graph


def test_demo_paths_only_use_secret_permissions():
    graph = _demo_graph()
    paths = find_attack_paths(graph, max_paths=20)

    assert len(paths) == 2
    for path in paths:
        for node in path.nodes:
            attrs = graph.nodes[node]
            if attrs.get("kind") == "permission":
                assert attrs["resource"] == "secrets"
                assert attrs["verb"] in {"get", "list"}


def test_disable_token_is_top_quick_win_for_demo():
    graph = _demo_graph()
    actions = propose_remediation_actions(graph)
    plans = optimize_actions(graph, actions, max_paths=20, budget=8)

    assert plans[0].remaining_paths == 0
    assert "disable-token::workload:edge:public-gateway" in plans[0].selected_actions
