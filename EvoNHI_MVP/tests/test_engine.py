from app.domain.analysis_models import CrownJewelSpec, ScenarioConfig
from app.engine.graph_builder import build_attack_graph
from app.engine.manifest_loader import load_cluster_model
from app.engine.optimizer import optimize_actions
from app.engine.path_analysis import find_attack_paths
from app.engine.remediation import propose_remediation_actions


def test_demo_environment_generates_paths_and_plans():
    model = load_cluster_model("data/demo/manifests")
    scenario = ScenarioConfig(
        crown_jewels=[CrownJewelSpec(kind="Secret", name="payments-db-secret", namespace="payments")],
        entry_workloads=["public-gateway"],
        max_paths=50,
    )
    graph = build_attack_graph(model, scenario)
    paths = find_attack_paths(graph, max_paths=50)
    actions = propose_remediation_actions(graph)
    plans = optimize_actions(graph, actions, max_paths=50, budget=8)
    assert len(paths) >= 1
    assert len(actions) >= 1
    assert len(plans) >= 1
