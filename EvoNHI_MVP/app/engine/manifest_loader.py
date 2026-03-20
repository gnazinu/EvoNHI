from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from app.domain.analysis_models import (
    ClusterModel,
    Metadata,
    NetworkPolicy,
    PolicyRule,
    Role,
    RoleBinding,
    Secret,
    ServiceAccount,
    SubjectRef,
    Workload,
)


def _safe_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _metadata(doc: Dict[str, Any]) -> Metadata:
    md = doc.get("metadata", {}) or {}
    return Metadata(
        name=md.get("name", "unknown"),
        namespace=md.get("namespace", "default"),
        labels=md.get("labels", {}) or {},
        annotations=md.get("annotations", {}) or {},
    )


def load_yaml_documents(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for doc in yaml.safe_load_all(handle):
            if doc:
                yield doc


def load_cluster_model(manifest_dir: str | Path) -> ClusterModel:
    manifest_dir = Path(manifest_dir)
    documents = []
    for file_path in sorted(manifest_dir.rglob("*.y*ml")):
        for doc in load_yaml_documents(file_path):
            doc = dict(doc)
            doc.setdefault("_evonhi_source", file_path.relative_to(manifest_dir).as_posix())
            documents.append(doc)
    return load_cluster_model_from_documents(documents)


def load_cluster_model_from_documents(documents: Iterable[Dict[str, Any]]) -> ClusterModel:
    model = ClusterModel()

    for doc in documents:
        kind = doc.get("kind")
        md = _metadata(doc)

        if kind == "ServiceAccount":
            model.service_accounts.append(
                ServiceAccount(
                    metadata=md,
                    automount_token=doc.get("automountServiceAccountToken"),
                )
            )
        elif kind in {"Role", "ClusterRole"}:
            rules = []
            for rule in doc.get("rules", []) or []:
                rules.append(
                    PolicyRule(
                        resources=_safe_list(rule.get("resources")),
                        verbs=_safe_list(rule.get("verbs")),
                        api_groups=_safe_list(rule.get("apiGroups")),
                        resource_names=_safe_list(rule.get("resourceNames")),
                    )
                )
            model.roles.append(
                Role(
                    metadata=md,
                    rules=rules,
                    scope="Cluster" if kind == "ClusterRole" else "Namespaced",
                )
            )
        elif kind in {"RoleBinding", "ClusterRoleBinding"}:
            subjects = []
            for subject in doc.get("subjects", []) or []:
                subjects.append(
                    SubjectRef(
                        kind=subject.get("kind", "ServiceAccount"),
                        name=subject.get("name", "unknown"),
                        namespace=subject.get("namespace", md.namespace),
                    )
                )
            role_ref = doc.get("roleRef", {}) or {}
            model.role_bindings.append(
                RoleBinding(
                    metadata=md,
                    role_ref_kind=role_ref.get("kind", "Role"),
                    role_ref_name=role_ref.get("name", "unknown"),
                    subjects=subjects,
                    scope="Cluster" if kind == "ClusterRoleBinding" else "Namespaced",
                )
            )
        elif kind == "Secret":
            model.secrets.append(Secret(metadata=md, kind=doc.get("type", "Opaque")))
        elif kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}:
            spec = doc.get("spec", {}) or {}
            template_spec = spec.get("template", {}).get("spec", {}) if kind != "Pod" else spec
            mounted_secrets = []
            for volume in template_spec.get("volumes", []) or []:
                secret_info = volume.get("secret")
                if secret_info and secret_info.get("secretName"):
                    mounted_secrets.append(secret_info["secretName"])
            for container in template_spec.get("containers", []) or []:
                for env in container.get("env", []) or []:
                    secret_ref = (((env.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name"))
                    if secret_ref:
                        mounted_secrets.append(secret_ref)
            public = md.annotations.get("evonhi.io/public", "false").lower() == "true"
            model.workloads.append(
                Workload(
                    metadata=md,
                    workload_kind=kind,
                    service_account_name=template_spec.get("serviceAccountName", "default"),
                    automount_token=template_spec.get("automountServiceAccountToken"),
                    mounted_secrets=sorted(set(mounted_secrets)),
                    public=public,
                )
            )
        elif kind == "NetworkPolicy":
            model.network_policies.append(NetworkPolicy(metadata=md))

    return model
