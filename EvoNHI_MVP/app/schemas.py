from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import settings


def _normalize_name(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Value cannot be empty")
    return normalized


class TenantCreate(BaseModel):
    name: str
    slug: str
    plan_tier: str = "starter"

    @field_validator("name", "plan_tier")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        return _normalize_name(value)

    @field_validator("slug")
    @classmethod
    def normalize_slug(cls, value: str) -> str:
        slug = _normalize_name(value).lower().replace(" ", "-").replace("_", "-")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        if not slug or any(char not in allowed for char in slug):
            raise ValueError("Slug must contain only lowercase letters, numbers and hyphens")
        return slug


class WorkspaceCreate(BaseModel):
    name: str
    description: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _normalize_name(value)


class EnvironmentCreate(BaseModel):
    name: str
    platform: str = "kubernetes"
    manifests_path: str
    entry_workloads: list[str] = Field(default_factory=list)
    budget_limit: int = 10
    notes: str | None = None

    @field_validator("name", "platform", "manifests_path")
    @classmethod
    def validate_required_strings(cls, value: str) -> str:
        return _normalize_name(value)

    @field_validator("entry_workloads")
    @classmethod
    def normalize_entry_workloads(cls, value: list[str]) -> list[str]:
        normalized = []
        seen = set()
        for item in value:
            clean = _normalize_name(item)
            if clean not in seen:
                normalized.append(clean)
                seen.add(clean)
        return normalized

    @field_validator("budget_limit")
    @classmethod
    def validate_budget(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Budget limit must be greater than zero")
        if value > 100:
            raise ValueError("Budget limit must stay within a practical planning range (<= 100)")
        return value


class CrownJewelCreate(BaseModel):
    kind: str
    name: str
    namespace: str = "default"
    criticality: int = 10
    rationale: str = "High-value target"

    @field_validator("kind", "name", "namespace", "rationale")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _normalize_name(value)

    @field_validator("kind")
    @classmethod
    def normalize_kind(cls, value: str) -> str:
        return value[:1].upper() + value[1:]

    @field_validator("criticality")
    @classmethod
    def validate_criticality(cls, value: int) -> int:
        if not 1 <= value <= 10:
            raise ValueError("Criticality must be between 1 and 10")
        return value


class AnalysisRunCreate(BaseModel):
    max_paths: int = 50

    @field_validator("max_paths")
    @classmethod
    def validate_max_paths(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_paths must be greater than zero")
        if value > settings.max_paths_limit:
            raise ValueError(f"max_paths cannot exceed {settings.max_paths_limit}")
        return value


class TenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    plan_tier: str
    created_at: datetime


class WorkspaceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    name: str
    description: str | None
    created_at: datetime


class EnvironmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    workspace_id: int
    name: str
    platform: str
    manifests_path: str
    entry_workloads: list[str] = Field(default_factory=list)
    budget_limit: int
    notes: str | None
    created_at: datetime


class CrownJewelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    environment_id: int
    kind: str
    name: str
    namespace: str
    criticality: int
    rationale: str
    created_at: datetime


class RemediationActionRead(BaseModel):
    action_id: str
    title: str
    description: str
    cost: int
    impact: int
    action_type: str
    relation: str
    rationale: str


class RemediationPlanRead(BaseModel):
    id: int
    title: str
    coverage_ratio: float
    reduced_paths: int
    remaining_paths: int
    cost: int
    operational_impact: int
    selected_actions: list[RemediationActionRead]
    reasoning: str


class AnalysisRunRead(BaseModel):
    id: int
    environment_id: int
    status: str
    baseline_paths: int
    summary: dict[str, Any]
    remediation_plans: list[RemediationPlanRead]
    created_at: datetime


class DashboardRead(BaseModel):
    tenant_id: int
    tenant_name: str
    workspaces: int
    environments: int
    analysis_runs: int
    latest_risk_summary: dict[str, Any]
    latest_runs: list[dict[str, Any]]
    environment_overview: list[dict[str, Any]]
