from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TenantCreate(BaseModel):
    name: str
    slug: str
    plan_tier: str = "starter"


class WorkspaceCreate(BaseModel):
    name: str
    description: str | None = None


class EnvironmentCreate(BaseModel):
    name: str
    platform: str = "kubernetes"
    manifests_path: str
    entry_workloads: list[str] = Field(default_factory=list)
    budget_limit: int = 10
    notes: str | None = None


class CrownJewelCreate(BaseModel):
    kind: str
    name: str
    namespace: str = "default"
    criticality: int = 10
    rationale: str = "High-value target"


class AnalysisRunCreate(BaseModel):
    max_paths: int = 50


class TenantRead(BaseModel):
    id: int
    name: str
    slug: str
    plan_tier: str
    created_at: datetime

    class Config:
        from_attributes = True


class WorkspaceRead(BaseModel):
    id: int
    tenant_id: int
    name: str
    description: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class EnvironmentRead(BaseModel):
    id: int
    workspace_id: int
    name: str
    platform: str
    manifests_path: str
    budget_limit: int
    notes: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class CrownJewelRead(BaseModel):
    id: int
    environment_id: int
    kind: str
    name: str
    namespace: str
    criticality: int
    rationale: str
    created_at: datetime

    class Config:
        from_attributes = True


class RemediationPlanRead(BaseModel):
    id: int
    title: str
    coverage_ratio: float
    reduced_paths: int
    remaining_paths: int
    cost: int
    operational_impact: int
    selected_actions: list[str]
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
    workspaces: int
    environments: int
    analysis_runs: int
    latest_risk_summary: dict[str, Any]
