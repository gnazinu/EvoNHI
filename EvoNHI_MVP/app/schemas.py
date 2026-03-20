from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import settings


def _normalize_text(value: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError("Value cannot be empty")
    return clean


def _normalize_slug(value: str) -> str:
    slug = _normalize_text(value).lower().replace(" ", "-").replace("_", "-")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    if any(char not in allowed for char in slug):
        raise ValueError("Value must contain only lowercase letters, numbers and hyphens")
    return slug


class MembershipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: int
    role: str
    status: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    is_active: bool
    is_platform_admin: bool
    created_at: datetime


class AccessTokenRead(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime | None
    user: UserRead
    memberships: list[MembershipRead]


class BootstrapRegister(BaseModel):
    email: str
    full_name: str
    password: str = Field(min_length=12)
    tenant_name: str
    tenant_slug: str

    @field_validator("full_name", "tenant_name")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _normalize_text(value)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = _normalize_text(value).lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("Email must be valid")
        return email

    @field_validator("tenant_slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        return _normalize_slug(value)


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = _normalize_text(value).lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("Email must be valid")
        return email


class TenantCreate(BaseModel):
    name: str
    slug: str
    plan_tier: str = "starter"

    @field_validator("name", "plan_tier")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _normalize_text(value)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        return _normalize_slug(value)


class TenantSettingsUpdate(BaseModel):
    max_environments: int | None = None
    max_connectors: int | None = None
    max_daily_analysis_runs: int | None = None
    retention_days: int | None = None
    enabled_features: dict[str, bool] | None = None


class WorkspaceCreate(BaseModel):
    name: str
    description: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _normalize_text(value)


class EnvironmentCreate(BaseModel):
    name: str
    platform: str = "kubernetes"
    manifests_path: str
    entry_workloads: list[str] = Field(default_factory=list)
    budget_limit: int = 10
    notes: str | None = None

    @field_validator("name", "platform", "manifests_path")
    @classmethod
    def validate_required(cls, value: str) -> str:
        return _normalize_text(value)

    @field_validator("entry_workloads")
    @classmethod
    def validate_entry_workloads(cls, value: list[str]) -> list[str]:
        seen = set()
        items = []
        for item in value:
            clean = _normalize_text(item)
            if clean not in seen:
                seen.add(clean)
                items.append(clean)
        return items

    @field_validator("budget_limit")
    @classmethod
    def validate_budget(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Budget limit must be greater than zero")
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
        return _normalize_text(value)

    @field_validator("criticality")
    @classmethod
    def validate_criticality(cls, value: int) -> int:
        if not 1 <= value <= 10:
            raise ValueError("Criticality must be between 1 and 10")
        return value


class ClusterConnectorCreate(BaseModel):
    name: str
    kind: str = "kubernetes-push-agent"
    scopes: list[str] = Field(default_factory=lambda: ["telemetry:write", "snapshot:write"])
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name", "kind")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _normalize_text(value)


class ClusterConnectorSecretRead(BaseModel):
    connector_id: int
    connector_token: str


class TelemetrySnapshotCreate(BaseModel):
    source_kind: str = "connector"
    payload: dict[str, Any]
    summary: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime | None = None


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


class RemediationPlanUpdate(BaseModel):
    status: str | None = None
    owner_user_id: int | None = None
    ticket_url: str | None = None
    notes: str | None = None


class TenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    plan_tier: str
    is_active: bool
    settings: dict[str, Any]
    feature_flags: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class WorkspaceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


class EnvironmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    workspace_id: int
    name: str
    platform: str
    manifests_path: str
    entry_workloads: list[str]
    budget_limit: int
    notes: str | None
    lifecycle_status: str
    runtime_profile: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class CrownJewelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    environment_id: int
    kind: str
    name: str
    namespace: str
    criticality: int
    rationale: str
    created_at: datetime
    updated_at: datetime


class ClusterConnectorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    environment_id: int
    name: str
    kind: str
    status: str
    read_only: bool
    scopes: list[str]
    config: dict[str, Any]
    last_seen_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class TelemetrySnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    environment_id: int
    connector_id: int | None
    source_kind: str
    summary: dict[str, Any]
    payload: dict[str, Any]
    collected_at: datetime
    created_at: datetime


class EnvironmentSnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    environment_id: int
    manifests_digest: str
    manifest_source: dict[str, Any]
    summary: dict[str, Any]
    telemetry_snapshot_id: int | None
    created_at: datetime


class RemediationActionRead(BaseModel):
    action_id: str
    title: str
    description: str
    cost: int
    impact: float
    action_type: str
    relation: str
    rationale: str
    telemetry_confidence: float | None = None


class RemediationPlanRead(BaseModel):
    id: int
    tenant_id: int
    analysis_run_id: int
    title: str
    coverage_ratio: float
    reduced_paths: int
    remaining_paths: int
    cost: int
    operational_impact: float
    selected_actions: list[RemediationActionRead]
    reasoning: str
    status: str
    owner_user_id: int | None
    approved_by_user_id: int | None
    ticket_url: str | None
    notes: str | None
    approved_at: datetime | None
    applied_at: datetime | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AnalysisRunRead(BaseModel):
    id: int
    tenant_id: int
    environment_id: int
    requested_by_user_id: int | None
    snapshot_id: int
    telemetry_snapshot_id: int | None
    status: str
    baseline_paths: int
    progress: int
    attempts: int
    max_paths_requested: int
    worker_id: str | None
    queue_name: str
    error_message: str | None
    summary: dict[str, Any]
    remediation_plans: list[RemediationPlanRead]
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int | None
    user_id: int | None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str | None
    status: str
    request_id: str | None
    ip_address: str | None
    details: dict[str, Any]
    created_at: datetime


class DashboardRead(BaseModel):
    tenant_id: int
    tenant_name: str
    workspaces: int
    environments: int
    connectors: int
    analysis_runs: int
    latest_risk_summary: dict[str, Any]
    latest_runs: list[dict[str, Any]]
    environment_overview: list[dict[str, Any]]
    telemetry_overview: list[dict[str, Any]]


class MetricsRead(BaseModel):
    requests_total: int
    analysis_runs_total: int
    analysis_failures_total: int
    recent_request_latencies_ms: list[float]
