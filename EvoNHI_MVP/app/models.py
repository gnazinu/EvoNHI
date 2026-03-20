from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.config import settings
from app.db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class JsonTextMixin:
    @staticmethod
    def _loads(value: str, fallback):
        try:
            return json.loads(value or "")
        except (TypeError, json.JSONDecodeError):
            return fallback


class Tenant(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    plan_tier: Mapped[str] = mapped_column(String(50), default="starter")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings_json: Mapped[str] = mapped_column(
        Text,
        default=lambda: json.dumps(
            {
                "max_environments": settings.default_tenant_max_environments,
                "max_connectors": settings.default_tenant_max_connectors,
                "max_daily_analysis_runs": settings.default_tenant_max_daily_runs,
                "retention_days": 90,
            }
        ),
    )
    feature_flags_json: Mapped[str] = mapped_column(
        Text,
        default=lambda: json.dumps(
            {
                "executive_dashboard": True,
                "connectors": True,
                "audit_trail": True,
                "remediation_workflow": True,
            }
        ),
    )

    memberships: Mapped[list[Membership]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    workspaces: Mapped[list[Workspace]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    environments: Mapped[list[Environment]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    connectors: Mapped[list[ClusterConnector]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    telemetry_snapshots: Mapped[list[TelemetrySnapshot]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    environment_snapshots: Mapped[list[EnvironmentSnapshot]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    remediation_plans: Mapped[list[RemediationPlan]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="tenant", cascade="all, delete-orphan")

    @property
    def settings(self) -> dict:
        return self._loads(self.settings_json, {})

    @property
    def feature_flags(self) -> dict:
        return self._loads(self.feature_flags_json, {})


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")
    tokens: Mapped[list[AccessToken]] = relationship(back_populates="user", cascade="all, delete-orphan")
    requested_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="requested_by")
    owned_plans: Mapped[list[RemediationPlan]] = relationship(
        back_populates="owner_user",
        foreign_keys="RemediationPlan.owner_user_id",
    )
    approved_plans: Mapped[list[RemediationPlan]] = relationship(
        back_populates="approved_by_user",
        foreign_keys="RemediationPlan.approved_by_user_id",
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="user")


class Membership(Base, TimestampMixin):
    __tablename__ = "memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(50), default="member")
    status: Mapped[str] = mapped_column(String(40), default="active")

    user: Mapped[User] = relationship(back_populates="memberships")
    tenant: Mapped[Tenant] = relationship(back_populates="memberships")


class AccessToken(Base, TimestampMixin):
    __tablename__ = "access_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(120), default="interactive-session")
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    scopes_json: Mapped[str] = mapped_column(Text, default='["tenant:read","tenant:write","analysis:run"]')
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="tokens")

    @property
    def scopes(self) -> list[str]:
        return JsonTextMixin._loads(self.scopes_json, [])


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="workspaces")
    environments: Mapped[list[Environment]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class Environment(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    platform: Mapped[str] = mapped_column(String(80), default="kubernetes")
    manifests_path: Mapped[str] = mapped_column(String(300), nullable=False)
    entry_workloads_json: Mapped[str] = mapped_column(Text, default="[]")
    budget_limit: Mapped[int] = mapped_column(Integer, default=10)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    lifecycle_status: Mapped[str] = mapped_column(String(40), default="active")
    runtime_profile_json: Mapped[str] = mapped_column(
        Text,
        default=lambda: json.dumps(
            {
                "ingestion_mode": "manifest_bundle",
                "last_runtime_sync": None,
                "last_snapshot_id": None,
                "last_telemetry_snapshot_id": None,
            }
        ),
    )

    tenant: Mapped[Tenant] = relationship(back_populates="environments")
    workspace: Mapped[Workspace] = relationship(back_populates="environments")
    crown_jewels: Mapped[list[CrownJewel]] = relationship(back_populates="environment", cascade="all, delete-orphan")
    connectors: Mapped[list[ClusterConnector]] = relationship(back_populates="environment", cascade="all, delete-orphan")
    telemetry_snapshots: Mapped[list[TelemetrySnapshot]] = relationship(back_populates="environment", cascade="all, delete-orphan")
    environment_snapshots: Mapped[list[EnvironmentSnapshot]] = relationship(back_populates="environment", cascade="all, delete-orphan")
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="environment", cascade="all, delete-orphan")

    @property
    def entry_workloads(self) -> list[str]:
        return self._loads(self.entry_workloads_json, [])

    @property
    def runtime_profile(self) -> dict:
        return self._loads(self.runtime_profile_json, {})


class CrownJewel(Base, TimestampMixin):
    __tablename__ = "crown_jewels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    namespace: Mapped[str] = mapped_column(String(120), default="default")
    criticality: Mapped[int] = mapped_column(Integer, default=10)
    rationale: Mapped[str] = mapped_column(Text, default="High-value target")

    environment: Mapped[Environment] = relationship(back_populates="crown_jewels")


class ClusterConnector(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "cluster_connectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(80), default="kubernetes-push-agent")
    status: Mapped[str] = mapped_column(String(40), default="provisioning")
    read_only: Mapped[bool] = mapped_column(Boolean, default=True)
    scopes_json: Mapped[str] = mapped_column(Text, default='["telemetry:write","snapshot:write"]')
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="connectors")
    environment: Mapped[Environment] = relationship(back_populates="connectors")
    telemetry_snapshots: Mapped[list[TelemetrySnapshot]] = relationship(back_populates="connector")

    @property
    def scopes(self) -> list[str]:
        return self._loads(self.scopes_json, [])

    @property
    def config(self) -> dict:
        return self._loads(self.config_json, {})


class TelemetrySnapshot(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "telemetry_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    connector_id: Mapped[int | None] = mapped_column(ForeignKey("cluster_connectors.id"), nullable=True, index=True)
    source_kind: Mapped[str] = mapped_column(String(80), default="connector")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    tenant: Mapped[Tenant] = relationship(back_populates="telemetry_snapshots")
    environment: Mapped[Environment] = relationship(back_populates="telemetry_snapshots")
    connector: Mapped[ClusterConnector | None] = relationship(back_populates="telemetry_snapshots")
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="telemetry_snapshot")
    environment_snapshots: Mapped[list[EnvironmentSnapshot]] = relationship(back_populates="telemetry_snapshot")

    @property
    def payload(self) -> dict:
        return self._loads(self.payload_json, {})

    @property
    def summary(self) -> dict:
        return self._loads(self.summary_json, {})


class EnvironmentSnapshot(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "environment_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    manifests_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    manifest_bundle_json: Mapped[str] = mapped_column(Text, default="[]")
    manifest_source_json: Mapped[str] = mapped_column(Text, default="{}")
    telemetry_snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("telemetry_snapshots.id"), nullable=True, index=True)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")

    tenant: Mapped[Tenant] = relationship(back_populates="environment_snapshots")
    environment: Mapped[Environment] = relationship(back_populates="environment_snapshots")
    telemetry_snapshot: Mapped[TelemetrySnapshot | None] = relationship(back_populates="environment_snapshots")
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="snapshot")

    @property
    def manifest_bundle(self) -> list[dict]:
        return self._loads(self.manifest_bundle_json, [])

    @property
    def manifest_source(self) -> dict:
        return self._loads(self.manifest_source_json, {})

    @property
    def summary(self) -> dict:
        return self._loads(self.summary_json, {})


class AnalysisRun(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    requested_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("environment_snapshots.id"), nullable=False, index=True)
    telemetry_snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("telemetry_snapshots.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default="queued", index=True)
    baseline_paths: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_paths_requested: Mapped[int] = mapped_column(Integer, default=50)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    worker_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    queue_name: Mapped[str] = mapped_column(String(50), default="analysis")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="analysis_runs")
    environment: Mapped[Environment] = relationship(back_populates="analysis_runs")
    requested_by: Mapped[User | None] = relationship(back_populates="requested_runs")
    snapshot: Mapped[EnvironmentSnapshot] = relationship(back_populates="analysis_runs")
    telemetry_snapshot: Mapped[TelemetrySnapshot | None] = relationship(back_populates="analysis_runs")
    remediation_plans: Mapped[list[RemediationPlan]] = relationship(back_populates="analysis_run", cascade="all, delete-orphan")

    @property
    def summary(self) -> dict:
        return self._loads(self.summary_json, {})


class RemediationPlan(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    coverage_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    reduced_paths: Mapped[int] = mapped_column(Integer, default=0)
    remaining_paths: Mapped[int] = mapped_column(Integer, default=0)
    cost: Mapped[int] = mapped_column(Integer, default=0)
    operational_impact: Mapped[float] = mapped_column(Float, default=0.0)
    selected_actions_json: Mapped[str] = mapped_column(Text, default="[]")
    reasoning: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(40), default="proposed")
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    approved_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    ticket_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="remediation_plans")
    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="remediation_plans")
    owner_user: Mapped[User | None] = relationship(
        back_populates="owned_plans",
        foreign_keys=[owner_user_id],
    )
    approved_by_user: Mapped[User | None] = relationship(
        back_populates="approved_plans",
        foreign_keys=[approved_by_user_id],
    )

    @property
    def selected_actions(self) -> list[dict]:
        return self._loads(self.selected_actions_json, [])


class AuditEvent(Base, TimestampMixin, JsonTextMixin):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    actor_type: Mapped[str] = mapped_column(String(40), default="user")
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="success")
    request_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(120), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")

    tenant: Mapped[Tenant | None] = relationship(back_populates="audit_events")
    user: Mapped[User | None] = relationship(back_populates="audit_events")

    @property
    def details(self) -> dict:
        return self._loads(self.details_json, {})
