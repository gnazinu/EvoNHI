from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    plan_tier: Mapped[str] = mapped_column(String(50), default="starter")

    workspaces: Mapped[list[Workspace]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="workspaces")
    environments: Mapped[list[Environment]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class Environment(Base, TimestampMixin):
    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    platform: Mapped[str] = mapped_column(String(80), default="kubernetes")
    manifests_path: Mapped[str] = mapped_column(String(300), nullable=False)
    entry_workloads_json: Mapped[str] = mapped_column(Text, default="[]")
    budget_limit: Mapped[int] = mapped_column(Integer, default=10)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    workspace: Mapped[Workspace] = relationship(back_populates="environments")
    crown_jewels: Mapped[list[CrownJewel]] = relationship(back_populates="environment", cascade="all, delete-orphan")
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="environment", cascade="all, delete-orphan")


class CrownJewel(Base, TimestampMixin):
    __tablename__ = "crown_jewels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    namespace: Mapped[str] = mapped_column(String(120), default="default")
    criticality: Mapped[int] = mapped_column(Integer, default=10)
    rationale: Mapped[str] = mapped_column(Text, default="High-value target")

    environment: Mapped[Environment] = relationship(back_populates="crown_jewels")


class AnalysisRun(Base, TimestampMixin):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="completed")
    baseline_paths: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")

    environment: Mapped[Environment] = relationship(back_populates="analysis_runs")
    remediation_plans: Mapped[list[RemediationPlan]] = relationship(back_populates="analysis_run", cascade="all, delete-orphan")


class RemediationPlan(Base, TimestampMixin):
    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    coverage_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    reduced_paths: Mapped[int] = mapped_column(Integer, default=0)
    remaining_paths: Mapped[int] = mapped_column(Integer, default=0)
    cost: Mapped[int] = mapped_column(Integer, default=0)
    operational_impact: Mapped[int] = mapped_column(Integer, default=0)
    selected_actions_json: Mapped[str] = mapped_column(Text, default="[]")
    reasoning: Mapped[str] = mapped_column(Text, default="")

    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="remediation_plans")
