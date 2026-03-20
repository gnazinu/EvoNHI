# EvoNHI

EvoNHI is a security decision platform for reducing Kubernetes non-human identity attack paths.

The project focuses on a hard practical question:

**which few changes should a team make first to reduce reachable paths to crown jewels without blowing the budget or causing reckless operational impact?**

## What the project does today

This repository now ships a more production-minded MVP with:

- tenant, workspace and environment data model
- manifest-based environment onboarding with path hardening
- attack-graph construction for service accounts, RBAC, mounted secrets and public workloads
- bounded attack-path discovery with human-readable evidence
- remediation planning with budget-aware optimization
- persistent analysis runs and remediation plans
- optional API-key protection for API and dashboards
- executive HTML dashboard for non-coders
- API endpoints for technical users and automation

## What changed in this refactor

The project was upgraded in the areas that matter most for credibility:

- the graph builder no longer mixes unrelated RBAC resources and verbs into fake paths
- permission scope now follows binding scope more closely, which is much closer to real Kubernetes behavior
- analysis results now include explainable attack stories and executive summaries
- remediation plans store rich action metadata instead of opaque IDs
- onboarding validates parents, duplicate data and manifest path boundaries
- the app can be protected with `EVONHI_API_KEY`
- a visual dashboard was added at `/dashboard/runs/{run_id}` plus a control-center home page at `/`
- tests now cover semantic correctness and report generation, not just happy-path existence

## Honest scope

The current engine is strong enough to be useful as a serious demo and internal planning tool, but it is still not pretending to solve every Kubernetes attack vector.

Modeled well right now:

- public workload entry points
- service-account token inheritance
- RBAC secret reads
- mounted secret exposure
- workload mutation pivots via RBAC

Not fully modeled yet:

- real cluster connectors
- runtime telemetry
- user auth and RBAC beyond API-key protection
- asynchronous workers
- billing, notifications and audit trails
- full network-policy semantics

## Architecture

### API layer

FastAPI exposes resource management, analysis execution and executive summary endpoints.

### Application layer

Service modules validate onboarding, orchestrate analyses and build audience-specific summaries.

### Analysis engine

The engine:

1. loads Kubernetes manifests
2. builds an attack graph with scoped permissions
3. finds bounded high-signal paths to crown jewels
4. generates remediation actions
5. optimizes plans under budget and operational impact constraints

### Presentation layer

A server-rendered HTML dashboard translates technical findings into a business-readable story.

### Persistence layer

SQLAlchemy stores tenants, workspaces, environments, crown jewels, analysis runs and remediation plans in SQLite by default.

## Tech stack

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic v2
- NetworkX
- PyYAML
- Uvicorn

## Repository structure

```text
app/
  api/          # REST endpoints
  services/     # onboarding, reporting, analysis orchestration
  engine/       # graph, path, remediation and optimization logic
  domain/       # analysis dataclasses
  ui/           # HTML dashboard rendering
  main.py       # FastAPI entrypoint

data/demo/
  manifests/    # reproducible Kubernetes-like demo bundle

tests/
  test_engine.py
  test_engine_semantics.py
  test_onboarding_analysis.py
```

## Quick start

### 1. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Optional: protect the API and dashboards

```bash
export EVONHI_API_KEY="change-me"
```

When enabled, use either the `X-API-Key` header or `?api_key=...` in dashboard URLs.

### 4. Seed demo data

```bash
python scripts/seed_demo.py
```

That script creates a demo tenant, runs an analysis and prints the dashboard URL.

### 5. Run the API

```bash
uvicorn app.main:app --reload
```

### 6. Open the product views

- Control center: `http://127.0.0.1:8000/`
- Swagger docs: `http://127.0.0.1:8000/docs`
- Dashboard example: `http://127.0.0.1:8000/dashboard/runs/1`

## Suggested demo flow

1. Create a tenant.
2. Create a workspace.
3. Register an environment with a manifest bundle under the configured manifest root.
4. Add one or more crown jewels.
5. Trigger an analysis run.
6. Review the API output or open the executive dashboard.

## Important API endpoints

- `POST /api/v1/tenants`
- `POST /api/v1/tenants/{tenant_id}/workspaces`
- `POST /api/v1/workspaces/{workspace_id}/environments`
- `POST /api/v1/environments/{environment_id}/crown-jewels`
- `POST /api/v1/environments/{environment_id}/analysis-runs`
- `GET /api/v1/analysis-runs/{run_id}`
- `GET /api/v1/analysis-runs/{run_id}/executive-summary`
- `GET /api/v1/tenants/{tenant_id}/dashboard`

## Example product promise

EvoNHI is not trying to be a generic scanner or a full SOC.

Its value proposition is narrower and stronger:

**turn non-human identity exposure into prioritized, explainable remediation decisions that both engineers and non-engineers can act on.**
