# EvoNHI Enterprise Control Plane

EvoNHI is a multi-tenant SaaS for reducing Kubernetes non-human identity attack paths with stronger isolation, async analysis execution and runtime-aware telemetry.

The project is now oriented around three enterprise realities:

- customer data must be isolated per tenant
- heavy graph and optimization work must run outside the web request path
- operational impact must be informed by runtime telemetry, not only static YAML

## What changed in this enterprise refactor

The platform now includes:

- PostgreSQL-first configuration with SQLite fallback only for local/test use
- user accounts, memberships and bearer tokens instead of a single global API key
- tenant-scoped access control across environments, runs, plans and connectors
- DB-backed queued analysis runs with a dedicated worker entrypoint at `app/worker.py`
- versioned environment snapshots for each analysis run
- connector tokens and telemetry ingestion endpoints
- audit events for auth, onboarding, snapshots, runs and remediation updates
- tenant settings and quotas for environments, connectors and daily analysis runs
- remediation workflow fields like status, owner, approvals and ticket URL
- request metrics and request IDs for basic platform observability
- updated dashboards and API contracts around the new architecture

## Core architecture

### Control plane

FastAPI handles:

- authentication
- tenant and workspace management
- environment onboarding
- connector provisioning
- queued analysis orchestration
- remediation workflow
- executive and technical dashboards

### Compute plane

Heavy analysis no longer needs to live in the HTTP path.

- API requests enqueue analysis runs
- a worker process claims queued runs and executes graph building plus optimization
- each run references a versioned environment snapshot and optional telemetry snapshot

Run the worker with:

```bash
python -m app.worker
```

For local development only, you can also set:

```bash
export EVONHI_RUN_EMBEDDED_WORKER=true
```

### Runtime telemetry plane

Instead of relying only on static manifests, EvoNHI can ingest runtime context through tenant-scoped connectors.

Supported in this codebase:

- connector provisioning with one-time token return
- telemetry snapshot ingestion
- runtime-aware operational-impact modifiers during remediation planning

The ingestion model is push-based right now:

- cluster-side connector or agent sends telemetry to `POST /api/v1/connector-ingest/telemetry`

## Data model highlights

The platform now tracks:

- tenants
- users
- memberships
- access tokens
- workspaces
- environments
- crown jewels
- cluster connectors
- telemetry snapshots
- environment snapshots
- analysis runs
- remediation plans
- audit events

## Security posture improvements

- no more single global `EVONHI_API_KEY`
- per-user bearer tokens with expiration and revocation fields
- per-connector tokens for ingestion
- access checks enforced by tenant membership and role
- audit events for critical actions
- tenant quotas and feature flags

Current tenant roles:

- `viewer`
- `analyst`
- `editor`
- `admin`
- `owner`

## Analysis model

The engine still focuses on:

- public workload entry points
- service account token inheritance
- RBAC secret reads
- mounted secret exposure
- workload mutation pivots

What improved:

- each analysis run is reproducible from a stored snapshot
- operational impact can now be adjusted with runtime telemetry confidence
- results are queued and can be processed by dedicated workers

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

### 3. Configure PostgreSQL

```bash
export EVONHI_DATABASE_URL="postgresql+psycopg://evonhi:evonhi@localhost:5432/evonhi"
```

In local tests and fallback development, the app can still drop to SQLite if the PostgreSQL driver is unavailable and `EVONHI_ENV` is not `production`.

### 4. Seed demo data

```bash
python scripts/seed_demo.py
```

That script bootstraps:

- a tenant
- an owner user
- a workspace
- an environment
- a crown jewel
- a telemetry snapshot
- a processed analysis run

### 5. Run the API and worker

```bash
uvicorn app.main:app --reload
python -m app.worker
```

### 6. Authenticate

Use the seeded credentials:

- email: `owner@acme.test`
- password: `super-secure-pass`

Login:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"owner@acme.test","password":"super-secure-pass"}'
```

Then use:

- `Authorization: Bearer <token>`
- or `?access_token=<token>` for HTML dashboards

## Important API endpoints

### Auth

- `POST /api/v1/auth/bootstrap`
- `POST /api/v1/auth/login`
- `GET /api/v1/me`

### Tenant and onboarding

- `GET /api/v1/tenants`
- `POST /api/v1/tenants`
- `PATCH /api/v1/tenants/{tenant_id}/settings`
- `GET /api/v1/tenants/{tenant_id}/workspaces`
- `POST /api/v1/tenants/{tenant_id}/workspaces`
- `GET /api/v1/workspaces/{workspace_id}/environments`
- `POST /api/v1/workspaces/{workspace_id}/environments`
- `POST /api/v1/environments/{environment_id}/crown-jewels`

### Connectors and telemetry

- `GET /api/v1/environments/{environment_id}/connectors`
- `POST /api/v1/environments/{environment_id}/connectors`
- `GET /api/v1/environments/{environment_id}/telemetry-snapshots`
- `POST /api/v1/environments/{environment_id}/telemetry-snapshots`
- `POST /api/v1/connector-ingest/telemetry`

### Analysis

- `GET /api/v1/environments/{environment_id}/analysis-runs`
- `POST /api/v1/environments/{environment_id}/analysis-runs`
- `POST /api/v1/environments/{environment_id}/analysis-runs/execute-inline`
- `POST /api/v1/analysis-runs/{run_id}/execute-now`
- `GET /api/v1/analysis-runs/{run_id}`
- `GET /api/v1/analysis-runs/{run_id}/executive-summary`

### Workflow and operations

- `GET /api/v1/analysis-runs/{run_id}/remediation-plans`
- `PATCH /api/v1/remediation-plans/{plan_id}`
- `GET /api/v1/tenants/{tenant_id}/audit-events`
- `GET /api/v1/tenants/{tenant_id}/dashboard`
- `GET /api/v1/platform/metrics`

## Dashboard experience

HTML views remain available for non-coders:

- `/` control center
- `/dashboard/runs/{run_id}` executive run dashboard

Open them with:

```text
http://127.0.0.1:8000/?access_token=<token>
http://127.0.0.1:8000/dashboard/runs/1?access_token=<token>
```

## Current limitations

This refactor makes the SaaS much more realistic, but a few enterprise-grade items are still future work:

- full Alembic migrations
- SSO/SAML/OIDC identity federation
- distributed queue backend
- pull-based cloud connectors for EKS/GKE/AKS
- Prometheus/OpenTelemetry ingestion out of the box
- compliance packages such as SOC 2 automation

## Bottom line

EvoNHI is no longer shaped like a script that happens to have an API.

It is now shaped like a real control plane:

- identity-aware
- tenant-aware
- queue-aware
- telemetry-aware
- workflow-aware
