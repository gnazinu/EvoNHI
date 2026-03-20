# EvoNHI

**GitHub repo description:**
SaaS platform for reducing non-human identity attack paths in Kubernetes through budget-aware, production-safe remediation planning.

---

# EvoNHI

EvoNHI is a SaaS-first cybersecurity platform focused on **non-human identities** in cloud-native environments, especially Kubernetes.

Its goal is simple:

**help teams decide which security changes should be made first to reduce real attack paths to critical assets, without overspending and without breaking production.**

---

## Why EvoNHI exists

Modern systems depend on many automatic identities and credentials:

- service accounts
- tokens
- secrets
- RBAC permissions
- workload-to-workload trust
- automated pipelines and background jobs

These pieces often create hidden paths that an attacker can use to move through the environment and reach important assets.

Most tools can show exposure or misconfigurations.
Few tools answer the harder question:

**What should we change first to reduce the most risk with the least operational damage?**

That is the problem EvoNHI is built to solve.

---

## What EvoNHI does

EvoNHI analyzes a Kubernetes-like environment, builds an attack graph around non-human identities, and generates **prioritized remediation plans**.

In simple terms, it does five things:

1. reads the environment structure
2. identifies attack paths to crown jewels
3. proposes possible security changes
4. compares different defensive plans
5. recommends the best options under cost and operational constraints

Instead of just saying **"there is a risk here"**, EvoNHI tries to answer:

- what change should happen first
- what change reduces the most risk
- what fits the available budget
- what is less likely to break production

---

## Core idea

EvoNHI is **not** just another scanner.
It is a **defense optimization system**.

The core thesis is:

> Security for non-human identities should not stop at detection. It should help teams choose the best remediation strategy under real-world constraints.

That means the platform is designed around:

- **real attack paths**, not isolated findings
- **critical assets**, not generic risk scores
- **remediation planning**, not only visibility
- **budget-aware decisions**, not idealized security
- **production-safe changes**, not blind hardening

---

## Who this is for

EvoNHI is useful for teams that operate Kubernetes or cloud-native systems and need better security decisions around machine identities.

Examples:

- platform security teams
- DevSecOps teams
- cloud security engineers
- infrastructure teams
- SaaS companies with multiple workloads and service accounts
- organizations that want clearer remediation priorities

---

## Product direction

This repository represents a **SaaS-first MVP**.

The long-term product direction is a multi-tenant platform where customers can:

- onboard environments
- define crown jewels
- run repeatable analyses
- compare analysis history
- review remediation plans
- justify security work with clearer evidence and trade-offs

The current MVP already follows that product shape.

---

## Current MVP scope

### Included

- SaaS-style data model
- tenants, workspaces, and environments
- crown jewel registration
- manifest-based environment onboarding
- attack graph construction
- attack path analysis
- remediation option generation
- multi-objective optimization
- persistent analysis runs and remediation plans
- REST API with FastAPI

### Not included yet

- real cluster connectors
- live telemetry
- runtime detection
- authentication and user roles
- billing
- notifications
- background workers
- web frontend
- audit trail

---

## How the MVP works

### 1. Environment intake
The system receives Kubernetes manifests and reads objects such as:

- namespaces
- service accounts
- roles and role bindings
- secrets
- workloads
- network policies

### 2. Graph modeling
It converts the environment into a graph that represents:

- identities
- permissions
- credentials
- trust relationships
- possible movement paths

### 3. Crown jewel targeting
The customer defines which assets matter most.
These are the crown jewels the system tries to protect first.

### 4. Attack path discovery
The engine finds paths that could let an attacker move from exposed or weak points toward those crown jewels.

### 5. Remediation generation
The system creates candidate defensive actions, such as:

- removing unnecessary permissions
- restricting service accounts
- protecting or isolating secrets
- reducing access to sensitive resources
- limiting exposure paths

### 6. Optimization
Instead of choosing changes one by one, EvoNHI compares many possible remediation plans and tries to optimize for:

- lower attack-path exposure
- lower cost
- lower operational impact
- better defensive coverage

---

## Why this approach matters

Security teams usually face three real constraints:

- they cannot fix everything at once
- they cannot break production
- they need to justify priorities

EvoNHI is designed around those constraints from the start.

That is why the platform is centered on **decision quality**, not just detection volume.

---

## High-level architecture

The MVP uses a layered architecture.

### API layer
FastAPI exposes product endpoints for tenants, workspaces, environments, crown jewels, and analysis runs.

### Application layer
Service modules handle onboarding, analysis orchestration, and persistence of results.

### Analysis engine
The engine loads manifests, builds the graph, identifies attack paths, generates remediation options, and runs optimization.

### Persistence layer
SQLite stores product entities and analysis output in a SaaS-like structure.

---

## Tech stack

- **Python** — core application and analysis engine
- **FastAPI** — API layer
- **SQLAlchemy** — persistence model
- **SQLite** — default database for the MVP
- **NetworkX** — graph modeling and path analysis
- **pymoo** — multi-objective evolutionary optimization
- **Pydantic** — request and response schemas
- **Uvicorn** — local API server

---

## Repository structure

```text
app/
  api/          # API routes
  services/     # product orchestration
  engine/       # graph, path, remediation, optimization logic
  domain/       # analysis models
  models.py     # SaaS database entities
  schemas.py    # API schemas
  main.py       # FastAPI entrypoint

data/demo/
  manifests/    # reproducible demo scenario

docs/
  ARCHITECTURE.md
  WHY_SAAS.md
  PROJECT_SOUL.md

tests/
  test_engine.py
```

---

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

### 3. Run the API

```bash
uvicorn app.main:app --reload
```

### 4. Open the docs

Visit:

```text
http://127.0.0.1:8000/docs
```

---

## Suggested demo flow

1. create a tenant
2. create a workspace
3. register an environment
4. add crown jewels
5. trigger an analysis run
6. inspect the remediation plans

---

## Example product promise

EvoNHI does not try to be a full SOC or a general-purpose scanner.

Its value is more specific:

**turn non-human identity exposure into clear, prioritized, and production-aware remediation decisions.**

---

## Long-term roadmap

### Near term

- improve remediation catalog
- expand graph semantics
- strengthen scoring for operational impact
- add better demo scenarios
- add asynchronous analysis jobs

### Mid term

- PostgreSQL support
- authentication and RBAC
- cluster connectors instead of local manifests
- policy export and policy-as-code integrations
- better visualization of attack paths and plans

### Later

- multi-cloud support
- runtime signals
- continuous drift analysis
- team workflows and approvals
- reporting for customers and leadership

---

## Philosophy

EvoNHI is built around a simple idea:

**less noise, better decisions.**

The goal is not to produce more alerts.
The goal is to help teams reduce the most dangerous attack paths in the smartest possible way.

---

## Status

This repository is currently an **MVP / research-to-product foundation**.
It is meant to validate the product direction, the analysis logic, and the optimization model before moving toward a more complete SaaS platform.

-*gnazinu*
