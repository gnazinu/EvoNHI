# EvoNHI

A cybersecurity framework for Kubernetes that finds transitive attack paths through non-human identities and generates prioritized remediation plans.

## The problem

Tools like Trivy, Checkov and kube-bench evaluate permissions individually. They'll tell you "this service account has excessive privileges" — but they won't show you how those permissions chain together into exploitable paths toward your critical assets.

A `pods/create` permission looks harmless in isolation. But it lets you spawn a pod under any service account in the namespace, potentially reaching secrets it was never supposed to touch.

EvoNHI models the cluster as a directed attack graph and finds those chains automatically.

## What it does

- Builds an attack graph from service accounts, RBAC bindings, workloads and secrets
- Discovers transitive attack paths toward crown jewel assets
- Generates remediation plans prioritized by exposure reduction, implementation cost and operational impact, within a real budget constraint (NSGA-II multi-objective optimization, implemented from scratch)
- Produces human-readable attack stories and an executive HTML dashboard

## Tech stack

Python, FastAPI, SQLAlchemy, NetworkX, Pydantic v2, PyYAML, Uvicorn

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/seed_demo.py
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` to see the control center.

## Key endpoints

- `POST /api/v1/environments/{id}/analysis-runs` — trigger an analysis
- `GET /api/v1/analysis-runs/{id}` — get results
- `GET /api/v1/analysis-runs/{id}/executive-summary` — business-readable summary
- `GET /dashboard/runs/{id}` — visual dashboard

## Current scope

Models public workload entry points, service account token inheritance, RBAC secret reads, mounted secret exposure and workload mutation pivots. Basic telemetry context is available but live cluster connectors and network policy semantics are not yet implemented.
