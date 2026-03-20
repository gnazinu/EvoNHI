# EvoNHI SaaS MVP Architecture

## Product shape
This MVP is built as a **control plane**. The analysis engine exists behind a SaaS model, not as a standalone script.

## Core layers

### 1. API layer
FastAPI exposes tenant, workspace, environment and analysis endpoints.

### 2. Application layer
Services orchestrate:
- customer onboarding
- environment registration
- crown jewel setup
- analysis execution
- remediation plan persistence

### 3. Domain engine
The engine handles:
- manifest loading
- attack graph creation
- path discovery
- remediation generation
- multi-objective optimization

### 4. Persistence layer
SQLite stores product entities:
- tenants
- workspaces
- environments
- crown jewels
- analysis runs
- remediation plans

## Why this architecture fits a SaaS
Because the real product is not just the algorithm. The product is the ability to:
- onboard multiple customers
- keep customer environments isolated
- rerun analyses over time
- compare runs
- persist remediation plans as reusable outputs
- evolve toward auth, billing and background jobs later

## Future-ready extension points
- swap SQLite for PostgreSQL
- swap sync analysis for Celery/RQ workers
- replace local manifest paths with cluster connectors
- add auth and tenant RBAC
- add billing, notifications and audit logging
