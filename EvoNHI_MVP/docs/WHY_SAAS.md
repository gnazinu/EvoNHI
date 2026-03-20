# Why EvoNHI should be SaaS-first

A research prototype usually proves one technical point. A SaaS proves that the technical point can become an operational product.

EvoNHI should be SaaS-first because the value is recurring:
- environments change
- permissions drift
- workloads change
- secrets rotate
- attack paths reappear
- customers need repeated analyses, not one report

## Product promise
EvoNHI does not just surface exposure. It helps customers decide the **best next defensive actions** under cost and operational constraints.

## Product objects that matter
- Tenant: the customer account
- Workspace: the customer team or business unit
- Environment: the cluster or deployment target
- Crown jewel: what must be protected first
- Analysis run: a dated risk snapshot
- Remediation plan: the actionable product output

## Why the MVP is still credible
Even with local manifests and synchronous jobs, the shape is already the shape of a real platform:
- multi-tenant data
- persistent runs
- stored plans
- product API
- reproducible analysis engine
