from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app import models


def record_audit_event(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    tenant_id: int | None = None,
    user_id: int | None = None,
    actor_type: str = "user",
    status: str = "success",
    request_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> models.AuditEvent:
    event = models.AuditEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        request_id=request_id,
        ip_address=ip_address,
        details_json=json.dumps(details or {}),
    )
    db.add(event)
    db.flush()
    return event
