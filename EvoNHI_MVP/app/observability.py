from __future__ import annotations

import logging
from collections import deque
from typing import Any

from app.config import settings

logger = logging.getLogger("evonhi")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

_recent_latencies_ms: deque[float] = deque(maxlen=settings.metrics_history_size)
_requests_total = 0
_analysis_runs_total = 0
_analysis_failures_total = 0


def metrics_snapshot() -> dict[str, Any]:
    return {
        "requests_total": _requests_total,
        "analysis_runs_total": _analysis_runs_total,
        "analysis_failures_total": _analysis_failures_total,
        "recent_request_latencies_ms": list(_recent_latencies_ms),
    }


def record_analysis_run(success: bool) -> None:
    global _analysis_runs_total, _analysis_failures_total
    _analysis_runs_total += 1
    if not success:
        _analysis_failures_total += 1


def record_request(latency_ms: float) -> None:
    global _requests_total
    _requests_total += 1
    _recent_latencies_ms.append(latency_ms)
