from __future__ import annotations

import time

from app.config import settings
from app.db import init_db, session_scope
from app.services.analysis_service import claim_next_analysis_run, process_analysis_run


def run_worker_loop() -> None:
    init_db()
    while True:
        with session_scope() as db:
            run = claim_next_analysis_run(db, worker_id=settings.analysis_worker_id)
            if run is None:
                pass
            else:
                process_analysis_run(db, run.id, worker_id=settings.analysis_worker_id)
        time.sleep(settings.analysis_job_poll_seconds)


if __name__ == "__main__":
    run_worker_loop()
