from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from app import models
from app.api.routes import router
from app.config import settings
from app.db import get_db, init_db
from app.security import require_api_key
from app.services.analysis_service import analysis_run_to_dict
from app.services.reporting import build_dashboard_payload
from app.ui.dashboard import render_analysis_dashboard, render_home_page

init_db()

app = FastAPI(
    title="EvoNHI SaaS MVP",
    version="0.1.0",
    description="Production-minded MVP for non-human identity attack path reduction.",
)


@app.get("/health")
def healthcheck():
    return {"status": "ok", "service": "evonhi-saas"}


@app.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    _api_key: str | None = Depends(require_api_key),
    db=Depends(get_db),
):
    runs = db.query(models.AnalysisRun).order_by(models.AnalysisRun.created_at.desc()).limit(8).all()
    cards = [build_dashboard_payload(analysis_run_to_dict(run)) for run in runs]
    api_key = request.query_params.get("api_key")
    link_suffix = f"?api_key={api_key}" if api_key else ""
    return HTMLResponse(render_home_page(cards, auth_enabled=settings.auth_enabled, link_suffix=link_suffix))


@app.get("/dashboard/runs/{run_id}", response_class=HTMLResponse)
def analysis_dashboard(
    run_id: int,
    _api_key: str | None = Depends(require_api_key),
    db=Depends(get_db),
):
    run = db.get(models.AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    payload = build_dashboard_payload(analysis_run_to_dict(run))
    return HTMLResponse(render_analysis_dashboard(payload))


app.include_router(router)
